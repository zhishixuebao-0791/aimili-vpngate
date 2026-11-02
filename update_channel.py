"""Keep installations on their original channel, including legacy ml handoffs."""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess

CHANNELS = {'stable': ('stable', '稳定版'), 'release': ('main', '发行版')}
TAG = re.compile(r'v(\d{1,3})\.(\d+)\.(\d+)')


def manifest_tag(manifest, channel):
    if channel not in CHANNELS or not isinstance(manifest, dict) or manifest.get('schema') != 1:
        raise ValueError('更新渠道清单无效，停止更新')
    entry = manifest.get(channel)
    if not isinstance(entry, dict) or entry.get('branch') != CHANNELS[channel][0] or not TAG.fullmatch(str(entry.get('tag', ''))):
        raise ValueError('找不到本渠道有效版本，停止更新')
    return entry['tag']


def source_identity(source):
    constants = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
    version = constants.get('APP_VERSION')
    if not isinstance(version, str) or not TAG.fullmatch('v' + version):
        raise ValueError('旧版本没有可识别的版本号，请先明确安装渠道')
    channel = constants.get('APP_CHANNEL')
    if channel is None:
        # Released legacy versions explicitly labelled the stable version constant.
        matched = re.search(r'(?m)^# ([^\n]*发行版本号[^\n]*)\nAPP_VERSION\s*=', source)
        if not matched:
            raise ValueError('旧版本渠道不明确，停止更新')
        channel = 'stable' if '稳定版' in matched[1] else 'release'
    if channel not in CHANNELS:
        raise ValueError('安装渠道不受支持，停止更新')
    return {'channel': channel, 'version': version}


class Updater:
    def __init__(self, repo):
        self.repo = Path(repo).resolve()
        self.marker = self.repo / 'vpngate_data/update_channel.json'

    def git(self, *args, required=True):
        result = subprocess.run(['git', '-C', str(self.repo), *args], capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=60)
        if required and result.returncode:
            raise RuntimeError('Git渠道检查失败，停止更新: ' + args[0])
        return result.stdout.strip() if result.returncode == 0 else ''

    def identity_at(self, ref):
        return source_identity(self.git('show', ref + ':vpngate_manager.py'))

    def legacy_previous(self):
        subject = self.git('reflog', '-1', '--format=%gs', required=False)
        previous = self.git('rev-parse', '--verify', 'ORIG_HEAD', required=False)
        reflog_previous = self.git('rev-parse', '--verify', 'HEAD@{1}', required=False)
        if subject.startswith('reset: moving to ') and previous and previous == reflog_previous:
            return previous
        if not subject and previous and previous != self.git('rev-parse', 'HEAD'):
            # reset also writes ORIG_HEAD when reflogs are disabled or expired.
            return previous
        return ''

    def identity(self, legacy_local=False, fresh=False, requested_channel=None):
        if fresh:
            channel = requested_channel or 'stable'
            if channel not in CHANNELS:
                raise ValueError('首次安装渠道只能为stable或release')
            return {'channel': channel, 'version': None}
        if self.marker.exists():
            value = json.loads(self.marker.read_text(encoding='utf-8'))
            if not isinstance(value, dict) or value.get('schema') != 1 or value.get('channel') not in CHANNELS:
                raise ValueError('本地渠道记录无效，不回退到默认渠道')
            if not isinstance(value.get('version'), str) or not TAG.fullmatch('v' + value['version']):
                raise ValueError('本地渠道版本记录无效，停止更新')
            return {'channel': value['channel'], 'version': value.get('version')}
        if legacy_local:
            previous = self.legacy_previous()
            if previous:
                return self.identity_at(previous)
        source = (self.repo / 'vpngate_manager.py').read_text(encoding='utf-8')
        if legacy_local and re.search(r'(?m)^APP_CHANNEL\s*=', source):
            raise ValueError('缺少更新前渠道记录，不能把刚拉取的main视为原渠道')
        return source_identity(source)

    def fetch(self):
        # No --force on tags: an altered published tag is a fetch failure, not an update target.
        self.git('fetch', '--tags', 'origin',
                 'refs/heads/main:refs/remotes/origin/main',
                 'refs/heads/stable:refs/remotes/origin/stable')

    def target(self, identity, requested_ref=None):
        channel = identity['channel']
        manifest = json.loads(self.git('show', 'refs/remotes/origin/main:release_channels.json'))
        tag = requested_ref or manifest_tag(manifest, channel)
        if not TAG.fullmatch(tag):
            raise ValueError('部署目标必须为明确的版本标签')
        commit = self.git('rev-parse', '--verify', 'refs/tags/' + tag + '^{commit}')
        target_identity = self.identity_at(commit)
        if target_identity['channel'] != channel:
            raise ValueError('拒绝跨渠道更新: ' + channel + ' -> ' + target_identity['channel'])
        branch = CHANNELS[channel][0]
        check = subprocess.run(['git', '-C', str(self.repo), 'merge-base', '--is-ancestor', commit,
                                'refs/remotes/origin/' + branch], capture_output=True, timeout=20)
        if check.returncode:
            raise ValueError('目标不属于本渠道发布分支，停止更新')
        if not requested_ref and identity.get('version'):
            current = tuple(int(p) for p in identity['version'].split('.'))
            candidate = tuple(int(p) for p in target_identity['version'].split('.'))
            if candidate < current:
                raise ValueError('远端本渠道版本较旧，拒绝自动降级')
        # Old targets without this helper cannot preserve the channel on their next update.
        if not self.git('ls-tree', '--name-only', commit, 'update_channel.py'):
            raise ValueError('目标缺少渠道保护，请使用带渠道保护的新版本')
        return {'tag': tag, 'commit': commit, **target_identity}

    def save(self, value):
        self.marker.parent.mkdir(parents=True, exist_ok=True)
        value = {'schema': 1, **value}
        temporary = self.marker.with_name(self.marker.name + '.' + str(os.getpid()) + '.tmp')
        try:
            with temporary.open('w', encoding='utf-8') as stream:
                os.chmod(temporary, 0o600)
                json.dump(value, stream, ensure_ascii=False, indent=2)
            os.replace(temporary, self.marker)
        finally:
            temporary.unlink(missing_ok=True)

    def checkout(self, target):
        # Persist the channel before reset so the target installer cannot reinterpret it.
        previous = self.marker.read_bytes() if self.marker.exists() else None
        self.save(target)
        try:
            self.git('reset', '--hard', target['commit'])
        except BaseException:
            if previous is None:
                self.marker.unlink(missing_ok=True)
            else:
                self.marker.write_bytes(previous)
            raise

    def prepare_install(self, fresh=False, legacy_local=False, requested_channel=None, requested_ref=None):
        previous = self.legacy_previous() if legacy_local and not self.marker.exists() else ''
        try:
            if (self.repo / '.local_dev').exists():
                raise ValueError('本地开发模式已暂停自动部署，保留现有源码')
            if fresh and requested_ref and not requested_channel:
                requested_channel = self.identity_at('refs/tags/' + requested_ref)['channel']
            identity = self.identity(legacy_local=legacy_local, fresh=fresh, requested_channel=requested_channel)
            if requested_channel and requested_channel != identity['channel']:
                raise ValueError('现有安装已锁定渠道，拒绝跨渠道重装')
            target = self.target(identity, requested_ref=requested_ref)
            changed = self.git('rev-parse', 'HEAD') != target['commit']
            if changed:
                self.checkout(target)
            else:
                self.save(target)
            print('安装渠道：' + CHANNELS[target['channel']][1] + '，版本：' + target['tag'])
            return changed
        except BaseException:
            # An old ml may already have reset stable code to main. Restore its original
            # commit on any handoff failure rather than leaving a crossed installation.
            if previous:
                self.git('reset', '--hard', previous)
            raise

    def update(self, confirm=input):
        if (self.repo / '.local_dev').exists():
            raise ValueError('本地开发模式已暂停自动更新，保留现有源码')
        identity = self.identity()
        self.fetch()
        target = self.target(identity)
        label = CHANNELS[identity['channel']][1]
        if self.git('rev-parse', 'HEAD') == target['commit']:
            self.save(target)
            print('当前已是最新' + label + ' ' + target['tag'])
            return False
        print('当前渠道：' + label + '，更新目标：' + target['tag'])
        if confirm('是否确认更新本渠道版本并重启服务？(Y/n): ').strip().lower() not in ('', 'y', 'yes'):
            print('已取消更新。')
            return False
        self.checkout(target)
        return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare'])
    parser.add_argument('--repo', required=True)
    parser.add_argument('--fresh', action='store_true')
    parser.add_argument('--legacy-local', action='store_true')
    args = parser.parse_args()
    try:
        changed = Updater(args.repo).prepare_install(fresh=args.fresh, legacy_local=args.legacy_local,
            requested_channel=os.environ.get('AIMILI_CHANNEL') or None,
            requested_ref=os.environ.get('AIMILI_DEPLOY_REF') or None)
        return 10 if changed else 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('渠道检查失败，安装/更新已停止：' + str(error), file=__import__('sys').stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
