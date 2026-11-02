#!/usr/bin/env python3
"""Install bounded conntrack tuning, with owned rules and a persistent rollback."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

SERVICE = 'aimili-notrack-lo'
SCRIPT = '/opt/aimilivpn/conntrack_tuning.py'
MARKER = 'aimili-conntrack'
RUNTIME = {
    'max': '/proc/sys/net/netfilter/nf_conntrack_max',
    'timeout': '/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established',
    'buckets': '/sys/module/nf_conntrack/parameters/hashsize',
}


class Tuning:
    def __init__(self, root=Path('/'), runner=subprocess.run, which=shutil.which):
        self.root = Path(root)
        self.runner, self.which = runner, which
        self.store = self.path('/var/lib/aimilivpn-network')
        self.state_path = self.store / 'state.json'
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        if self.state and self.state.get('version') != 1:
            raise ValueError('网络调优状态版本不支持，保留现有配置')

    def path(self, name):
        return self.root / name.lstrip('/')

    def command(self, args):
        try:
            return self.runner(args, capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return subprocess.CompletedProcess(args, 1, '', '')

    def save(self):
        self.store.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store.chmod(0o700)
        self.atomic(self.state_path, json.dumps(self.state, indent=2).encode(), 0o600)

    @staticmethod
    def atomic(path, value, mode):
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + '.aimili-' + str(os.getpid()))
        try:
            with open(temporary, 'wb') as stream:
                os.chmod(temporary, mode)
                stream.write(value)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def remember_write(self, name, text, mode=0o644):
        path, value = self.path(name), text.encode()
        if path.is_symlink():
            raise ValueError('拒绝覆盖符号链接: ' + name)
        files = self.state.setdefault('files', {})
        if name not in files:
            files[name] = {'original': base64.b64encode(path.read_bytes()).decode() if path.exists() else None,
                           'mode': path.stat().st_mode & 0o777 if path.exists() else mode}
        files[name]['written_hash'] = hashlib.sha256(value).hexdigest()
        self.save()  # Journal the intended replacement before changing it.
        self.atomic(path, value, mode)

    def number(self, key):
        try:
            value = int(self.path(RUNTIME[key]).read_text().strip())
            return value if value > 0 else None
        except (OSError, ValueError):
            return None

    def available(self):
        if self.number('max') is None and self.which('modprobe'):
            self.command(['modprobe', 'nf_conntrack'])
        return self.number('max') is not None and self.number('timeout') is not None

    def init_system(self):
        if self.path('/run/systemd/system').is_dir() and self.which('systemctl'):
            return 'systemd'
        if self.which('rc-service') and self.which('rc-update'):
            return 'openrc'
        return None

    def rules(self, owned=True):
        for binary in ('iptables', 'ip6tables'):
            if not self.which(binary):
                continue
            for chain, direction in (('PREROUTING', '-i'), ('OUTPUT', '-o')):
                rule = [chain, direction, 'lo']
                if owned:
                    rule += ['-m', 'comment', '--comment', MARKER]
                yield binary, rule + ['-j', 'NOTRACK']

    def rule_command(self, binary, action, rule):
        return self.command([binary, '-w', '5', '-t', 'raw', action] + rule)

    def apply(self):
        if not self.state or self.state.get('rolled_back'):
            return
        if not self.available():
            print('[网络调优] 当前内核不提供conntrack或模块不可加载，跳过运行时设置。')
            return
        for key, desired in self.state['target'].items():
            current = self.number(key)
            if current is None:
                continue
            # Never shrink an existing larger table, or lengthen a shorter timeout.
            target = min(current, desired) if key == 'timeout' else max(current, desired)
            if current == target:
                continue
            try:
                self.path(RUNTIME[key]).write_text(str(target) + '\n')
            except OSError:
                print('[网络调优] 内核参数不可写，保留现值: ' + key)
                continue
            self.state.setdefault('applied', {})[key] = target
            self.save()
        for binary, rule in self.rules():
            if self.rule_command(binary, '-C', rule).returncode == 0:
                continue
            bare = rule[:3] + rule[-2:]
            if self.rule_command(binary, '-C', bare).returncode == 0:
                continue  # Leave pre-existing unmarked rules under their original owner.
            if self.rule_command(binary, '-A', rule).returncode:
                print('[网络调优] ' + binary + ' raw/NOTRACK不可用，跳过该回环规则。')

    def stop(self):
        for binary, rule in self.rules():
            if self.rule_command(binary, '-C', rule).returncode == 0:
                if self.rule_command(binary, '-D', rule).returncode:
                    raise RuntimeError('无法移除本程序添加的NOTRACK规则')

    def install(self):
        if not self.available():
            print('[网络调优] 当前内核不提供conntrack或模块不可加载，跳过；安装继续。')
            return False
        if self.state.get('rolled_back'):
            self.state = {}
        for name, saved in self.state.get('files', {}).items():
            path = self.path(name)
            if path.is_symlink() or (path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != saved['written_hash']):
                raise RuntimeError('现有调优配置已被修改，请先核对: ' + name)
        if not self.state:
            self.state = {'version': 1, 'original_runtime': {key: self.number(key) for key in RUNTIME},
                          'init': self.init_system()}
            init = self.state['init']
            if init == 'systemd':
                self.state['previous_enabled'] = self.command(['systemctl', 'is-enabled', SERVICE]).stdout.strip() == 'enabled'
                self.state['previous_active'] = self.command(['systemctl', 'is-active', SERVICE]).returncode == 0
            elif init == 'openrc':
                shown = self.command(['rc-update', 'show', 'default']).stdout
                self.state['previous_enabled'] = any(line.split('|')[0].strip() == SERVICE for line in shown.splitlines())
                self.state['previous_active'] = self.command(['rc-service', SERVICE, 'status']).returncode == 0
        current = {key: self.number(key) for key in RUNTIME}
        self.state['target'] = {'max': max(65536, current['max']),
                                'timeout': min(7200, current['timeout']),
                                'buckets': max(16384, current['buckets'] or 0)}
        self.save()
        target = self.state['target']
        try:
            self.remember_write('/etc/sysctl.d/90-aimili-conntrack.conf',
                '# Managed by AimiliVPN; rollback: python3 ' + SCRIPT + ' rollback\n'
                + 'net.netfilter.nf_conntrack_max=' + str(target['max']) + '\n'
                + 'net.netfilter.nf_conntrack_tcp_timeout_established=' + str(target['timeout']) + '\n')
            self.remember_write('/etc/modprobe.d/aimili-conntrack.conf',
                '# Managed by AimiliVPN\noptions nf_conntrack hashsize=' + str(target['buckets']) + '\n')
            self.configure_service()
            self.apply()
        except BaseException:
            self.rollback()
            raise
        print('[网络调优] conntrack设置已应用，原配置保存在 ' + str(self.store))
        return True

    def configure_service(self):
        init = self.state['init']
        if init == 'systemd':
            self.remember_write('/etc/systemd/system/' + SERVICE + '.service',
                '[Unit]\nDescription=AimiliVPN conntrack tuning and loopback NOTRACK\n'
                'After=network-pre.target ufw.service firewalld.service\nBefore=aimilivpn.service\n'
                'Wants=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                'ExecStart=/usr/bin/python3 ' + SCRIPT + ' apply\n'
                'ExecStop=/usr/bin/python3 ' + SCRIPT + ' stop\n\n[Install]\nWantedBy=multi-user.target\n')
            for command in (['systemctl', 'daemon-reload'], ['systemctl', 'enable', SERVICE]):
                if self.command(command).returncode:
                    raise RuntimeError('无法持久化conntrack服务')
            # --no-block avoids waiting on the same installer state lock in ExecStart.
            if self.command(['systemctl', 'start', '--no-block', SERVICE]).returncode:
                raise RuntimeError('无法启动conntrack服务')
        elif init == 'openrc':
            self.remember_write('/etc/init.d/' + SERVICE,
                '#!/sbin/openrc-run\ndescription="AimiliVPN conntrack tuning and loopback NOTRACK"\n'
                'depend() {\n    after firewall iptables ip6tables\n    before aimilivpn\n}\n'
                'start() {\n    /usr/bin/python3 ' + SCRIPT + ' apply\n}\n'
                'stop() {\n    /usr/bin/python3 ' + SCRIPT + ' stop\n}\n', 0o755)
            if self.command(['rc-update', 'add', SERVICE, 'default']).returncode:
                raise RuntimeError('无法持久化OpenRC conntrack服务')
            # Runtime settings are applied below; the enabled service reapplies them at boot.
        else:
            print('[网络调优] 未检测到systemd/OpenRC，回环规则仅当前生效。')

    def rollback(self):
        if not self.state or self.state.get('rolled_back'):
            print('[网络调优] 没有需要回退的安装记录。')
            return
        init = self.state.get('init')
        if init == 'systemd':
            self.command(['systemctl', 'disable', '--now', SERVICE])
        elif init == 'openrc':
            self.command(['rc-update', 'del', SERVICE, 'default'])
            self.command(['rc-service', SERVICE, 'stop'])
        self.stop()
        for key, applied in self.state.get('applied', {}).items():
            original = self.state['original_runtime'].get(key)
            if original is not None and self.number(key) == applied:
                self.path(RUNTIME[key]).write_text(str(original) + '\n')
        for name, saved in self.state.get('files', {}).items():
            path = self.path(name)
            if path.is_symlink():
                raise RuntimeError('配置已变为符号链接，请手动核对: ' + name)
            if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != saved['written_hash']:
                original = base64.b64decode(saved['original']) if saved['original'] is not None else None
                if path.read_bytes() != original:
                    raise RuntimeError('配置在安装后已修改，请手动核对: ' + name)
                continue
            if saved['original'] is None:
                path.unlink(missing_ok=True)
            else:
                self.atomic(path, base64.b64decode(saved['original']), saved['mode'])
        if init == 'systemd':
            self.command(['systemctl', 'daemon-reload'])
            if self.state.get('previous_enabled'):
                self.command(['systemctl', 'enable', SERVICE])
            if self.state.get('previous_active'):
                self.command(['systemctl', 'start', '--no-block', SERVICE])
        elif init == 'openrc':
            if self.state.get('previous_enabled'):
                self.command(['rc-update', 'add', SERVICE, 'default'])
            if self.state.get('previous_active'):
                # Restored legacy scripts may be started after this command has released its lock.
                print('[网络调优] 已恢复原OpenRC服务；原回环规则仍保留，可执行rc-service ' + SERVICE + ' start。')
        self.state['rolled_back'] = True
        self.save()
        print('[网络调优] 已恢复安装前配置和未被另行修改的运行时参数。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'apply', 'stop', 'rollback'])
    action = parser.parse_args().action
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        parser.error('只能在Linux上以root运行')
    os.umask(0o077)
    tuning = Tuning()
    if action == 'stop':
        tuning.stop()  # ExecStop must not contend with rollback's state lock.
        return
    import fcntl
    tuning.store.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (tuning.store / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        tuning = Tuning()
        getattr(tuning, action)()


if __name__ == '__main__':
    main()
