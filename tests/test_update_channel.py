"""Exercise real Git histories, including the original shipped ml update functions."""
import ast
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / 'release_channels.json').read_text(encoding='utf-8'))
STABLE_TAG = MANIFEST['stable']['tag']
RELEASE_TAG = MANIFEST['release']['tag']
spec = importlib.util.spec_from_file_location('channel', ROOT / 'update_channel.py')
channel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(channel)


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], capture_output=True,
                            text=True, encoding='utf-8', errors='replace', check=True)
    return result.stdout.strip()


class ChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temp.name)
        assert cls.base.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
        source = cls.base / 'source'
        source.mkdir()
        git(source, 'init', '-q', '-b', 'main')
        git(source, 'config', 'user.name', 'Channel tests')
        git(source, 'config', 'user.email', 'tests@example.invalid')
        git(source, 'config', 'core.autocrlf', 'false')
        def version(value, kind, modern=False):
            comment = '# 发行版本号（稳定版）' if kind == 'stable' else '# 发行版本号。发布新版本时同步修改此处并打同名git标签'
            text = comment + '\nAPP_VERSION = "' + value + '"\n'
            if modern:
                text += 'APP_CHANNEL = "' + kind + '"\n'
                shutil.copyfile(ROOT / 'update_channel.py', source / 'update_channel.py')
                shutil.copyfile(ROOT / 'release_channels.json', source / 'release_channels.json')
            (source / 'vpngate_manager.py').write_text(text, encoding='utf-8')
            (source / 'install.sh').write_text('# fixture: no host service operations\n')
            git(source, 'add', '.')
            git(source, 'commit', '-qm', kind + ' ' + value)
            git(source, 'tag', 'v' + value)
        version('1.26.6', 'stable')
        git(source, 'branch', 'stable')
        git(source, 'switch', '-q', 'stable')
        for value in ['1.26.7', '1.26.8', '1.26.9']:
            version(value, 'stable')
        version('1.26.15', 'stable', True)
        version('1.26.17', 'stable', True)
        if STABLE_TAG != 'v1.26.15':
            version(STABLE_TAG[1:], 'stable', True)
        git(source, 'switch', '-q', 'main')
        for value in ['1.26.10', '1.26.11', '1.26.12', '1.26.13', '1.26.14']:
            version(value, 'release')
        version('1.26.16', 'release', True)
        version('1.26.18', 'release', True)
        if RELEASE_TAG != 'v1.26.16':
            version(RELEASE_TAG[1:], 'release', True)
        cls.origin = cls.base / 'origin.git'
        subprocess.run(['git', 'clone', '-q', '--bare', str(source), str(cls.origin)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        output = patch('builtins.print')
        output.start()
        self.addCleanup(output.stop)
        self.cwd = os.getcwd()
        self.addCleanup(os.chdir, self.cwd)
        self.case = tempfile.TemporaryDirectory()
        assert Path(self.case.name).resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.case.cleanup)
        self.repo = Path(self.case.name) / 'install'
        subprocess.run(['git', 'clone', '-q', str(self.origin), str(self.repo)], check=True)
        git(self.repo, 'config', 'user.name', 'Channel tests')
        git(self.repo, 'config', 'user.email', 'tests@example.invalid')
        self.updater = channel.Updater(self.repo)

    def installed(self, tag, detached=False):
        if detached:
            git(self.repo, 'checkout', '-q', '--detach', tag)
        else:
            git(self.repo, 'checkout', '-q', '-B', 'main', tag)

    def assert_target(self, kind, tag):
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), git(self.repo, 'rev-parse', tag))
        self.assertEqual(self.updater.identity()['channel'], kind)
        self.assertEqual(json.loads(self.updater.marker.read_text())['channel'], kind)

    def old_update(self, kind):
        source = (ROOT / 'tests/fixtures' / ('legacy_ml_' + kind + '.py')).read_text(encoding='utf-8')
        real_run = subprocess.run
        handoffs = []
        def command(args, **kwargs):
            if args[0] == 'bash':
                handoffs.append(self.updater.identity_at('HEAD')['channel'])
                self.updater.prepare_install(legacy_local=True)
                # Source replacement hands off to the selected installer, now protected by its marker.
                self.updater.prepare_install(legacy_local=True)
                return subprocess.CompletedProcess(args, 0)
            if args[0] == 'find':
                return subprocess.CompletedProcess(args, 0)
            return real_run(args, **kwargs)
        namespace = {'os': os, 'sys': sys, 'INSTALL_DIR': str(self.repo), 'subprocess': Mock(run=command, DEVNULL=subprocess.DEVNULL),
                     'time': Mock(), 'input': lambda _: 'y', 'print': Mock(),
                     'mark_login_refresh_required': Mock()}
        exec(compile(source, 'original-' + kind + '-ml', 'exec'), namespace)
        try:
            namespace['update_service']()
        finally:
            os.chdir(self.cwd)
        self.assertEqual(handoffs, ['release'], str(namespace['print'].call_args_list))

    def test_new_updater_keeps_old_stable_on_stable(self):
        self.installed('v1.26.8')
        self.assertTrue(self.updater.update(confirm=lambda _: 'y'))
        self.assert_target('stable', STABLE_TAG)

    def test_new_updater_keeps_old_release_on_release(self):
        self.installed('v1.26.14')
        self.assertTrue(self.updater.update(confirm=lambda _: 'y'))
        self.assert_target('release', RELEASE_TAG)

    def test_original_stable_ml_finally_installs_stable(self):
        self.installed('v1.26.9')
        self.old_update('stable')
        self.assert_target('stable', STABLE_TAG)

    def test_original_stable_ml_from_detached_tag_keeps_stable(self):
        self.installed('v1.26.8', detached=True)
        self.old_update('stable')
        self.assert_target('stable', STABLE_TAG)

    def test_original_release_ml_finally_installs_release(self):
        self.installed('v1.26.14', detached=True)
        self.old_update('release')
        self.assert_target('release', RELEASE_TAG)

    def test_all_known_old_versions_detect_their_own_channel(self):
        for version in range(6, 15):
            expected = 'stable' if version <= 9 else 'release'
            with self.subTest(version=version):
                self.assertEqual(self.updater.identity_at('v1.26.' + str(version))['channel'], expected)

    def test_marker_preserves_channel_even_after_old_ml_reset(self):
        self.installed('v1.26.15')
        self.updater.save({'channel': 'stable', 'version': '1.26.15'})
        git(self.repo, 'reset', '--hard', 'origin/main')
        self.updater.prepare_install(legacy_local=True)
        self.assert_target('stable', STABLE_TAG)

    def test_previous_modern_stable_upgrades_within_stable(self):
        self.installed('v1.26.15')
        self.updater.update(confirm=lambda _: 'y')
        self.assert_target('stable', STABLE_TAG)

    def test_previous_modern_release_upgrades_within_release(self):
        self.installed('v1.26.16')
        self.updater.update(confirm=lambda _: 'y')
        self.assert_target('release', RELEASE_TAG)

    def test_previous_stable_17_upgrades_within_stable(self):
        self.installed('v1.26.17')
        self.updater.update(confirm=lambda _: 'y')
        self.assert_target('stable', STABLE_TAG)

    def test_previous_release_18_upgrades_within_release(self):
        self.installed('v1.26.18')
        self.updater.update(confirm=lambda _: 'y')
        self.assert_target('release', RELEASE_TAG)

    def test_stable_cannot_request_release_tag(self):
        self.installed('v1.26.8')
        before = git(self.repo, 'rev-parse', 'HEAD')
        with self.assertRaisesRegex(ValueError, '跨渠道'):
            self.updater.prepare_install(requested_ref='v1.26.16')
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), before)

    def test_release_cannot_request_stable_tag(self):
        self.installed('v1.26.14')
        with self.assertRaisesRegex(ValueError, '跨渠道'):
            self.updater.prepare_install(requested_ref='v1.26.15')

    def test_channel_environment_cannot_change_existing_installation(self):
        self.installed('v1.26.8')
        with self.assertRaisesRegex(ValueError, '跨渠道'):
            self.updater.prepare_install(requested_channel='release')

    def test_fresh_install_defaults_to_stable(self):
        self.updater.prepare_install(fresh=True)
        self.assert_target('stable', STABLE_TAG)

    def test_fresh_release_install_stays_release_on_reinstall(self):
        self.updater.prepare_install(fresh=True, requested_channel='release')
        self.updater.prepare_install(legacy_local=True)
        self.assert_target('release', RELEASE_TAG)

    def test_fresh_install_can_infer_channel_from_explicit_ref(self):
        self.updater.prepare_install(fresh=True, requested_ref=RELEASE_TAG)
        self.assert_target('release', RELEASE_TAG)

    def test_missing_channel_does_not_fall_back_to_largest_tag(self):
        with self.assertRaises(ValueError):
            channel.manifest_tag({'schema': 1, 'release': {'branch': 'main', 'tag': 'v99.0.0'}}, 'stable')

    def test_highest_global_tag_is_ignored(self):
        self.installed('v1.26.8')
        git(self.repo, 'tag', 'v99.0.0', 'origin/main')
        self.assertEqual(self.updater.target(self.updater.identity())['tag'], STABLE_TAG)

    def test_unknown_legacy_channel_is_rejected(self):
        with self.assertRaises(ValueError):
            channel.source_identity('APP_VERSION = "1.0.0"\n')

    def test_corrupt_marker_is_rejected_without_changing_source(self):
        self.installed('v1.26.8')
        self.updater.marker.parent.mkdir()
        self.updater.marker.write_text('{not valid json')
        before = git(self.repo, 'rev-parse', 'HEAD')
        with self.assertRaises(ValueError):
            self.updater.update(confirm=lambda _: 'y')
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), before)

    def test_latest_version_does_not_restart_or_replace_source(self):
        self.installed(STABLE_TAG)
        self.assertFalse(self.updater.update(confirm=lambda _: self.fail('No prompt expected')))
        self.assert_target('stable', STABLE_TAG)

    def test_cancelled_update_leaves_original_source_and_channel_record(self):
        self.installed('v1.26.8')
        before = git(self.repo, 'rev-parse', 'HEAD')
        self.assertFalse(self.updater.update(confirm=lambda _: 'n'))
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), before)
        self.assertFalse(self.updater.marker.exists())

    def test_legacy_handoff_failure_restores_pre_reset_stable_code(self):
        self.installed('v1.26.8')
        original = git(self.repo, 'rev-parse', 'HEAD')
        git(self.repo, 'reset', '--hard', 'origin/main')
        with patch.object(self.updater, 'target', side_effect=ValueError('broken manifest')):
            with self.assertRaises(ValueError):
                self.updater.prepare_install(legacy_local=True)
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), original)
        self.assertFalse(self.updater.marker.exists())

    def test_legacy_reset_recovers_stable_from_orig_head_without_reflog(self):
        self.installed('v1.26.8')
        git(self.repo, 'reset', '--hard', 'origin/main')
        git(self.repo, 'reflog', 'expire', '--expire=now', '--all')
        self.updater.prepare_install(legacy_local=True)
        self.assert_target('stable', STABLE_TAG)

    def test_missing_all_legacy_history_does_not_assume_pulled_main_is_release(self):
        git(self.repo, 'reflog', 'expire', '--expire=now', '--all')
        git(self.repo, 'update-ref', '-d', 'ORIG_HEAD')
        with self.assertRaisesRegex(ValueError, '缺少更新前'):
            self.updater.prepare_install(legacy_local=True)
        self.assertFalse(self.updater.marker.exists())

    def test_development_mode_refuses_update_without_overwriting_source(self):
        self.installed('v1.26.8')
        before = git(self.repo, 'rev-parse', 'HEAD')
        (self.repo / '.local_dev').write_text('')
        with self.assertRaisesRegex(ValueError, '开发模式'):
            self.updater.update(confirm=lambda _: 'y')
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), before)

    def test_old_update_in_development_mode_restores_original_channel(self):
        self.installed('v1.26.8')
        before = git(self.repo, 'rev-parse', 'HEAD')
        (self.repo / '.local_dev').write_text('')
        git(self.repo, 'reset', '--hard', 'origin/main')
        with self.assertRaisesRegex(ValueError, '开发模式'):
            self.updater.prepare_install(legacy_local=True)
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), before)

    def shell_selector(self, local, choice=''):
        install = (ROOT / 'install.sh').read_text(encoding='utf-8')
        start = install.index('echo -e "\\n${YELLOW}[2/4]')
        end = install.index('# Persist conntrack tuning', start)
        script = Path(self.case.name) / 'source-selection.sh'
        script.write_text('set -e\n' + install[start:end], encoding='utf-8')
        env = dict(os.environ, INSTALL_DIR=str(self.repo), GITHUB_URL=str(self.origin),
                   GITHUB_USER='tests', GITHUB_REPO='tests', LOCAL_RERUN='1' if local else '0',
                   AIMILI_CHANNEL=choice, AIMILI_DEPLOY_REF='', AIMILI_SOURCE_READY='0',
                   GREEN='', YELLOW='', RED='', PLAIN='')
        result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Real installer shell handoff is tested on Linux')
    def test_real_shell_corrects_legacy_stable_reset_before_service_phase(self):
        self.installed('v1.26.8', detached=True)
        git(self.repo, 'reset', '--hard', 'origin/main')
        self.shell_selector(local=True)
        self.assert_target('stable', STABLE_TAG)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Real installer shell handoff is tested on Linux')
    def test_real_shell_reinstall_keeps_old_release_channel(self):
        self.installed('v1.26.14', detached=True)
        self.shell_selector(local=False)
        self.assert_target('release', RELEASE_TAG)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Real installer shell handoff is tested on Linux')
    def test_real_shell_fresh_install_defaults_to_stable(self):
        # Use a fresh, absent directory; the original fixture clone remains untouched.
        self.repo = Path(self.case.name) / 'fresh-install'
        self.updater = channel.Updater(self.repo)
        self.shell_selector(local=False)
        self.assert_target('stable', STABLE_TAG)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Real deployment entries are tested on Linux')
    def test_real_shell_both_documented_deployment_entries_select_their_channel(self):
        for choice, version in [('stable', STABLE_TAG), ('release', RELEASE_TAG)]:
            with self.subTest(choice=choice):
                self.repo = Path(self.case.name) / ('chosen-' + choice)
                self.updater = channel.Updater(self.repo)
                self.shell_selector(local=False, choice=choice)
                self.assert_target(choice, version)


class VersionNoticeTests(unittest.TestCase):
    def test_notices_only_select_the_installed_channel(self):
        source = (ROOT / 'vpngate_manager.py').read_text(encoding='utf-8')
        node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'latest_github_version_ref')
        manifest = json.loads((ROOT / 'release_channels.json').read_text())
        encoded = base64.b64encode(json.dumps(manifest).encode()).decode()
        for kind, expected in [('stable', STABLE_TAG), ('release', RELEASE_TAG)]:
            def api(path):
                return {'content': encoded} if '/contents/' in path else {'sha': 'checked-' + expected}
            namespace = {'github_api_get': api, 'APP_CHANNEL': kind, 'UPDATE_REPO_OWNER': 'tests',
                         'UPDATE_REPO_NAME': 'tests', 'json': json, 'urllib': __import__('urllib.parse')}
            with patch.dict(sys.modules, {'update_channel': channel}):
                exec(compile(ast.Module(body=[node], type_ignores=[]), 'notice', 'exec'), namespace)
                self.assertEqual(namespace['latest_github_version_ref']()[0], expected)


if __name__ == '__main__':
    unittest.main()
