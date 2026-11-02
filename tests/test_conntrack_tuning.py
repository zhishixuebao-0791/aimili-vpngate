"""Exercise actual file/command decisions without touching host networking."""
import importlib.util
import ast
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tuning', ROOT / 'conntrack_tuning.py')
tuning = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tuning)


class Commands:
    def __init__(self):
        self.calls, self.rules = [], set()
        self.fail_enable = False
        self.no_raw = False
        self.on_modprobe = None
        self.enabled, self.active = False, False

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        code, output = 0, ''
        if args[0] in ('iptables', 'ip6tables'):
            action = next(x for x in ('-C', '-A', '-D') if x in args)
            rule = (args[0], tuple(args[args.index(action) + 1:]))
            if self.no_raw:
                code = 1
            elif action == '-C':
                code = 0 if rule in self.rules else 1
            elif action == '-A':
                self.rules.add(rule)
            else:
                self.rules.discard(rule)
        elif args[:2] == ['systemctl', 'is-enabled']:
            code, output = (0, 'enabled\n') if self.enabled else (1, 'disabled\n')
        elif args[:2] == ['systemctl', 'is-active'] or (args[0] == 'rc-service' and args[-1] == 'status'):
            code = 0 if self.active else 1
        elif args[:2] == ['systemctl', 'enable'] and self.fail_enable:
            code = 1
        elif args[0] == 'modprobe' and self.on_modprobe:
            self.on_modprobe()
        return subprocess.CompletedProcess(args, code, output, '')


class TuningTests(unittest.TestCase):
    def setUp(self):
        output = patch('builtins.print')
        output.start()
        self.addCleanup(output.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands = Commands()
        self.binaries = {'iptables', 'ip6tables', 'systemctl', 'modprobe'}
        self.make_kernel()
        (self.root / 'run/systemd/system').mkdir(parents=True)

    def make_kernel(self, maximum=7680, timeout=432000, buckets=1920):
        for key, value in [('max', maximum), ('timeout', timeout), ('buckets', buckets)]:
            path = self.root / tuning.RUNTIME[key].lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(value) + '\n')

    def instance(self):
        return tuning.Tuning(self.root, runner=self.commands,
                             which=lambda name: name if name in self.binaries else None)

    def test_systemd_install_applies_and_persists_targets(self):
        instance = self.instance()
        self.assertTrue(instance.install())
        self.assertEqual([instance.number(k) for k in tuning.RUNTIME], [65536, 7200, 16384])
        self.assertEqual(len(self.commands.rules), 4)
        unit = instance.path('/etc/systemd/system/aimili-notrack-lo.service').read_text()
        self.assertIn('Before=aimilivpn.service', unit)
        self.assertIn(tuning.SCRIPT + ' apply', unit)
        self.assertIn(['systemctl', 'start', '--no-block', tuning.SERVICE], self.commands.calls)
        self.assertEqual(json.loads(instance.state_path.read_text())['original_runtime']['max'], 7680)

    def test_reinstall_and_boot_apply_do_not_duplicate_rules_or_replace_baseline(self):
        self.instance().install()
        original = self.instance().state['original_runtime']
        self.instance().install()
        self.instance().apply()
        self.assertEqual(len(self.commands.rules), 4)
        self.assertEqual(self.instance().state['original_runtime'], original)
        adds = [c for c in self.commands.calls if c[0] in ('iptables', 'ip6tables') and '-A' in c]
        self.assertEqual(len(adds), 4)

    def test_larger_capacity_and_shorter_timeout_are_kept(self):
        self.make_kernel(262144, 1800, 65536)
        instance = self.instance()
        instance.install()
        self.assertEqual([instance.number(k) for k in tuning.RUNTIME], [262144, 1800, 65536])
        self.assertIn('nf_conntrack_max=262144', instance.path('/etc/sysctl.d/90-aimili-conntrack.conf').read_text())

    def test_missing_module_is_loaded_before_probing_parameters(self):
        for name in tuning.RUNTIME.values():
            (self.root / name.lstrip('/')).unlink()
        self.commands.on_modprobe = self.make_kernel
        self.assertTrue(self.instance().install())
        self.assertIn(['modprobe', 'nf_conntrack'], self.commands.calls)

    def test_unsupported_kernel_leaves_no_config_or_firewall_changes(self):
        for name in tuning.RUNTIME.values():
            (self.root / name.lstrip('/')).unlink()
        instance = self.instance()
        self.assertFalse(instance.install())
        self.assertFalse(instance.state_path.exists())
        self.assertFalse(instance.path('/etc/sysctl.d/90-aimili-conntrack.conf').exists())
        self.assertFalse(self.commands.rules)

    def test_missing_module_loader_is_nonfatal(self):
        self.binaries.discard('modprobe')
        for name in tuning.RUNTIME.values():
            (self.root / name.lstrip('/')).unlink()
        self.assertFalse(self.instance().install())

    def test_openrc_uses_boot_service_and_orders_before_manager(self):
        self.binaries.discard('systemctl')
        self.binaries.update({'rc-service', 'rc-update'})
        instance = self.instance()
        instance.install()
        script = instance.path('/etc/init.d/aimili-notrack-lo').read_text()
        self.assertTrue(script.startswith('#!/sbin/openrc-run'))
        self.assertIn('before aimilivpn', script)
        self.assertIn(['rc-update', 'add', tuning.SERVICE, 'default'], self.commands.calls)
        self.assertEqual(instance.number('max'), 65536)

    def test_rollback_restores_original_config_and_kernel_parameters(self):
        instance = self.instance()
        path = instance.path('/etc/sysctl.d/90-aimili-conntrack.conf')
        path.parent.mkdir(parents=True)
        path.write_bytes(b'# original custom settings\n')
        instance.install()
        self.instance().rollback()
        self.assertEqual(path.read_bytes(), b'# original custom settings\n')
        self.assertEqual([instance.number(k) for k in tuning.RUNTIME], [7680, 432000, 1920])
        self.assertFalse(self.commands.rules)
        self.assertFalse(instance.path('/etc/systemd/system/aimili-notrack-lo.service').exists())
        self.assertTrue(self.instance().state['rolled_back'])
        self.instance().install()
        self.assertEqual(instance.number('max'), 65536)

    def test_existing_unmarked_rules_survive_install_and_rollback(self):
        instance = self.instance()
        originals = {(binary, tuple(rule)) for binary, rule in instance.rules(owned=False)}
        self.commands.rules.update(originals)
        instance.install()
        self.assertEqual(self.commands.rules, originals)
        self.instance().rollback()
        self.assertEqual(self.commands.rules, originals)

    def test_boot_reapplies_rules_after_firewall_has_cleared_them(self):
        self.instance().install()
        self.commands.rules.clear()
        self.instance().apply()
        self.assertEqual(len(self.commands.rules), 4)

    def test_no_raw_table_is_nonfatal_and_never_flushes_rules(self):
        self.commands.no_raw = True
        self.assertTrue(self.instance().install())
        self.assertEqual(self.instance().number('max'), 65536)
        self.assertFalse(any('-F' in call or '--flush' in call for call in self.commands.calls))

    def test_runtime_customizations_after_install_are_preserved_on_rollback(self):
        self.instance().install()
        self.make_kernel(131072, 3600, 32768)
        self.instance().rollback()
        self.assertEqual([self.instance().number(k) for k in tuning.RUNTIME], [131072, 3600, 32768])

    def test_edited_managed_file_is_not_overwritten_by_reinstall(self):
        instance = self.instance()
        instance.install()
        path = instance.path('/etc/sysctl.d/90-aimili-conntrack.conf')
        path.write_text('# user edit\n')
        with self.assertRaises(RuntimeError):
            self.instance().install()
        self.assertEqual(path.read_text(), '# user edit\n')

    def test_failed_service_enable_rolls_back_partial_install(self):
        self.commands.fail_enable = True
        instance = self.instance()
        with self.assertRaises(RuntimeError):
            instance.install()
        self.assertFalse(instance.path('/etc/sysctl.d/90-aimili-conntrack.conf').exists())
        self.assertFalse(instance.path('/etc/modprobe.d/aimili-conntrack.conf').exists())
        self.assertEqual(instance.number('max'), 7680)

    def test_read_only_kernel_setting_is_skipped(self):
        instance = self.instance()
        original_write = Path.write_text
        def write(path, *args, **kwargs):
            if str(path).endswith('nf_conntrack_max'):
                raise PermissionError('read only')
            return original_write(path, *args, **kwargs)
        with patch.object(Path, 'write_text', write):
            instance.install()
        self.assertEqual(instance.number('max'), 7680)
        self.assertEqual(instance.number('timeout'), 7200)

    def test_no_prior_install_rollback_preserves_existing_rules(self):
        instance = self.instance()
        originals = {(binary, tuple(rule)) for binary, rule in instance.rules(owned=False)}
        self.commands.rules.update(originals)
        instance.rollback()
        self.assertEqual(self.commands.rules, originals)
        self.assertFalse(instance.state_path.exists())

    def test_openrc_rollback_removes_boot_entry_and_owned_rules(self):
        self.binaries.discard('systemctl')
        self.binaries.update({'rc-service', 'rc-update'})
        instance = self.instance()
        instance.install()
        self.instance().rollback()
        self.assertFalse(instance.path('/etc/init.d/aimili-notrack-lo').exists())
        self.assertIn(['rc-update', 'del', tuning.SERVICE, 'default'], self.commands.calls)
        self.assertFalse(self.commands.rules)

    def test_rollback_refuses_to_overwrite_a_later_file_edit(self):
        instance = self.instance()
        instance.install()
        path = instance.path('/etc/sysctl.d/90-aimili-conntrack.conf')
        path.write_text('# later edit\n')
        with self.assertRaises(RuntimeError):
            self.instance().rollback()
        self.assertEqual(path.read_text(), '# later edit\n')


class InstallerLifecycleTests(unittest.TestCase):
    def uninstall(self, returncode):
        text = (ROOT / 'install.sh').read_text(encoding='utf-8')
        cli = text.split("cat > /usr/bin/ml <<'EOF'\n", 1)[1].split('\nEOF\n', 1)[0]
        tree = ast.parse(cli)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'uninstall_service')
        events = []
        def command(args):
            events.append(('command', args))
            return subprocess.CompletedProcess(args, returncode if args[-1] == 'rollback' else 0)
        fake_os = Mock(path=Mock(join=lambda *parts: '/'.join(parts), isfile=lambda _: True))
        stop = lambda: events.append(('stop',))
        namespace = {'INSTALL_DIR': '/test/install', 'input': lambda _: 'y', 'print': Mock(),
                     'stop_service': stop, 'os': fake_os, 'sys': Mock(executable='python3'),
                     'subprocess': Mock(run=command), 'shutil': Mock(which=lambda _: True)}
        exec(compile(ast.Module(body=[function], type_ignores=[]), 'uninstall', 'exec'), namespace)
        namespace['uninstall_service']()
        return events, namespace

    def test_uninstall_rolls_back_before_stopping_or_removing_application(self):
        events, namespace = self.uninstall(0)
        self.assertEqual(events[0], ('command', ['python3', '/test/install/conntrack_tuning.py', 'rollback']))
        self.assertEqual(events[1], ('stop',))
        self.assertIn(('command', ['rm', '-rf', '/test/install']), events)

    def test_failed_rollback_preserves_application_and_rollback_tool(self):
        events, namespace = self.uninstall(1)
        self.assertEqual(len(events), 1)
        namespace['os'].unlink.assert_not_called()


if __name__ == '__main__':
    unittest.main()
