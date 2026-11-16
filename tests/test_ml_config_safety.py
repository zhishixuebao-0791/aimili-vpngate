"""Exercise the shipped CLI functions using temporary configuration files only."""
import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def cli_functions(names, extra, path):
    shell = (ROOT/'install.sh').read_text(encoding='utf-8')
    body = re.search(r"cat > /usr/bin/ml <<'EOF'\n(.*?)\nEOF", shell, re.S).group(1)
    body = body.replace('/opt/aimilivpn/vpngate_data/ui_auth.json', str(path).replace('\\', '/'))
    tree = ast.parse(body)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(nodes) == len(names)
    namespace = dict(extra)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), 'real-cli', 'exec'), namespace)
    return namespace


class ConfigSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'ui_auth.json'
        self.ns = cli_functions(['load_ui_cfg', 'save_ui_cfg'],
            {'os': os, 'time': types.SimpleNamespace(sleep=lambda value: None)}, self.path)
        self.load = self.ns['load_ui_cfg']
        self.save = self.ns['save_ui_cfg']
        self.cfg = {'username': 'fixture-user', 'password': 'fixture-only', 'proxy_port': 7928,
                    'unknown_setting': {'keep': True}, 'secret_path': 'fixture-path'}
        self.path.write_text(json.dumps(self.cfg), encoding='utf-8')

    def test_malformed_file_is_not_replaced_with_defaults(self):
        self.path.write_bytes(b'{')
        cfg = self.load()
        self.assertTrue(cfg['_load_failed'])
        with redirect_stdout(io.StringIO()):
            self.assertFalse(self.save(cfg))
        self.assertEqual(self.path.read_bytes(), b'{')

    def test_valid_non_object_json_is_rejected_without_overwrite(self):
        self.path.write_text('[]', encoding='utf-8')
        cfg = self.load()
        self.assertTrue(cfg['_load_failed'])
        with redirect_stdout(io.StringIO()):
            self.assertFalse(self.save(cfg))
        self.assertEqual(self.path.read_text(), '[]')

    def test_success_preserves_unknown_fields_and_omits_internal_flag(self):
        cfg = self.load()
        cfg['proxy_port'] = 7999
        cfg['_load_failed'] = False
        self.assertTrue(self.save(cfg))
        value = json.loads(self.path.read_text(encoding='utf-8'))
        self.assertEqual(value['unknown_setting'], self.cfg['unknown_setting'])
        self.assertEqual(value['username'], self.cfg['username'])
        self.assertEqual(value['proxy_port'], 7999)
        self.assertNotIn('_load_failed', value)

    def test_replacement_exposes_only_complete_old_or_new_json(self):
        replace = os.replace
        seen = []
        def inspect(source, target):
            seen.append(json.loads(Path(target).read_text(encoding='utf-8')))
            self.assertEqual(json.loads(Path(source).read_text(encoding='utf-8')), self.cfg)
            replace(source, target)
        before = json.loads(self.path.read_text(encoding='utf-8'))
        with patch.object(os, 'replace', side_effect=inspect):
            self.assertTrue(self.save(self.cfg))
        self.assertEqual(seen, [before])
        self.assertFalse(list(self.path.parent.glob('.ui_auth.ml-*')))

    def test_serialization_failure_leaves_original_file_and_cleans_temp(self):
        before = self.path.read_bytes()
        with redirect_stdout(io.StringIO()):
            self.assertFalse(self.save({**self.cfg, 'bad': object()}))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.path.parent.glob('.ui_auth.ml-*')))

    def test_replace_failure_leaves_original_file_and_cleans_temp(self):
        before = self.path.read_bytes()
        with patch.object(os, 'replace', side_effect=PermissionError('fixture')), redirect_stdout(io.StringIO()):
            self.assertFalse(self.save(self.cfg))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.path.parent.glob('.ui_auth.ml-*')))

    def test_concurrent_writers_use_unique_temps_and_leave_a_complete_document(self):
        values = [{**self.cfg, 'writer': i} for i in range(2)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            with redirect_stdout(io.StringIO()):
                result = list(pool.map(self.save, values))
        if os.name == 'nt':
            # Windows may reject overlapping destination handles. The Linux
            # CLI must still retain complete data and report a rejected save.
            self.assertTrue(any(result))
        else:
            self.assertEqual(result, [True, True])
        self.assertIn(json.loads(self.path.read_text(encoding='utf-8')), values)
        self.assertFalse(list(self.path.parent.glob('.ui_auth.ml-*')))

    @unittest.skipIf(os.name == 'nt', 'POSIX configuration permission preservation')
    def test_permissions_are_preserved(self):
        self.path.chmod(0o600)
        self.assertTrue(self.save(self.cfg))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_missing_config_can_be_initialized(self):
        self.path.unlink()
        cfg = self.load()
        self.assertFalse(cfg.get('_load_failed'))
        self.assertTrue(self.save({**cfg, **self.cfg}))
        self.assertEqual(json.loads(self.path.read_text(encoding='utf-8'))['username'], 'fixture-user')

    def test_all_configuration_menus_stop_after_failed_save(self):
        cases = [('configure_web', '1', ['3']), ('configure_web', '2', []),
                 ('configure_port', '', ['1', '9999']), ('configure_port', '', ['2', '7999']),
                 ('configure_credentials', '1', ['new-user', 'fixture-password']),
                 ('configure_credentials', '2', [])]
        for function, key, inputs in cases:
            with self.subTest(function=function, key=key, inputs=inputs):
                restart = Mock()
                answers = iter(inputs)
                save = Mock(return_value=False)
                namespace = cli_functions([function], {'load_ui_cfg': lambda: dict(self.cfg),
                    'save_ui_cfg': save, 'getch': lambda: key, 'input': lambda prompt: next(answers),
                    'ask_restart': restart, 'generate_random_suffix': lambda: 'fixture-next',
                    'generate_random_password': lambda: 'fixture-password',
                    'time': types.SimpleNamespace(sleep=lambda value: None)}, self.path)
                log = io.StringIO()
                with redirect_stdout(log):
                    namespace[function]()
                save.assert_called_once()
                restart.assert_not_called()
                self.assertNotIn('修改成功', log.getvalue())
                self.assertNotIn('重置成功', log.getvalue())
                self.assertNotIn('已更新为', log.getvalue())


if __name__ == '__main__':
    unittest.main()
