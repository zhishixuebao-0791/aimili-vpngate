"""Exercise actual module initialization without starting a proxy or web server."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StartupListenerTests(unittest.TestCase):
    def test_saved_listener_settings_override_environment_on_initial_import(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            settings = {'username': 'fixture', 'password': 'fixture-password', 'secret_path': 'FixturePath',
                'port': 18787, 'proxy_port': 17929, 'host': '127.0.0.1', 'connection_enabled': False,
                'latency_check_interval_minutes': 5, 'latency_threshold_ms': 500}
            (data / 'ui_auth.json').write_text(json.dumps(settings), encoding='utf-8')
            env = dict(os.environ, VPNGATE_DATA_DIR=str(data), LOCAL_PROXY_PORT='7928', UI_PORT='8787', UI_HOST='::')
            code = ('import json; import vpngate_manager as app; '
                    'print(json.dumps({"proxy":app.LOCAL_PROXY_PORT,"ui":app.UI_PORT,"host":app.UI_HOST}))')
            result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            listeners = json.loads(result.stdout.splitlines()[-1])
            self.assertEqual(listeners, {'proxy': 17929, 'ui': 18787, 'host': '127.0.0.1'})
            saved = json.loads((data / 'ui_auth.json').read_text(encoding='utf-8'))
            self.assertEqual(saved['username'], settings['username'])
            self.assertEqual(saved['password'], settings['password'])
            self.assertEqual(saved['proxy_port'], settings['proxy_port'])


if __name__ == '__main__':
    unittest.main()
