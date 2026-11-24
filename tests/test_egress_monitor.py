import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ops import egress_monitor as monitor


class EgressMonitorTest(unittest.TestCase):
    def test_failure_snapshot_alert_and_recovery(self):
        failure = {'ok': False, 'rc': 28, 'http': '000', 'ms': 3001}
        success = {'ok': True, 'rc': 0, 'http': '204', 'ms': 100}
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            service = monitor.Monitor(logs)
            with patch.object(monitor, 'snapshot_command', return_value='sample'), \
                 patch.object(monitor, 'proxy_address', return_value='127.0.0.1:7928'), \
                 patch.object(monitor, 'probe', side_effect=[failure, failure, failure, failure, success]):
                for expected in ('degraded', 'unhealthy', 'healthy'):
                    service.tick()
                    self.assertEqual(json.loads((logs / 'health.json').read_text())['egress_status'], expected)
            self.assertEqual(len(list((logs / 'snapshots').glob('*.json'))), 1)
            recorded = [json.loads(line) for line in (logs / 'events.log').read_text().splitlines()]
            self.assertEqual([row['event'] for row in recorded], ['snapshot', 'unhealthy', 'healthy'])

    def test_curl_uses_proxy_dns_and_does_not_expose_credentials(self):
        with patch.object(monitor, 'get_proxy_credentials', return_value=('demo', 'quote"slash\\')), \
             patch.object(monitor.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '204', '')) as run:
            self.assertTrue(monitor.probe(monitor.TARGETS[0], '127.0.0.1:7901')['ok'])
        args = run.call_args.args[0]
        self.assertEqual(args[args.index('--socks5-hostname') + 1], '127.0.0.1:7901')
        self.assertEqual(args[args.index('--proto') + 1], '=https')
        self.assertNotIn('demo', ' '.join(args))
        self.assertEqual(run.call_args.kwargs['input'], 'proxy-user = "demo:quote\\"slash\\\\"\n')

    def test_uses_saved_proxy_port(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            (data / 'ui_auth.json').write_text('{"proxy_port":17929}', encoding='utf-8')
            with patch.object(monitor, 'DATA_DIR', data), patch.dict('os.environ', {'LOCAL_PROXY_HOST': '::'}):
                self.assertEqual(monitor.proxy_address(), '[::1]:17929')


@unittest.skipUnless(os.name == 'posix' and shutil.which('sh'), 'Requires a Linux shell sandbox')
class MonitorServiceTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        marker = self.directory / 'running-systemd'
        marker.mkdir()
        self.unit = self.directory / 'aimili-monitor.service'
        app = self.directory / 'app'
        (app / 'ops').mkdir(parents=True)
        (app / 'ops/egress_monitor.py').touch()
        raw = (Path(monitor.__file__).parent / 'install_monitor.sh').read_text(encoding='utf-8')
        self.script = raw.replace('/run/systemd/system', str(marker))
        self.script = self.script.replace('/etc/systemd/system', str(self.directory)).replace('/opt/aimilivpn', str(app))
        self.calls = self.directory / 'calls'
        fake = self.directory / 'systemctl'
        fake.write_text('#!/bin/sh\n[ "$1" = show ] || printf "%s\\n" "$*" >> "$CALLS"\n')
        fake.chmod(0o755)

    def invoke(self, action):
        env = dict(os.environ, PATH=f'{self.directory}:{os.environ["PATH"]}', CALLS=str(self.calls))
        subprocess.run(['sh', '-c', self.script, 'install_monitor.sh', action], env=env, check=True,
                       capture_output=True, timeout=6)

    def test_systemd_monitor_registers_and_removes_only_its_own_service(self):
        self.invoke('install')
        self.assertIn('After=network.target aimilivpn.service', self.unit.read_text())
        self.assertIn('WantedBy=multi-user.target', self.unit.read_text())
        self.invoke('uninstall')
        self.assertFalse(self.unit.exists())
        self.assertEqual(self.calls.read_text().splitlines(), ['daemon-reload', 'enable --now aimili-monitor.service',
                                                             'disable --now aimili-monitor.service', 'daemon-reload'])

    def test_systemd_monitor_leaves_custom_unit_untouched(self):
        self.unit.write_text('local administrator unit\n')
        self.invoke('install')
        self.invoke('uninstall')
        self.assertEqual(self.unit.read_text(), 'local administrator unit\n')
        self.assertFalse(self.calls.exists())
