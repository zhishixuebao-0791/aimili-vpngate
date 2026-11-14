"""Exercise service installation only under temporary paths and command stubs."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Requires a Linux shell sandbox')
class OpenRCSupervisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.openrc = self.root / 'init.d/aimilivpn'
        self.systemd = self.root / 'systemd/aimilivpn.service'
        self.openrc.parent.mkdir()
        self.systemd.parent.mkdir()
        self.calls = self.root / 'service-calls'
        source = (ROOT / 'install.sh').read_text(encoding='utf-8')
        self.section = source.split('# 5. Configure Service\n', 1)[1].split('# 6. Configure global command shortcut', 1)[0]
        self.section = self.section.replace('/etc/init.d/aimilivpn', str(self.openrc))
        self.section = self.section.replace('/lib/systemd/system/aimilivpn.service', str(self.systemd))
        self.stub('chmod', 'exec /bin/chmod "$@"')
        self.stub('cat', 'exec /bin/cat "$@"')
        self.stub('rc-update', 'printf "%s\\n" "$*" >> ' + shlex.quote(str(self.calls)))

    def stub(self, name, body='exit 0'):
        target = self.bin / name
        target.write_text('#!/bin/sh\n' + body + '\n')
        target.chmod(0o755)

    def run_section(self):
        env = dict(os.environ, PATH=str(self.bin), INSTALL_DIR=str(self.root / 'app'))
        return subprocess.run([shutil.which('bash'), '--noprofile', '--norc', '-c', self.section],
            env=env, cwd=self.root, capture_output=True, text=True, timeout=8)

    def test_missing_supervisor_preserves_existing_openrc_service(self):
        self.stub('rc-service')
        self.openrc.write_text('existing-service\n')
        result = self.run_section()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('supervise-daemon', result.stdout)
        self.assertEqual(self.openrc.read_text(), 'existing-service\n')
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.systemd.exists())

    def test_supported_openrc_installs_foreground_supervision(self):
        self.stub('rc-service')
        self.stub('supervise-daemon')
        result = self.run_section()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.access(self.openrc, os.X_OK))
        script = self.openrc.read_text()
        self.assertIn('supervisor="supervise-daemon"', script)
        self.assertNotIn('command_background=', script)
        self.assertIn('respawn_delay=5', script)
        self.assertIn('respawn_max=0', script)
        self.assertIn(str(self.root / 'app/vpngate_manager.py'), script)
        self.assertEqual(self.calls.read_text().strip(), 'add aimilivpn default')
        self.assertFalse(self.systemd.exists())

    def test_systemd_install_does_not_require_openrc_supervisor(self):
        self.stub('systemctl', 'printf "%s\\n" "$*" >> ' + shlex.quote(str(self.calls)))
        result = self.run_section()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Restart=always', self.systemd.read_text())
        self.assertIn('RestartSec=5', self.systemd.read_text())
        self.assertEqual(self.calls.read_text().splitlines(), ['daemon-reload', 'enable aimilivpn.service'])
        self.assertFalse(self.openrc.exists())


if __name__ == '__main__':
    unittest.main()
