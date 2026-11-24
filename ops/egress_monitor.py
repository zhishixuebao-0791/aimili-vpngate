#!/usr/bin/env python3
"""Record AimiliVPN SOCKS/HTTPS health and bounded local incident snapshots."""

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time


APP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))
from proxy_server import get_proxy_credentials


DATA_DIR = Path(os.environ.get('VPNGATE_DATA_DIR', str(APP_DIR / 'vpngate_data')))
LOG_DIR = Path('/var/log/aimili-monitor')
TARGETS = ('https://www.google.com/generate_204', 'https://cp.cloudflare.com/generate_204')
INTERVAL = 60
SNAPSHOT_COOLDOWN = 120
MAX_SNAPSHOTS = 50
MAX_LOG_BYTES = 5 * 1024 * 1024


def read_object(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def proxy_address():
    settings = read_object(DATA_DIR / 'ui_auth.json')
    port = settings.get('proxy_port', os.environ.get('LOCAL_PROXY_PORT', '7928'))
    try:
        port = int(port)
    except (ValueError, TypeError):
        port = 7928
    if not 1 <= port <= 65535:
        port = 7928
    host = os.environ.get('LOCAL_PROXY_HOST', '127.0.0.1')
    host = {'': '127.0.0.1', 'localhost': '127.0.0.1', '0.0.0.0': '127.0.0.1', '::': '::1'}.get(host, host)
    # Credentials are only used against the configured local listener.
    addr = ipaddress.ip_address(host)
    return f'[{addr}]:{port}' if addr.version == 6 else f'{addr}:{port}'


def probe(url, socks_address):
    arguments = ['curl', '-q', '--silent', '--noproxy', '', '--proto', '=https',
                 '--socks5-hostname', socks_address, '--max-time', '3',
                 '--output', os.devnull, '--write-out', '%{http_code}', url]
    username, password = get_proxy_credentials()
    config = ''
    if username is not None and password is not None:
        escaping = str.maketrans({'\\': '\\\\', '"': '\\"', '\n': '\\n', '\r': '\\r', '\t': '\\t'})
        value = f'{username}:{password}'.translate(escaping)
        config = f'proxy-user = "{value}"\n'
        arguments[2:2] = ['--config', '-']
    start = time.monotonic()
    try:
        result = subprocess.run(arguments, input=config, capture_output=True, text=True, timeout=4)
        status = result.stdout.strip() if result.stdout.strip().isdigit() else '000'
        rc = result.returncode
    except subprocess.TimeoutExpired:
        status, rc = '000', 28
    except OSError:
        status, rc = '000', -1
    return {'ok': rc == 0 and status == '204', 'rc': rc, 'http': status, 'ms': int((time.monotonic() - start) * 1000)}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def append_log(path, value):
    if path.exists() and path.stat().st_size >= MAX_LOG_BYTES:
        path.replace(path.with_name(path.name + '.1'))
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(value, ensure_ascii=False) + '\n')


def snapshot_command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=3)
    except (OSError, subprocess.TimeoutExpired) as error:
        return type(error).__name__
    return (result.stdout + result.stderr)[:12000]


class Monitor:
    def __init__(self, log_dir=LOG_DIR):
        self.log_dir = log_dir
        self.snapshots = log_dir / 'snapshots'
        self.snapshots.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state_file = log_dir / 'health.json'
        self.state = read_object(self.state_file)
        self.failures = 0
        self.last_snapshot = None

    def capture(self, sample):
        now = time.monotonic()
        if self.last_snapshot is not None and now - self.last_snapshot < SNAPSHOT_COOLDOWN:
            return
        self.last_snapshot = now
        active = read_object(DATA_DIR / 'state.json')
        commands = (('interface', ['ip', '-brief', 'address', 'show', 'dev', 'tun0']),
                    ('rules', ['ip', 'rule', 'show']), ('vpn_routes', ['ip', 'route', 'show', 'table', '100']),
                    ('sockets', ['ss', '-s']), ('conntrack', ['conntrack', '-S']))
        context = {k: active.get(k) for k in ('proxy_ok', 'is_connecting', 'active_openvpn_node_id', 'proxy_latency_ms')}
        for name in ('count', 'max'):
            try:
                context['conntrack_' + name] = int(Path('/proc/sys/net/netfilter/nf_conntrack_' + name).read_text())
            except (OSError, ValueError):
                pass
        path = self.snapshots / (datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f') + '.json')
        contents = {'probe': sample, 'manager': context, 'system': {name: snapshot_command(args) for name, args in commands}}
        path.write_text(json.dumps(contents, ensure_ascii=False, indent=2), encoding='utf-8')
        for old in sorted(self.snapshots.glob('*.json'))[:-MAX_SNAPSHOTS]:
            old.unlink(missing_ok=True)
        append_log(self.log_dir / 'events.log', {'time': sample['time'], 'event': 'snapshot', 'name': path.name})

    def tick(self):
        attempts = []
        address = proxy_address()
        for index, url in enumerate(TARGETS):
            result = {'target': index, **probe(url, address)}
            attempts.append(result)
            if result['ok']:
                break
        ok = attempts[-1]['ok']
        self.failures = 0 if ok else self.failures + 1
        status = 'healthy' if ok else 'degraded' if self.failures == 1 else 'unhealthy'
        sample = {'time': timestamp(), 'ok': ok, 'attempts': attempts, 'status': status}
        previous = self.state.get('egress_status')
        self.state.update(observed_at=sample['time'], egress_status=status,
                          consecutive_failures=self.failures, last_probe={'ok': ok, 'attempts': attempts})
        if ok:
            self.state['last_success_at'] = sample['time']
        append_log(self.log_dir / 'egress.log', sample)
        pending = self.state_file.with_suffix('.tmp')
        pending.write_text(json.dumps(self.state, ensure_ascii=False), encoding='utf-8')
        pending.replace(self.state_file)
        if status != previous and status in ('healthy', 'unhealthy'):
            append_log(self.log_dir / 'events.log', {'time': sample['time'], 'event': status})
        if not ok:
            self.capture(sample)


def main():
    os.umask(0o077)
    monitor = Monitor()
    os.chmod(monitor.log_dir, 0o700)
    os.chmod(monitor.snapshots, 0o700)
    while True:
        monitor.tick()
        time.sleep(INTERVAL)


if __name__ == '__main__':
    main()
