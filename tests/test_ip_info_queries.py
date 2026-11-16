"""Real enrichment code, fake HTTP/clocks; no VPN or production state is used."""
import ast
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
from contextlib import redirect_stdout
import importlib.util
import io
import json
import math
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]


def manager_functions(names, extra):
    tree = ast.parse((ROOT/'vpngate_manager.py').read_text(encoding='utf-8'))
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(nodes) == len(names)
    future = ast.ImportFrom(module='__future__', names=[ast.alias(name='annotations')], level=0)
    namespace = dict(extra)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[future]+nodes, type_ignores=[])), 'real-manager', 'exec'), namespace)
    return namespace


class Response:
    def __init__(self, ips, headers=None, raw=None):
        self.headers = headers or {}
        self.raw = raw if raw is not None else json.dumps([
            {'status': 'success', 'query': ip, 'org': 'Fixture ISP', 'country': 'Fixture', 'hosting': False}
            for ip in ips]).encode()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        return self.raw


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        spec = importlib.util.spec_from_file_location('metadata_under_test', ROOT/'vpn_utils.py')
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.m.DATA_DIR = Path(self.temp.name)
        self.m.IP_CACHE_FILE = self.m.DATA_DIR/'ip_cache.json'
        self.clock = 1000.0
        self.m._ip_info_gate = self.m._IpInfoQueryGate(lambda: self.clock)
        self.calls = []
        def query(request, timeout):
            ips = json.loads(request.data)
            self.calls.append(ips)
            return Response(ips)
        self.query = query
        self.http = patch.object(self.m.urllib.request, 'urlopen', side_effect=query).start()
        self.addCleanup(patch.stopall)

    def cache(self, ip='192.0.2.1', age=0, **extra):
        value = {ip: {'cached_at': time.time()-age, 'owner': 'Known ISP', 'ip_type': 'residential', **extra}}
        self.m.IP_CACHE_FILE.write_text(json.dumps(value), encoding='utf-8')

    def test_fresh_cache_does_not_consume_http_budget(self):
        self.cache()
        nodes = [{'ip': '192.0.2.1'}]
        self.m.enrich_ip_info(nodes)
        self.assertEqual(nodes[0]['owner'], 'Known ISP')
        self.assertFalse(self.calls)
        self.assertFalse(self.m._ip_info_gate.requests)

    def test_large_lookup_is_batched_in_hundreds(self):
        nodes = [{'ip': f'198.18.{i//250}.{i%250+1}'} for i in range(201)]
        self.m.enrich_ip_info(nodes)
        self.assertEqual(list(map(len, self.calls)), [100, 100, 1])
        self.assertTrue(all(n['owner'] == 'Fixture ISP' for n in nodes))

    def test_duplicate_ips_in_one_batch_are_queried_once(self):
        nodes = [{'ip': '192.0.2.1'}, {'remote_host': '192.0.2.1'}]
        self.m.enrich_ip_info(nodes)
        self.assertEqual(self.calls, [['192.0.2.1']])
        self.assertEqual(nodes[0]['ip_type'], nodes[1]['ip_type'])

    def test_same_ip_concurrent_cold_queries_do_not_wait_or_duplicate(self):
        entered, release = threading.Event(), threading.Event()
        def slow(request, timeout):
            entered.set()
            self.assertTrue(release.wait(3))
            return Response(json.loads(request.data))
        self.http.side_effect = slow
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.m.enrich_ip_info, [{'ip': '192.0.2.1'}])
            try:
                self.assertTrue(entered.wait(2))
                second = pool.submit(self.m.enrich_ip_info, [{'ip': '192.0.2.1'}])
                second.result(timeout=1)
                self.assertEqual(self.http.call_count, 1)
            finally:
                release.set()
            first.result(timeout=2)
        self.m.enrich_ip_info([{'ip': '192.0.2.1'}])
        self.assertEqual(self.http.call_count, 1)

    def test_parallel_different_ips_merge_cache_entries(self):
        barrier = threading.Barrier(2)
        def query(request, timeout):
            barrier.wait(timeout=3)
            return Response(json.loads(request.data))
        self.http.side_effect = query
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(self.m.enrich_ip_info, [[{'ip': '192.0.2.1'}], [{'ip': '192.0.2.2'}]]))
        self.assertEqual(set(self.m.load_ip_cache()), {'192.0.2.1', '192.0.2.2'})

    def test_rolling_process_budget_does_not_sleep_then_recovers(self):
        with patch.object(self.m.time, 'sleep', side_effect=AssertionError('No cooldown sleeps')):
            for i in range(16):
                self.m.enrich_ip_info([{'ip': f'192.0.2.{i+1}'}])
            self.assertEqual(self.http.call_count, 15)
            self.clock += 60
            self.m.enrich_ip_info([{'ip': '192.0.2.16'}])
        self.assertEqual(self.http.call_count, 16)

    def test_zero_remaining_header_defers_next_request_until_ttl(self):
        self.http.side_effect = lambda request, timeout: Response(json.loads(request.data), {'x-rl': '0', 'x-ttl': '9'})
        self.m.enrich_ip_info([{'ip': '192.0.2.1'}])
        self.m.enrich_ip_info([{'ip': '192.0.2.2'}])
        self.assertEqual(self.http.call_count, 1)
        self.clock += 9
        self.m.enrich_ip_info([{'ip': '192.0.2.2'}])
        self.assertEqual(self.http.call_count, 2)

    def test_429_preserves_expired_metadata_and_uses_cooldown(self):
        self.cache(age=8*86400)
        before = self.m.IP_CACHE_FILE.read_bytes()
        self.http.side_effect = urllib.error.HTTPError('http://fixture.invalid', 429, 'limited', {'X-Ttl': '7', 'Retry-After': '12'}, None)
        node = {'ip': '192.0.2.1', 'probe_status': 'available', 'latency_ms': 42}
        with redirect_stdout(io.StringIO()), patch.object(self.m.time, 'sleep', side_effect=AssertionError('No waits')):
            self.m.enrich_ip_info([node])
            self.clock += 8
            self.m.enrich_ip_info([node])
        self.assertEqual(self.http.call_count, 1)
        self.assertEqual(node['ip_type'], 'residential')
        self.assertEqual(node['probe_status'], 'available')
        self.assertEqual(node['latency_ms'], 42)
        self.assertEqual(before, self.m.IP_CACHE_FILE.read_bytes())
        self.clock += 4
        self.http.side_effect = self.query
        self.m.enrich_ip_info([node])
        self.assertEqual(node['owner'], 'Fixture ISP')

    def test_429_stops_remaining_chunks_without_waiting(self):
        self.http.side_effect = urllib.error.HTTPError('http://fixture.invalid', 429, 'limited', {}, None)
        with redirect_stdout(io.StringIO()):
            self.m.enrich_ip_info([{'ip': f'198.18.0.{i+1}'} for i in range(201)])
        self.assertEqual(self.http.call_count, 1)
        self.assertEqual(self.m._ip_info_gate.retry_at, self.clock+60)

    def test_old_positive_or_shorter_response_cannot_clear_cooldown(self):
        gate = self.m._ip_info_gate
        gate.observe({'X-Rl': '0', 'X-Ttl': '40'})
        gate.observe({'X-Rl': '9', 'X-Ttl': '50'})
        self.clock += 2
        gate.observe({'X-Rl': '0', 'X-Ttl': '5'})
        self.assertEqual(gate.retry_at, 1040)

    def test_bad_cooldown_headers_use_bounded_default(self):
        for value in ['NaN', 'inf', '-9', 'bad']:
            gate = self.m._IpInfoQueryGate(lambda: self.clock)
            gate.observe({'X-Ttl': value}, limited=True)
            self.assertEqual(gate.retry_at, self.clock+60)

    def test_bad_response_releases_claim_and_can_be_retried(self):
        self.http.side_effect = lambda request, timeout: Response([], raw=b'{')
        with redirect_stdout(io.StringIO()):
            self.m.enrich_ip_info([{'ip': '192.0.2.1'}])
        self.assertFalse(self.m._ip_info_gate.inflight)
        self.http.side_effect = self.query
        node = {'ip': '192.0.2.1'}
        self.m.enrich_ip_info([node])
        self.assertEqual(node['owner'], 'Fixture ISP')

    def test_http_timeout_retains_node_information_and_releases_claim(self):
        self.http.side_effect = TimeoutError('fixture timeout')
        node = {'ip': '192.0.2.1', 'owner': 'Existing', 'probe_status': 'available'}
        with redirect_stdout(io.StringIO()):
            self.m.enrich_ip_info([node])
        self.assertEqual(node['owner'], 'Existing')
        self.assertEqual(node['probe_status'], 'available')
        self.assertFalse(self.m._ip_info_gate.inflight)

    def test_unrequested_response_ip_is_not_written_to_cache(self):
        self.http.side_effect = lambda request, timeout: Response(['192.0.2.99'])
        self.m.enrich_ip_info([{'ip': '192.0.2.1'}])
        self.assertFalse(self.m.load_ip_cache())

    def test_partial_api_failure_keeps_existing_fields(self):
        self.cache(age=8*86400)
        self.http.side_effect = lambda request, timeout: Response([], raw=b'[{"status":"fail","query":"192.0.2.1"}]')
        node = {'ip': '192.0.2.1'}
        self.m.enrich_ip_info([node])
        self.assertEqual(node['owner'], 'Known ISP')
        self.assertEqual(node['ip_type'], 'residential')

    def test_type_filters_are_not_relaxed_when_metadata_is_deferred(self):
        nodes = [{'id': 'r', 'ip': '192.0.2.1', 'ip_type': 'residential', 'probe_status': 'available'},
                 {'id': 'h', 'ip': '192.0.2.2', 'ip_type': 'hosting', 'probe_status': 'available'},
                 {'id': 'u', 'ip': '192.0.2.3', 'probe_status': 'available'}]
        self.m._ip_info_gate.observe({}, limited=True)
        self.m.enrich_ip_info(nodes)
        f = manager_functions(['filter_routing_candidates'], {'load_manual_blacklist': lambda: {},
            'manual_blacklist_match_for_node': lambda *args: False, 'node_passes_current_latency': lambda node: True,
            'country_matches': lambda *args: True, 'parse_int': lambda value: int(value or 0)})['filter_routing_candidates']
        for kind, expected in [('all', {'r','h','u'}), ('residential', {'r'}), ('hosting', {'h'})]:
            result = f(nodes, {'routing_mode': 'fixed_region', 'routing_ip_type': kind})
            self.assertEqual({node['id'] for node in result}, expected)


class ManagerBatchTests(unittest.TestCase):
    def test_workers_skip_metadata_and_one_bulk_query_preserves_node_status(self):
        nodes = [{'id': str(i), 'ip': '192.0.2.'+str(i+1)} for i in range(5)]
        worker = Mock(side_effect=lambda node, **kw: {**node, 'probe_status': 'available', 'latency_ms': 10})
        enrich = Mock()
        namespace = {'lock': threading.RLock(), 'read_nodes': lambda: nodes, 'test_node_real_egress': worker,
            'concurrent': concurrent, 'vpn_utils': types.SimpleNamespace(enrich_ip_info=enrich),
            'mark_purity_disabled': lambda node: None, 'load_manual_blacklist': lambda: {},
            'apply_manual_blacklist_to_node': lambda *args: None, 'sort_all_nodes': lambda value: value,
            'write_json': Mock(), 'NODES_FILE': 'fixture', 'cleanup_favorite_node_ids': Mock()}
        namespace.update(favorite_node_ids=lambda cfg: [], load_ui_config=lambda: {},
                         NODE_TIMEOUT_LATENCY_MS=999999, parse_int=lambda value: int(value or 0))
        f = manager_functions(['test_multiple_nodes'], namespace)['test_multiple_nodes']
        result = f([node['id'] for node in nodes])
        self.assertEqual(len(result), 5)
        self.assertEqual(enrich.call_count, 1)
        self.assertEqual(len(enrich.call_args.args[0]), 5)
        self.assertTrue(all(call.kwargs['enrich_metadata'] is False for call in worker.call_args_list))
        self.assertTrue(all(node['probe_status'] == 'available' for node in result))

    def test_single_probe_default_retains_enrichment_and_prior_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            enrich = Mock(side_effect=RuntimeError('metadata unavailable'))
            namespace = {'time': time, 'math': math, 'get_latency_threshold_ms': lambda: 1000,
                'NODE_PROBE_TIMEOUT_SECONDS': 30, 'NODE_TIMEOUT_LATENCY_MS': 999999,
                'load_manual_blacklist': lambda: {}, 'active_node_real_latency': lambda node: None,
                'test_config_path': lambda node: Path(directory)/'fixture.ovpn', 'CONFIG_DIR': Path(directory),
                'get_free_test_index': lambda: 100, 'release_test_index': Mock(), 'stop_process': Mock(),
                'run_openvpn_until_ready': lambda *args, **kw: (True, 'ok', object()),
                'measure_interface_egress_latency': lambda *args, **kw: {'ok': True, 'latency_ms': 10, 'ip': '192.0.2.9'},
                'parse_int': lambda value: int(value or 0), 'manual_blacklist_match_for_node': lambda *args: '',
                'settle_probe_failure_count': lambda *args: None, 'mark_purity_disabled': lambda node: None,
                'is_probe_timeout_message': lambda value: False, 'vpn_utils': types.SimpleNamespace(enrich_ip_info=enrich)}
            f = manager_functions(['test_node_real_egress'], namespace)['test_node_real_egress']
            node = {'id': 'fixture', 'ip': '192.0.2.1', 'config_text': 'fixture only', 'owner': 'Existing', 'ip_type': 'residential'}
            with redirect_stdout(io.StringIO()):
                result = f(node, False)
            self.assertEqual(enrich.call_count, 1)
            self.assertEqual(result['probe_status'], 'available')
            self.assertEqual(result['owner'], 'Existing')
            self.assertEqual(result['ip_type'], 'residential')
            enrich.reset_mock()
            result = f(node, False, enrich_metadata=False)
            enrich.assert_not_called()
            self.assertEqual(result['probe_status'], 'available')


if __name__ == '__main__':
    unittest.main()
