import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import vpngate_manager as manager


TIMEOUT = (28, "000", 3000, "")
TLS_ERROR = (60, "000", 20, "")
NO_CONTENT = (0, "204", 125, "")


class ProxyHTTPS(unittest.TestCase):
    def setUp(self):
        self.probe = Mock()
        self.local = Mock(return_value=None)
        self.process = object()
        patches = patch.multiple(manager, probe_proxy_https=self.probe, local_proxy_port_connect_error=self.local,
                                 active_openvpn_node_id="live", active_openvpn_process=self.process,
                                 sys=SimpleNamespace(platform="linux"), Path=Mock(return_value=Mock(exists=lambda: True)),
                                 read_json=lambda *args: {"active_openvpn_node_id": "live", "proxy_ip": "8.8.8.8"})
        patches.start()
        self.addCleanup(patches.stop)

    def test_both_https_failures_are_not_overridden_by_an_ip_lookup(self):
        self.probe.side_effect = [TIMEOUT, TLS_ERROR]
        result = manager.check_proxy_health()
        self.assertFalse(result["ok"])
        self.assertTrue(result["https_failure"])
        self.assertIn("rc=60", result["error"])
        self.assertEqual(self.probe.call_args_list, [call(url, 3) for url in manager.HTTPS_HEALTH_TARGETS])

    def test_one_provider_suffices_and_latency_excludes_ip_lookup(self):
        self.probe.side_effect = [TIMEOUT, NO_CONTENT, (0, "200", 1, "ip=1.1.1.1\n")]
        self.assertEqual(manager.check_proxy_health(require_egress_ip=True),
                         {"ok": True, "ip": "1.1.1.1", "latency_ms": 125})

    def test_new_tunnel_does_not_inherit_prior_exit_if_reflectors_fail(self):
        cases = [NO_CONTENT, NO_CONTENT, TLS_ERROR, TIMEOUT]
        self.probe.side_effect = cases * 2
        self.assertEqual(manager.check_proxy_health(), {"ok": True, "ip": "8.8.8.8", "latency_ms": 125})
        self.assertFalse(manager.check_proxy_health(require_egress_ip=True)["ok"])

    def test_lost_local_listener_is_not_an_https_node_failure(self):
        port_results = iter((None, OSError("listener lost")))
        self.local.side_effect = lambda timeout: next(port_results)
        self.probe.side_effect = [TIMEOUT, TIMEOUT]
        self.assertTrue(manager.check_proxy_health()["local_failure"])


class CurlHTTPS(unittest.TestCase):
    def test_only_falls_back_to_ipv4_if_ipv6_listener_is_unavailable(self):
        output = '\n0.125 204'
        responses = [subprocess.CompletedProcess([], 7, '0.001 000'), subprocess.CompletedProcess([], 0, output),
                     subprocess.CompletedProcess([], 28, '\n3.000 000')]
        with patch.multiple(manager, LOCAL_PROXY_HOST="::", LOCAL_PROXY_PORT=7928), \
             patch.object(manager.proxy_server, 'get_proxy_credentials', return_value=(None, None)), \
             patch.object(manager.subprocess, 'run', side_effect=responses) as runner:
            url = manager.HTTPS_HEALTH_TARGETS[0]
            self.assertEqual(manager.probe_proxy_https(url, 3), NO_CONTENT)
            self.assertEqual(manager.probe_proxy_https(url, 3), TIMEOUT)
        for invocation, host in zip(runner.call_args_list, ('[::1]', '127.0.0.1', '[::1]')):
            args = invocation.args[0]
            self.assertEqual(args[:2], ['curl', '-q'])
            self.assertEqual(args[args.index('--noproxy') + 1], '')
            self.assertEqual(args[args.index('--proto') + 1], '=https')
            self.assertEqual(args[args.index('--socks5-hostname') + 1], f'{host}:7928')
            self.assertNotIn('--insecure', args)


class Watchdog(unittest.TestCase):
    def check_failover(self, results):
        failed = {"ok": False, "https_failure": True, "error": "dual endpoint timeout"}
        healthy = {"ok": True, "ip": "8.8.8.8", "latency_ms": 125}
        res = {"failed": failed, "healthy": healthy, "missing_tun": {"ok": False, "error": "tun0 unavailable"}}
        node = {"id": "live", "probe_status": "available"}
        check = Mock(side_effect=[*(res[name] for name in results), KeyboardInterrupt()])
        switch, blacklist = Mock(), Mock()
        clock = SimpleNamespace(time=lambda: 0, sleep=Mock())
        with patch.multiple(manager, active_openvpn_node_id="live", active_openvpn_process=object(),
                            is_connecting=False, active_openvpn_running=lambda: True,
                            enforce_active_not_manual_blacklisted=lambda: False, check_proxy_health=check,
                            load_ui_config=lambda: {}, read_nodes=lambda: [node], auto_switch_node=switch,
                            mark_blacklisted=blacklist, write_json=Mock(), cleanup_favorite_node_ids=Mock(),
                            log_to_json=Mock(), set_state=Mock(), time=clock):
            with self.assertRaises(KeyboardInterrupt):
                manager.background_proxy_checker()
        return switch.call_count, blacklist.call_count, clock.sleep.call_args_list

    def test_two_failed_rounds_switch_once_after_short_confirmation(self):
        self.assertEqual(self.check_failover(['failed', 'failed']), (1, 1, [call(30), call(5), call(30)]))

    def test_a_success_resets_the_consecutive_failure_count(self):
        self.assertEqual(self.check_failover(['failed', 'healthy', 'failed']), (0, 0, [call(30), call(5), call(30), call(5)]))

    def test_missing_tunnel_still_switches_without_waiting_for_https_retry(self):
        self.assertEqual(self.check_failover(['missing_tun']), (1, 1, [call(30), call(30)]))


if __name__ == '__main__':
    unittest.main()
