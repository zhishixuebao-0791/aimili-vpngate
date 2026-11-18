"""Exercise real manager admission and provider policy without touching a tunnel."""
import ast
from datetime import datetime, timezone
import errno
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

import exit_risk as risk
import proxy_server as proxy

ROOT = Path(__file__).resolve().parents[1]
IP = "1.1.1.1"
OTHER = "8.8.8.8"
NOW = 1800000000
DATE = datetime.fromtimestamp(NOW - 1000, timezone.utc).isoformat()


class Reputation(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "risk.json"
        self.now = NOW
        self.flags = {"risk": 100, "proxy": True, "vpn": True, "hosting": True,
                      "confidence": 100, "compromised": False, "last_seen": DATE}
        self.abuse = {"ipAddress": IP, "abuseConfidenceScore": 0, "totalReports": 0,
                      "numDistinctUsers": 0, "lastReportedAt": None}
        self.http = Mock(side_effect=self.respond)
        self.engine = risk.RiskEngine(self.path, lambda name: "" if name == "ipqs" else "fixture",
                                      clock=lambda: self.now, transport=self.http)

    def respond(self, provider, ip, key):
        if provider == "proxycheck":
            return {"status": "warning", ip: {"detections": self.flags.copy(), "attack_history": None}}
        return {"data": self.abuse.copy()}

    def test_real_response_layout_and_type_only_proxy(self):
        verdict = self.engine.assess(IP, refresh=True)
        self.assertTrue(verdict["auto_eligible"])
        self.assertEqual(verdict["score"], 10)
        self.assertEqual(verdict["providers"]["proxycheck"]["data"]["native_score"], 100)
        self.assertNotIn("fixture", self.path.read_text())

    def test_conflicting_layouts_or_missing_compromised_rejected(self):
        with self.assertRaises(ValueError):
            risk.normalize("proxycheck", {"status":"ok", IP:{"risk":50,"detections":self.flags}}, IP, NOW)
        self.flags.pop("compromised")
        self.assertFalse(self.engine.assess(IP, refresh=True)["auto_eligible"])

    def test_corroborated_recent_abuse_is_high_despite_low_latency_or_short_pool(self):
        self.flags["compromised"] = True
        self.abuse.update(abuseConfidenceScore=86,totalReports=5,numDistinctUsers=3,lastReportedAt=DATE)
        result = self.engine.assess(IP, refresh=True)
        self.assertEqual((result["score"], result["level"], result["auto_eligible"]), (100,"high",False))
        self.assertFalse(self.engine.assess(OTHER)["auto_eligible"])
        self.assertEqual(self.http.call_count, 2)

    def test_single_strong_signal_is_not_eligible(self):
        self.flags["compromised"] = True
        self.assertEqual(self.engine.assess(IP, refresh=True)["level"], "review")

    def test_unexplained_high_score_requires_review(self):
        self.flags["proxy"] = False
        self.assertEqual(self.engine.assess(IP, refresh=True)["level"], "review")

    def test_target_mismatch_missing_sources_and_invalid_egress(self):
        self.abuse["ipAddress"] = OTHER
        self.assertFalse(self.engine.assess(IP, refresh=True)["auto_eligible"])
        for target in ["", "127.0.0.1", "224.0.0.1", "not-an-address"]:
            self.assertIsNone(self.engine.assess(target, refresh=True)["score"])
        self.assertEqual(self.http.call_count, 2)

    def test_restart_keeps_cache_and_quota_but_errors_cannot_renew_it(self):
        self.assertTrue(self.engine.assess(IP, refresh=True)["auto_eligible"])
        fresh = risk.RiskEngine(self.path, lambda name:"x" if name!="ipqs" else "", clock=lambda:self.now,
                                transport=self.http, daily_limit=1)
        self.assertTrue(fresh.assess(IP, refresh=True)["auto_eligible"])
        self.now += risk.TTL_SECONDS
        self.assertFalse(fresh.assess(IP, refresh=True)["auto_eligible"])
        self.assertEqual(self.http.call_count, 2)

    def test_short_429_applies_across_different_ips(self):
        self.http.side_effect = urllib.error.HTTPError("hidden",429,"limited",{"Retry-After":"10"},None)
        self.engine.assess(IP, refresh=True)
        self.engine.assess(OTHER, refresh=True)
        self.assertEqual(self.http.call_count, 2)
        self.assertFalse(self.engine.assess(OTHER)["auto_eligible"])

    def test_ipqs_suspicion_is_independent_of_vpn_status(self):
        for score, recent, strong in [(75, False, False), (90, True, True)]:
            r = risk.normalize("ipqs",{"success":True,"fraud_score":score,
                                       "recent_abuse":recent,"vpn":True},IP,NOW)
            self.assertEqual((r["abuse"],r["strong"]), (recent,strong))


def manager_subset(names, context):
    tree = ast.parse((ROOT/"vpngate_manager.py").read_text(encoding="utf-8"))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[future]+functions, type_ignores=[])), "manager", "exec"), context)
    return context


class Routing(unittest.TestCase):
    def setUp(self):
        import threading
        self.node = {"id":"candidate", "egress_ip":IP, "probe_status":"available", "latency_ms":1}
        self.verdict = Mock(return_value={"auto_eligible":False})
        self.ctx = manager_subset({"connect_node","connect_first_available_candidate","auto_risk_allowed","filter_routing_candidates"}, {
            "RISK_MODE":"enforce", "exit_risk":risk, "risk_engine":Mock(assess=self.verdict), "lock":threading.RLock(),
            "active_openvpn_node_id":"old", "is_connecting":False, "active_openvpn_process":Mock(),
            "read_nodes":lambda:[self.node], "set_state":Mock(), "clear_active_connection_state":Mock(),
            "log_node_activity":Mock(), "log_to_json":Mock(), "active_openvpn_running":lambda:True,
            "load_manual_blacklist":lambda:{}, "manual_blacklist_match_for_node":lambda *args:False,
            "node_passes_current_latency":lambda n:True, "parse_int":lambda n:int(n or 0),
            "load_ui_config":lambda:{}, "stop_active_openvpn":Mock(), "time":__import__("time")})

    def test_favorite_fallback_and_final_reconnect_do_not_stop_current_exit(self):
        for mode in ("auto","favorites","fixed_favorites","fixed_region"):
            self.assertFalse(self.ctx["filter_routing_candidates"]([self.node], {"routing_mode":mode,
                                "favorite_node_ids":["candidate"],"fav_fail_fallback":True}))
        with self.assertRaises(risk.RiskBlockedError):
            self.ctx["connect_node"]("candidate")
        self.assertFalse(self.ctx["connect_first_available_candidate"]([self.node], "recovery")[0])
        self.ctx["stop_active_openvpn"].assert_not_called()
        self.ctx["clear_active_connection_state"].assert_not_called()

    def test_only_explicit_manual_api_can_override_default_gate(self):
        tree = ast.parse((ROOT/"vpngate_manager.py").read_text("utf8"))
        uses = [n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
                and n.func.id == "connect_node" and any(kw.arg=="manual_request" for kw in n.keywords)]
        self.assertEqual(len(uses), 1)
        self.assertIn("payload.get", ast.unparse(uses[0]))

    def test_changed_egress_rejected_before_proxy_is_open(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            self.node["config_file"] = str(path/"candidate.ovpn")
            self.verdict.return_value = {"auto_eligible":True}
            admitted = Mock()
            self.ctx.update(DATA_DIR=path,CONFIG_DIR=path,Path=Path,json=__import__("json"),
                apply_manual_blacklist_to_node=lambda n:False,run_openvpn_until_ready=lambda *a,**kw:(True,"",Mock()),
                setup_policy_routing=Mock(), proxy_server=Mock(admit_tunnel=admitted),
                verify_connected_exit=Mock(side_effect=risk.RiskBlockedError("new exit failed")))
            with self.assertRaises(risk.RiskBlockedError):
                self.ctx["connect_node"]("candidate")
            admitted.assert_not_called()
            self.assertEqual(self.ctx["stop_active_openvpn"].call_count, 2)

    def test_observe_mode_does_not_gate_selection(self):
        self.ctx["RISK_MODE"]="observe"
        self.assertEqual(self.ctx["filter_routing_candidates"]([self.node],{}),[self.node])
        self.verdict.assert_not_called()

    def test_gateway_holds_during_verification_and_rejects_inflight_generation(self):
        self.addCleanup(proxy.admit_tunnel,None)
        proxy.admit_tunnel(())
        with patch.object(proxy, "resolve_dns_over_tun0") as dns, self.assertRaises(OSError) as caught:
            proxy.create_connection(("example.test",443))
        self.assertEqual(caught.exception.errno, errno.EAGAIN)
        dns.assert_not_called()
        proxy.admit_tunnel([socket.AF_INET])
        sock = Mock()
        sock.connect.side_effect = lambda unused: proxy.admit_tunnel(())
        with patch.object(proxy,"resolve_dns_over_tun0",return_value=IP), patch.object(socket,"socket",return_value=sock), \
                patch.object(socket,"SO_BINDTODEVICE",25,create=True), self.assertRaises(OSError):
            proxy.create_connection((IP,443))
        sock.close.assert_called_once()
