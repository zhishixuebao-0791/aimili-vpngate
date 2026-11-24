"""Exercise real manager admission and provider policy without touching a tunnel."""
import ast
from datetime import datetime, timezone
from email.message import Message
import errno
import ipaddress
import json
from pathlib import Path
import re
import socket
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import urllib.error

import exit_risk as risk
import proxy_server as proxy
import vpn_utils

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
        self.assertTrue(self.engine.assess(IP, refresh=True)["auto_eligible"])

    def test_corroborated_recent_abuse_is_high_despite_low_latency_or_short_pool(self):
        self.flags["compromised"] = True
        self.abuse.update(abuseConfidenceScore=86,totalReports=5,numDistinctUsers=3,lastReportedAt=DATE)
        result = self.engine.assess(IP, refresh=True)
        self.assertEqual((result["score"], result["level"], result["auto_eligible"]), (100,"high",False))
        self.assertTrue(self.engine.assess(OTHER)["auto_eligible"])
        self.assertEqual(self.http.call_count, 2)

    def test_single_strong_signal_stays_eligible_for_review(self):
        self.flags["compromised"] = True
        verdict = self.engine.assess(IP, refresh=True)
        self.assertEqual(verdict["level"], "review")
        self.assertTrue(verdict["auto_eligible"])

    def test_unexplained_high_score_requires_review(self):
        self.flags["proxy"] = False
        self.assertEqual(self.engine.assess(IP, refresh=True)["level"], "review")

    def test_target_mismatch_missing_sources_and_invalid_egress(self):
        self.abuse["ipAddress"] = OTHER
        verdict = self.engine.assess(IP, refresh=True)
        self.assertEqual(verdict["level"], "unknown")
        self.assertTrue(verdict["auto_eligible"])
        for target in ["", "127.0.0.1", "224.0.0.1", "not-an-address"]:
            self.assertIsNone(self.engine.assess(target, refresh=True)["score"])
        self.assertEqual(self.http.call_count, 2)

    def test_restart_keeps_cache_and_quota_but_errors_cannot_renew_it(self):
        self.assertTrue(self.engine.assess(IP, refresh=True)["auto_eligible"])
        fresh = risk.RiskEngine(self.path, lambda name:"x" if name!="ipqs" else "", clock=lambda:self.now,
                                transport=self.http, daily_limit=1)
        self.assertTrue(fresh.assess(IP, refresh=True)["auto_eligible"])
        self.now += risk.TTL_SECONDS
        verdict = fresh.assess(IP, refresh=True)
        self.assertEqual(verdict["level"], "unknown")
        self.assertTrue(verdict["auto_eligible"])
        self.assertEqual(self.http.call_count, 2)

    def test_short_429_applies_across_different_ips(self):
        self.engine.keys = lambda p: () if p == "ipqs" else (p + "-first", p + "-second")
        self.http.side_effect = urllib.error.HTTPError("hidden",429,"limited",{"Retry-After":"10"},None)
        self.engine.assess(IP, refresh=True)
        self.engine.assess(OTHER, refresh=True)
        self.assertEqual(self.http.call_count, 2)
        self.assertTrue(self.engine.assess(OTHER)["auto_eligible"])
        self.now += 61
        self.http.side_effect = self.respond
        self.engine.assess(IP, refresh=True)
        self.assertEqual([c.args[2] for c in self.http.call_args_list],
                         ["proxycheck-first", "abuseipdb-first", "proxycheck-second", "abuseipdb-second"])

    def test_rotating_each_provider_uses_persisted_request_count(self):
        def keys(provider):
            return () if provider == "ipqs" else (provider + "-first", provider + "-second")

        self.engine.keys = keys
        self.engine.assess(IP, refresh=True)
        self.engine.assess(IP, refresh=True)  # Cached response consumes no key or budget.
        self.now += risk.TTL_SECONDS
        restored = risk.RiskEngine(self.path, keys, clock=lambda: self.now, transport=self.http)
        restored.assess(IP, refresh=True)
        self.now += risk.TTL_SECONDS
        restored.assess(IP, refresh=True)
        self.assertEqual([c.args[2] for c in self.http.call_args_list],
                         ["proxycheck-first", "abuseipdb-first", "proxycheck-second", "abuseipdb-second",
                          "proxycheck-first", "abuseipdb-first"])
        self.assertNotIn("proxycheck-first", self.path.read_text(encoding="utf-8"))

    def test_ipqs_share_stays_within_daily_free_budget(self):
        for _ in range(30):
            self.assertFalse(self.engine._reserve("ipqs", self.now))
            self.now += 61
        restored = risk.RiskEngine(self.path, self.engine.keys, clock=lambda: self.now, transport=self.http)
        self.assertTrue(restored._reserve("ipqs", self.now))
        self.assertFalse(restored._reserve("abuseipdb", self.now))
        self.now += 86400
        self.assertFalse(restored._reserve("ipqs", self.now))

    def test_ipqs_exhausted_credit_isolated_to_one_key(self):
        settings = risk.RiskSettings(self.path.with_name("settings.json"), lambda _: ())
        settings.update(True, {"ipqs": ["fixture-first", "fixture-second"]}, 0)
        settings.validate_pending(lambda provider, key: ("valid", 0), clock=lambda: self.now)
        replies = Mock(side_effect=[{"success": False, "message": "insufficient credits"},
                                    {"success": True, "fraud_score": 0, "recent_abuse": False}])
        self.engine = risk.RiskEngine(self.path, settings.keys_for, clock=lambda: self.now,
                                      transport=replies, key_failure=settings.record_query_failure)
        self.engine.assess(IP, refresh=True)
        verdict = self.engine.assess(OTHER, refresh=True)
        self.assertEqual(settings.keys_for("ipqs"), ("fixture-second",))
        self.assertIn("ipqs", verdict["sources"])
        self.assertEqual([call.args[2] for call in replies.call_args_list], ["fixture-first", "fixture-second"])

    def test_reads_ipqs_section_without_mixing_credentials(self):
        config = self.path.with_name("API_Port.txt")
        ipqs_key = "b" * 64
        config.write_text("proxycheck.io每个账号\nabc123-def456-ghi789-jkl012\n"
                          "AbuseIPDB每个账号\n" + "a" * 80 + "\nIPQualityScore每个账号\n"
                          "https://www.ipqualityscore.com/\n邮件地址:user@example.net\nAPI Keys：" + ipqs_key + "\n",
                          encoding="utf-8-sig")
        with patch.object(vpn_utils, "API_KEYS_FILE", config), patch.dict("os.environ", {"IPQS_API_KEY": ipqs_key}):
            self.assertEqual(vpn_utils._load_api_port_keys(), (["abc123-def456-ghi789-jkl012"], ["a" * 80], [ipqs_key]))
            self.assertEqual(vpn_utils.get_ipqs_keys(), [ipqs_key])

    def test_high_survives_expiry_and_restart_until_fresh_low(self):
        self.flags["compromised"] = True
        self.abuse.update(abuseConfidenceScore=86,totalReports=5,numDistinctUsers=3,lastReportedAt=DATE)
        self.assertEqual(self.engine.assess(IP, refresh=True)["level"], "high")
        self.now += risk.TTL_SECONDS + 1
        restored = risk.RiskEngine(self.path, self.engine.keys, clock=lambda: self.now, transport=self.http)
        self.assertEqual(restored.assess(IP)["level"], "high")
        self.http.side_effect = TimeoutError
        self.assertFalse(restored.assess(IP, refresh=True)["auto_eligible"])
        self.now += 61
        self.flags["compromised"] = False
        self.abuse.update(abuseConfidenceScore=0,totalReports=0,numDistinctUsers=0,lastReportedAt=None)
        self.http.side_effect = self.respond
        self.assertEqual(restored.assess(IP, refresh=True)["level"], "low")
        self.assertTrue(restored.assess(IP)["auto_eligible"])

    def test_ipqs_suspicion_is_independent_of_vpn_status(self):
        for score, recent, strong in [(75, False, False), (90, True, True)]:
            r = risk.normalize("ipqs",{"success":True,"fraud_score":score,
                                       "recent_abuse":recent,"vpn":True},IP,NOW)
            self.assertEqual((r["abuse"],r["strong"]), (recent,strong))


class Settings(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "risk_settings.json"
        self.legacy = lambda provider: ["fixture-legacy"] if provider == "proxycheck" else []

    def test_defaults_off_and_reuses_legacy_credentials_after_opt_in(self):
        settings = risk.RiskSettings(self.path, self.legacy)
        self.assertFalse(settings.enabled)
        self.assertEqual(settings.summary()["key_counts"]["proxycheck"], 1)
        transport = Mock()
        engine = risk.RiskEngine(self.path.with_name("cache.json"), settings.keys_for, transport=transport)
        engine.assess(IP, refresh=True)
        transport.assert_not_called()
        result = settings.update(True, {"proxycheck": [0, "fixture-new", "fixture-new"]}, 0)
        self.assertEqual(result["key_counts"]["proxycheck"], 2)
        self.assertNotIn("fixture", str(result))
        saved = risk.RiskSettings(self.path, self.legacy)
        self.assertEqual(saved.summary()["status"], "checking")
        self.assertFalse(saved.active)
        self.assertTrue(saved.protect_cached)
        saved.validate_pending(lambda provider, key: ("valid", 0))
        self.assertEqual(saved.keys_for("proxycheck"), ("fixture-legacy", "fixture-new"))
        saved.update(False, {}, result["revision"])
        self.assertFalse(saved.keys_for("proxycheck"))
        self.assertEqual(saved.summary()["key_counts"]["proxycheck"], 2)

    def test_rejects_empty_enable_oversize_and_stale_edits(self):
        settings = risk.RiskSettings(self.path, lambda _: [])
        with self.assertRaisesRegex(risk.RiskSettingsError, "开启风险检测无效"):
            settings.update(True, {}, 0)
        with self.assertRaisesRegex(risk.RiskSettingsError, "最多可填写 5 个"):
            settings.update(True, {"ipqs": [f"fixture-{i}" for i in range(6)]}, 0)
        self.assertFalse(self.path.exists())
        settings.update(True, {"ipqs": [f"fixture-{i}" for i in range(5)]}, 0)
        with self.assertRaises(risk.StaleRiskSettings):
            settings.update(False, {"ipqs": []}, 0)
        self.assertEqual(settings.summary()["key_counts"]["ipqs"], 5)

    def test_failed_save_preserves_active_credentials(self):
        settings = risk.RiskSettings(self.path, self.legacy)
        with patch.object(risk, "write_private_json", side_effect=OSError):
            with self.assertRaises(OSError):
                settings.update(True, {"proxycheck": ["fixture-new"]}, 0)
        self.assertFalse(settings.enabled)
        self.assertEqual(settings.summary()["revision"], 0)

    def test_invalid_keys_hold_switch_on_without_polling_and_allow_replacement(self):
        settings = risk.RiskSettings(self.path, lambda _: [])
        settings.update(True, {"proxycheck": ["fixture-invalid"]}, 0)
        settings.validate_pending(lambda provider, key: ("invalid", 0))
        self.assertTrue(settings.enabled)
        self.assertFalse(settings.active)
        self.assertEqual(settings.summary()["status"], "invalid")
        self.assertEqual(settings.keys_for("proxycheck"), ())
        settings.update(True, {"proxycheck": [0, "fixture-valid"]}, 1)
        settings.validate_pending(lambda provider, key: (key.removeprefix("fixture-"), 0))
        self.assertTrue(settings.active)
        self.assertEqual(settings.keys_for("proxycheck"), ("fixture-valid",))
        settings.update(False, {"proxycheck": []}, 2)
        self.assertEqual(settings.summary()["status"], "off")

    def test_key_check_distinguishes_denied_from_service_limits(self):
        engine = risk.RiskEngine(self.path, lambda _: (), transport=Mock())
        engine.transport.side_effect = urllib.error.HTTPError("hidden", 401, "unauthorized", {}, None)
        self.assertEqual(engine.validate_key("proxycheck", "fixture-a"), ("invalid", 0))
        engine.transport.side_effect = urllib.error.HTTPError("hidden", 429, "limited", {"Retry-After": "300"}, None)
        first_retry = engine.validate_key("proxycheck", "fixture-b")
        self.assertEqual(first_retry[0], "unavailable")
        self.assertEqual(engine.validate_key("proxycheck", "fixture-c"), first_retry)
        self.assertEqual(engine.transport.call_count, 2)

    def test_temporarily_unavailable_key_retries_after_cooldown(self):
        now = [NOW]
        clock = lambda: now[0]
        settings = risk.RiskSettings(self.path, self.legacy, legacy_enabled=True)
        transport = Mock(side_effect=urllib.error.HTTPError("hidden", 429, "limited", {"Retry-After": "60"}, None))
        engine = risk.RiskEngine(self.path.with_name("cache.json"), settings.keys_for, clock=clock, transport=transport)
        settings.validate_pending(engine.validate_key, clock=clock)
        self.assertEqual(settings.summary()["status"], "unavailable")
        self.assertTrue(settings.protect_cached)
        transport.side_effect = None
        transport.return_value = {"status": "ok", "1.1.1.1": {"detections": {"risk": 0, "compromised": False}}}
        now[0] += 59
        settings.validate_pending(engine.validate_key, clock=clock)
        self.assertEqual(transport.call_count, 1)
        now[0] += 1
        settings.validate_pending(engine.validate_key, clock=clock)
        self.assertTrue(settings.active)

    def test_query_rejection_removes_previously_valid_key(self):
        settings = risk.RiskSettings(self.path, self.legacy, legacy_enabled=True)
        settings.validate_pending(lambda *_: ("valid", 0))
        failure = urllib.error.HTTPError("hidden", 401, "unauthorized", {}, None)
        engine = risk.RiskEngine(self.path.with_name("cache.json"), settings.keys_for,
                                 transport=Mock(side_effect=failure), key_failure=settings.record_query_failure)
        engine.assess(IP, refresh=True)
        self.assertTrue(settings.enabled)
        self.assertEqual(settings.summary()["status"], "invalid")
        self.assertFalse(settings.protect_cached)
        self.assertEqual(settings.keys_for("proxycheck"), ())

    def test_legacy_enforce_migrates_without_reenabling_a_saved_off_value(self):
        settings = risk.RiskSettings(self.path, self.legacy, legacy_enabled=True)
        self.assertTrue(settings.enabled)
        self.assertTrue(settings.protect_cached)
        settings.update(False, {}, 0)
        restored = risk.RiskSettings(self.path, self.legacy, legacy_enabled=True)
        self.assertFalse(restored.enabled)
        self.assertFalse(restored.protect_cached)


def manager_subset(names, context):
    tree = ast.parse((ROOT/"vpngate_manager.py").read_text(encoding="utf-8"))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[future]+functions, type_ignores=[])), "manager", "exec"), context)
    return context


class Retention(unittest.TestCase):
    def test_non_timeout_failure_is_removed_except_protected_nodes(self):
        functions = {"prune_failed_nodes", "node_should_be_removed_after_unfavorite", "cleanup_probe_results",
                     "cap_nodes_preserving_high_risk", "node_risk", "protect_node_from_cleanup",
                     "apply_probe_result", "remember_risk_exit"}
        ctx = manager_subset(functions, {
            "exit_risk":risk, "risk_engine":Mock(assess=lambda ip: {"level": "high" if ip == IP else "unknown"}),
            "parse_int":lambda n: int(n or 0), "active_openvpn_node_id":"active",
            "get_latency_threshold_ms":lambda *args:500, "NODE_TIMEOUT_LATENCY_MS":-1,
            "load_manual_blacklist":lambda:{}, "manual_blacklist_match_for_node":lambda *args: False,
            "sort_all_nodes":lambda n:n, "favorite_node_ids":lambda cfg:cfg["favorite_node_ids"],
        })
        make = lambda node_id, **extra: dict(id=node_id, probe_status="unavailable", latency_ms=0, **extra)
        high = make("high", egress_ip=IP)
        ctx["apply_probe_result"](high, {"egress_ip":""})
        rows = [make("failed"), high, make("active"), make("favorite"), make("manual", manual_blacklisted=True),
                {"id":"unknown", "probe_status":"available", "latency_ms":12, "egress_ip":OTHER}]
        expected = {"high","active","favorite","manual","unknown"}
        for cleaned in [ctx["cleanup_probe_results"](rows, {"favorite_node_ids":["favorite"]}),
                        ctx["prune_failed_nodes"](rows, {"favorite"})]:
            self.assertEqual({n["id"] for n in cleaned}, expected)
        self.assertIn(high, ctx["cap_nodes_preserving_high_risk"](rows, 1))


class Routing(unittest.TestCase):
    def setUp(self):
        import threading
        self.node = {"id":"candidate", "egress_ip":IP, "probe_status":"available", "latency_ms":1}
        self.verdict = Mock(return_value={"level":"high", "auto_eligible":False})
        self.ctx = manager_subset({"connect_node","connect_first_available_candidate","auto_risk_allowed","filter_routing_candidates","node_risk","risk_gate_enabled"}, {
            "RISK_MODE":"enforce", "exit_risk":risk, "risk_engine":Mock(assess=self.verdict), "lock":threading.RLock(),
            "risk_settings":SimpleNamespace(protect_cached=True, lock=threading.RLock()),
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
            self.verdict.return_value = {"level":"unknown", "auto_eligible":True}
            admitted = Mock()
            self.ctx.update(DATA_DIR=path,CONFIG_DIR=path,Path=Path,json=__import__("json"),
                apply_manual_blacklist_to_node=lambda n:False,run_openvpn_until_ready=lambda *a,**kw:(True,"",Mock()),
                setup_policy_routing=Mock(), proxy_server=Mock(admit_tunnel=admitted),
                verify_automatic_tunnel=Mock(side_effect=risk.RiskBlockedError("new exit failed")))
            with self.assertRaises(risk.RiskBlockedError):
                self.ctx["connect_node"]("candidate")
            admitted.assert_not_called()
            self.assertEqual(self.ctx["stop_active_openvpn"].call_count, 2)

    def test_unknown_is_available_for_automatic_selection(self):
        self.verdict.return_value = {"level":"unknown", "auto_eligible":True}
        self.assertEqual(self.ctx["filter_routing_candidates"]([self.node],{}),[self.node])

    def test_successful_switch_prunes_retired_failure_using_latest_rows_and_protections(self):
        for previous_role in ("failed", "available", "favorite", "fixed", "manual", "high"):
            with self.subTest(previous_role=previous_role), tempfile.TemporaryDirectory() as td:
                path = Path(td)
                previous = {"id": "old", "active": True, "probe_status": "unavailable", "latency_ms": 15}
                if previous_role == "available":
                    previous["probe_status"] = "available"
                elif previous_role == "manual":
                    previous["manual_blacklisted"] = True
                elif previous_role == "high":
                    previous["egress_ip"] = IP
                candidate = dict(self.node, config_file=str(path / "candidate.ovpn"))
                unrelated = {"id": "concurrent", "probe_status": "available", "latency_ms": 2}
                rows = [previous, candidate]
                ui = {"favorite_node_ids": [], "fixed_node_id": ""}

                def check_health(*, require_egress_ip=False):
                    self.assertTrue(require_egress_ip)
                    rows.append(unrelated)
                    if previous_role == "favorite":
                        ui["favorite_node_ids"].append("old")
                    elif previous_role == "fixed":
                        ui["fixed_node_id"] = "old"
                    return {"ok": True, "ip": OTHER, "latency_ms": 5}

                self.ctx["risk_settings"].protect_cached = False
                write = Mock()
                cached_verdict = lambda ip: {"level": "high" if ip == IP else "unknown"}
                context = {**self.ctx, "read_nodes": lambda: [dict(item) for item in rows],
                           "DATA_DIR": path, "CONFIG_DIR": path, "NODES_FILE": path / "nodes.json", "Path": Path,
                           "risk_engine": Mock(assess=cached_verdict),
                           "LOCAL_PROXY_HOST": "::", "LOCAL_PROXY_PORT": 7928, "json": json,
                           "load_ui_config": lambda: dict(ui), "apply_manual_blacklist_to_node": lambda node: False,
                           "run_openvpn_until_ready": lambda *args, **kwargs: (True, "", Mock()),
                           "setup_policy_routing": Mock(), "proxy_server": Mock(), "check_proxy_health": check_health,
                           "normalize_ip_value": lambda value: value, "write_json": write, "NODE_TIMEOUT_LATENCY_MS": -1,
                           "get_latency_threshold_ms": lambda *args: 500, "favorite_node_ids": lambda cfg: cfg["favorite_node_ids"]}
                functions = {"connect_node", "auto_risk_allowed", "node_risk", "risk_gate_enabled", "remember_risk_exit",
                             "cleanup_probe_results", "node_should_be_removed_after_unfavorite", "protect_node_from_cleanup"}
                manager = manager_subset(functions, context)
                self.assertEqual(manager["connect_node"]("candidate"), "Connected candidate")
                saved = {item["id"]: item for item in write.call_args.args[1]}
                self.assertEqual("old" in saved, previous_role != "failed")
                self.assertEqual(saved["concurrent"]["latency_ms"], 2)
                self.assertEqual(saved["candidate"]["egress_ip"], OTHER)
                self.assertEqual([item["id"] for item in saved.values() if item["active"]], ["candidate"])

    def test_tunnel_rechecks_actual_exit_and_records_rejected_new_address(self):
        measured = dict(self.node)
        backup = dict(self.node)
        write = Mock()
        ctx = manager_subset({"verify_automatic_tunnel","remember_risk_exit"}, {
            **self.ctx, "socket":socket, "proxy_server":Mock(tun0_supports_ipv6=lambda:False),
            "verify_connected_exit":lambda version:OTHER, "read_nodes":lambda:[backup],
            "write_json":write, "NODES_FILE":"test-fixture",
        })
        with self.assertRaises(risk.RiskBlockedError):
            ctx["verify_automatic_tunnel"](measured)
        self.assertEqual(backup["risk_exit_ipv4"], OTHER)
        self.verdict.assert_called_with(OTHER, refresh=True)
        write.assert_called_once()
        self.verdict.return_value = {"level":"unknown"}
        self.assertEqual(ctx["verify_automatic_tunnel"](measured), ([socket.AF_INET], [OTHER]))

    def test_observe_mode_does_not_gate_selection(self):
        self.ctx["RISK_MODE"]="observe"
        self.assertEqual(self.ctx["filter_routing_candidates"]([self.node],{}),[self.node])
        self.verdict.assert_not_called()

    def test_disabled_risk_ignores_cached_high_for_routing(self):
        self.ctx["risk_settings"].protect_cached = False
        self.assertEqual(self.ctx["filter_routing_candidates"]([self.node], {}), [self.node])
        self.verdict.assert_not_called()

    def test_risk_activated_during_handshake_is_applied_before_admission(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            self.node["config_file"] = str(path / "candidate.ovpn")
            settings = self.ctx["risk_settings"]
            settings.protect_cached = False
            def connect(*args, **kwargs):
                self.assertTrue(kwargs["guard_reconnect"])
                settings.protect_cached = True
                return True, "", Mock()
            admitted = Mock()
            verify = Mock(side_effect=risk.RiskBlockedError("known high"))
            self.ctx.update(DATA_DIR=path, CONFIG_DIR=path, Path=Path, json=json,
                apply_manual_blacklist_to_node=lambda n:False, run_openvpn_until_ready=connect,
                setup_policy_routing=Mock(), proxy_server=Mock(admit_tunnel=admitted), verify_automatic_tunnel=verify)
            with self.assertRaises(risk.RiskBlockedError):
                self.ctx["connect_node"]("candidate")
            admitted.assert_not_called()
            verify.assert_called_once()

    def test_refresh_without_backup_leaves_running_tunnel_intact(self):
        self.ctx["risk_settings"].protect_cached = False
        row = dict(self.node, id="old", active=True, latency_ms=800)
        context = {
            **self.ctx, "ensure_dirs": Mock(), "maintenance_lock": __import__("threading").Lock(),
            "read_nodes": lambda: [row], "fetch_candidates": lambda: [],
            "merge_nodes_preserve_old": lambda old, new: old, "cap_nodes_preserving_high_risk": lambda nodes: nodes,
            "get_latency_threshold_ms": lambda cfg:500, "favorite_node_ids": lambda cfg:[],
            "test_multiple_nodes": Mock(), "write_json": Mock(), "NODES_FILE": "fixture",
            "prune_failed_nodes": lambda nodes, fav_ids, keep_ids: nodes,
        }
        review = manager_subset({"refresh_test_prune_and_maybe_switch"}, context)
        review["refresh_test_prune_and_maybe_switch"]("latency threshold")
        self.assertEqual(review["active_openvpn_node_id"], "old")
        review["stop_active_openvpn"].assert_not_called()

    def test_failover_without_backup_keeps_running_tunnel_and_refills(self):
        thread = Mock()
        context = {**self.ctx, "read_nodes": lambda: [], "threading": SimpleNamespace(Thread=thread)}
        review = manager_subset({"auto_switch_node"}, context)
        review["auto_switch_node"]()
        review["stop_active_openvpn"].assert_not_called()
        thread.return_value.start.assert_called_once()


class RiskSettingsTransport(unittest.TestCase):
    def test_plain_http_toggle_requires_single_matching_origin(self):
        tree = ast.parse((ROOT / "vpngate_manager.py").read_text(encoding="utf-8"))
        handler = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Handler")
        definition = next(node for node in handler.body if getattr(node, "name", "") == "same_origin_risk_toggle")
        context = {}
        exec(compile(ast.Module(body=[definition], type_ignores=[]), "transport", "exec"), context)
        allowed = context[definition.name]
        headers = Message()
        headers["Host"] = "panel.example:8787"
        self.assertFalse(allowed(SimpleNamespace(headers=headers)))
        headers["Origin"] = "http://panel.example:8787"
        self.assertTrue(allowed(SimpleNamespace(headers=headers)))
        headers["Sec-Fetch-Site"] = "same-site"
        self.assertFalse(allowed(SimpleNamespace(headers=headers)))
        headers.replace_header("Sec-Fetch-Site", "same-origin")
        self.assertTrue(allowed(SimpleNamespace(headers=headers)))
        headers["Origin"] = "http://another.example"
        self.assertFalse(allowed(SimpleNamespace(headers=headers)))

    def test_only_loopback_and_explicit_https_proxy_allow_secret_changes(self):
        tree = ast.parse((ROOT / "vpngate_manager.py").read_text(encoding="utf-8"))
        handler = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Handler")
        definition = next(node for node in handler.body if getattr(node, "name", "") == "secure_risk_settings_transport")
        context = {"ipaddress": ipaddress, "re": re, "UI_HTTPS_PROXIES": {"192.0.2.10"}}
        exec(compile(ast.Module(body=[definition], type_ignores=[]), "transport", "exec"), context)
        allowed = context[definition.name]
        def request(peer, host, **forwarding):
            headers = Message()
            headers["Host"] = host
            for name, value in forwarding.items():
                headers[name.replace("_", "-")] = value
            return allowed(SimpleNamespace(client_address=(peer, 1234), headers=headers))
        self.assertTrue(request("::ffff:127.0.0.1", "127.0.0.1:8787", Origin="http://127.0.0.1:8787"))
        self.assertFalse(request("192.0.2.11", "localhost:8787", X_Forwarded_Proto="https"))
        self.assertFalse(request("127.0.0.1", "127.0.0.1:8787", Origin="http://example.test"))
        self.assertFalse(request("127.0.0.1", "example.test:8787"))
        self.assertTrue(request("192.0.2.10", "example.test", X_Forwarded_Proto="https"))
        self.assertFalse(request("192.0.2.10", "example.test", X_Forwarded_Proto="http"))

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
