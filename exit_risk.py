"""Evidence-based reputation for real VPN egress IPs, independent of connectivity.

Risk indices are policy severity bands, NOT fraud probabilities. No VPN/hosting
tag, latency, country or minimum pass ratio contributes to the index.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import copy
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

POLICY = "egress-abuse-v1"
MODES = ("off", "observe", "enforce")
PROVIDERS = ("proxycheck", "abuseipdb", "ipqs")
TTL_SECONDS = 900


class RiskBlockedError(RuntimeError):
    """A policy refusal, never a tunnel/connectivity failure."""


def public_ip(value):
    try:
        address = ipaddress.ip_address(str(value or ""))
        return str(address) if address.is_global and not address.is_multicast and "%" not in str(address) else ""
    except ValueError:
        return ""


def number(value, maximum=100):
    # Reject booleans, numeric strings, floats and null: API schema drift is unknown.
    return value if type(value) is int and 0 <= value <= maximum else None


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def recent(value, now, days):
    when = timestamp(value)
    return when is not None and now - days * 86400 <= when <= now


def normalize(provider, payload, ip, now):
    """Validate native schemas and keep only relevant fields, never API secrets."""
    if not isinstance(payload, dict):
        raise ValueError("invalid response")
    if provider == "proxycheck":
        if payload.get("status") not in ("ok", "warning"):
            raise ValueError("provider refused query")
        data = payload.get(ip)
        if not isinstance(data, dict):
            raise ValueError("missing target")
        flags = data.get("detections")
        if not isinstance(flags, dict) or type(flags.get("compromised")) is not bool:
            raise ValueError("missing attack detection")
        scores = [number(obj["risk"]) for obj in (data, flags) if "risk" in obj]
        if not scores or None in scores or len(set(scores)) != 1:
            raise ValueError("invalid or conflicting risk")
        score = scores[0]
        attacks = data.get("attack_history")
        if attacks is None:
            attacks = {}
        if not isinstance(attacks, dict) or any(number(v, 10**12) is None for v in attacks.values()):
            raise ValueError("invalid attack history")
        severe_types = {"denial_of_service", "vulnerability_probing", "malware", "botnet", "brute_force"}
        severe = sum(v for k, v in attacks.items() if k.lower().replace(" ", "_") in severe_types)
        observed_recently = recent(flags.get("last_seen"), now, 7)
        abuse = observed_recently and (flags["compromised"] or severe > 0)
        # v3 documents a baseline of 100 for a detected proxy. A high score
        # that exceeds the type baseline requires another look.
        baseline = max((value for tag, value in
                        (("hosting", 33), ("vpn", 50), ("tor", 75), ("scraper", 75), ("proxy", 100))
                        if flags.get(tag) is True), default=0)
        return {"native_score": score, "abuse": abuse,
                "strong": abuse and score >= 76,
                "unconfirmed": ((flags["compromised"] or severe > 0) and not observed_recently
                                or (not abuse and score >= 76 and score > baseline)),
                "tags": [k for k in ("vpn", "hosting", "proxy", "tor") if flags.get(k) is True],
                "confidence": number(flags.get("confidence")),
                "last_seen": flags.get("last_seen"), "severe_attacks": severe}
    if provider == "abuseipdb":
        data = payload.get("data")
        if not isinstance(data, dict) or public_ip(data.get("ipAddress")) != ip:
            raise ValueError("target mismatch")
        score = number(data.get("abuseConfidenceScore"))
        reports = number(data.get("totalReports"), 10**12)
        users = number(data.get("numDistinctUsers"), 10**12)
        if score is None or reports is None or users is None or users > reports:
            raise ValueError("missing report evidence")
        last = data.get("lastReportedAt")
        if reports and (timestamp(last) is None or timestamp(last) > now):
            raise ValueError("invalid report date")
        abuse = score >= 25 and users >= 2 and recent(last, now, 30)
        strong = score >= 80 and users >= 3 and recent(last, now, 7)
        return {"native_score": score, "abuse": abuse, "strong": strong,
                "unconfirmed": (score >= 80 and not strong) or (score >= 25 and not abuse),
                "reports": reports, "reporters": users, "last_reported_at": last, "tags": []}
    if provider == "ipqs":
        if payload.get("success") is not True or number(payload.get("fraud_score")) is None:
            raise ValueError("missing fraud score")
        if type(payload.get("recent_abuse")) is not bool:
            raise ValueError("missing recent abuse")
        score = payload["fraud_score"]
        return {"native_score": score, "abuse": payload["recent_abuse"],
                "strong": score >= 90 and payload["recent_abuse"],
                "unconfirmed": score >= 90 and not payload["recent_abuse"],
                "tags": [k for k in ("vpn", "proxy", "tor") if payload.get(k) is True]}
    raise ValueError("unknown provider")


def decision(ip, records, now):
    valid = {}
    reasons = []
    for name in PROVIDERS:
        record = records.get(name, {})
        if (valid_evidence(record)
                and 0 < record.get("checked_at", 0) <= now < record.get("expires_at", 0)
                and record["expires_at"] <= record["checked_at"] + TTL_SECONDS):
            valid[name] = record
        elif isinstance(record, dict) and record.get("error"):
            reasons.append(name + ": " + str(record["error"]))
    supporting = [name for name, r in valid.items() if r["data"].get("abuse") is True]
    strong = [name for name in supporting if valid[name]["data"].get("strong") is True]
    uncertain = [name for name, r in valid.items() if r["data"].get("unconfirmed") is True]
    score, level = None, "unknown"
    if len(supporting) >= 2 and strong:
        score, level = (100 if len(strong) >= 2 else 90), "high"
        reasons.insert(0, "多个独立来源证实近期滥用：" + ", ".join(supporting))
    elif strong or uncertain:
        score, level = 70, "review"
        reasons.insert(0, "单源强风险或证据时效待复核：" + ", ".join(strong + uncertain))
    elif supporting:
        score, level = 50, "review"
        reasons.insert(0, "存在滥用信号，尚需交叉核验：" + ", ".join(supporting))
    elif any(valid_evidence(r) and (r["data"]["abuse"] or r["data"]["unconfirmed"])
             for n, r in records.items() if n in PROVIDERS and n not in valid):
        level = "review"
        reasons.insert(0, "此前有风险信号，该来源需要重新核验")
    elif len(valid) >= 2:
        score, level = 10, "low"
        reasons.insert(0, "至少两个有效来源未达到滥用判定条件；不代表绝对安全")
    else:
        reasons.insert(0, "真实出口未验证或有效独立来源不足两个")
    return {"policy": POLICY, "egress_ip": ip, "level": level, "score": score,
            "auto_eligible": level != "high", "reasons": reasons, "sources": list(valid),
            "checked_at": min((r["checked_at"] for r in valid.values()), default=0),
            "expires_at": min((r["expires_at"] for r in valid.values()), default=0),
            "providers": copy.deepcopy({n: r for n, r in records.items() if n in PROVIDERS})}


def valid_evidence(record):
    if not isinstance(record, dict):
        return False
    data = record.get("data")
    return (isinstance(data, dict) and number(data.get("native_score")) is not None
            and all(type(data.get(key)) is bool for key in ("abuse", "strong", "unconfirmed"))
            and all(type(record.get(key)) in (int, float) for key in ("checked_at", "expires_at")))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RiskEngine:
    """One shared quota/cache per provider, atomic on disk, no sleeping on HTTP errors."""
    def __init__(self, cache_file, keys, *, clock=time.time, transport=None, daily_limit=900):
        self.path = Path(cache_file)
        self.keys = keys  # Callable; reads existing private key locations only on demand.
        self.clock = clock
        self.transport = transport or self._http
        self.daily_limit = min(900, max(1, daily_limit))
        self.lock = threading.RLock()
        self.inflight = set()
        self.minute = {p: deque() for p in PROVIDERS}
        self.cache_error = False
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
            if (not isinstance(state, dict) or state.get("schema") != 1
                    or not isinstance(state.get("entries"), dict)
                    or not isinstance(state.get("budgets"), dict)):
                raise ValueError("invalid cache")
            self.state = state
        except FileNotFoundError:
            self.state = {"schema": 1, "entries": {}, "budgets": {}}
        except (OSError, ValueError, TypeError):
            self.state = {"schema": 1, "entries": {}, "budgets": {}}
            self.cache_error = True  # Never reset a corrupt daily quota and query again.
        if not self.state.get("confirmed_high_initialized"):
            for records in self.state["entries"].values():
                if not isinstance(records, dict):
                    continue
                times = sorted({r["checked_at"] for r in records.values() if valid_evidence(r)})
                for checked_at in times:
                    self._record_high_decision("", records, checked_at)
            self.state["confirmed_high_initialized"] = True

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".exit-risk-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.state, stream, ensure_ascii=False, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @staticmethod
    def _http(provider, ip, key):
        if provider == "proxycheck":
            query = urllib.parse.urlencode({"key": key})
            url = "https://proxycheck.io/v3/" + urllib.parse.quote(ip, safe="") + "?" + query
            headers = {}
        elif provider == "abuseipdb":
            url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
                {"ipAddress": ip, "maxAgeInDays": 30})
            headers = {"Key": key}
        else:
            url = "https://www.ipqualityscore.com/api/json/ip/" + urllib.parse.quote(key, safe="") + "/" + urllib.parse.quote(ip, safe="") + "?strictness=0&allow_public_access_points=true"
            headers = {}
        headers.update({"Accept": "application/json", "User-Agent": "AimiliVPN-ExitRisk/1"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(urllib.request.Request(url, headers=headers), timeout=3) as response:
            raw = response.read(524289)
            if len(raw) > 524288:
                raise ValueError("oversized response")
            return json.loads(raw.decode("utf-8"))

    def _cache_key(self, ip):
        return POLICY + ":" + str(ipaddress.ip_address(ip).version) + ":" + ip

    def _reserve(self, provider, now):
        if self.cache_error:
            return "风险缓存损坏或不可写，暂停外部查询"
        day = datetime.fromtimestamp(now, timezone.utc).date().isoformat()
        budgets = self.state["budgets"]
        budget = budgets.get(provider, {})
        if not isinstance(budget, dict):
            return "风险配额记录无效"
        if not isinstance(budget.get("day", ""), str):
            return "风险配额记录无效"
        if budget.get("day", "") > day:
            return "系统时间回退，暂停查询"
        if budget.get("day") != day:
            budget = {"day": day, "used": 0, "cooldown_until": budget.get("cooldown_until", 0)}
            budgets[provider] = budget
        used, cooldown = budget.get("used"), budget.get("cooldown_until", 0)
        if type(used) is not int or used < 0 or type(cooldown) not in (int, float):
            return "风险配额记录无效"
        if cooldown > now:
            return "服务商冷却中"
        window = self.minute[provider]
        while window and window[0] <= now - 60:
            window.popleft()
        if used >= self.daily_limit or len(window) >= 8:
            return "本地风险查询预算已用尽"
        budget["used"] += 1
        window.append(now)
        try:
            self._save()  # Reserve before HTTP, preserving quota even after a crash.
        except (OSError, ValueError):
            self.cache_error = True
            return "风险缓存不可写，暂停查询"
        return ""

    def assess(self, egress_ip, *, refresh=False):
        ip = public_ip(egress_ip)
        if not ip:
            return decision("", {}, self.clock())
        with self.lock:
            cache_key = self._cache_key(ip)
            records = self.state["entries"].get(cache_key, {})
            records = records if isinstance(records, dict) else {}
            if not refresh:
                return self._result(ip, records)
            self.state["entries"][cache_key] = records
        for provider in PROVIDERS:
            now = self.clock()
            with self.lock:
                record = records.get(provider, {})
                record = record if isinstance(record, dict) else {}
                checked, expires = record.get("checked_at", 0), record.get("expires_at", 0)
                try:
                    fresh = valid_evidence(record) and 0 < checked <= now < expires <= checked + TTL_SECONDS
                    retrying = record.get("retry_at", 0) > now
                except TypeError:
                    fresh, retrying = False, False
                token = (cache_key, provider)
                if fresh or retrying or token in self.inflight or len(self.inflight) >= 2:
                    continue
                try:
                    key = self.keys(provider)
                except Exception:
                    key = ""
                if not key:
                    # Missing optional providers do not turn a valid two-source decision unknown.
                    records[provider] = {**record, "error": "未配置 API key", "retry_at": now + 60}
                    continue
                refused = self._reserve(provider, now)
                if refused:
                    records[provider] = {**record, "error": refused, "retry_at": now + 60}
                    continue
                self.inflight.add(token)
            try:
                payload = self.transport(provider, ip, key)
                normalized = normalize(provider, payload, ip, self.clock())
                checked = self.clock()
                outcome = {"data": normalized, "checked_at": checked, "expires_at": checked + TTL_SECONDS}
            except Exception as exc:
                # Exception messages/URLs may contain API keys. Never retain or return them.
                wait = 60
                error = "查询失败：" + type(exc).__name__
                if isinstance(exc, urllib.error.HTTPError):
                    error = "HTTP " + str(exc.code)
                    if exc.code == 429:
                        wait = 3600
                        retry = exc.headers.get("Retry-After", "") if exc.headers else ""
                        try:
                            wait = max(60, min(86400, int(retry)))
                        except (ValueError, TypeError):
                            when = timestamp(retry)
                            if when is None:
                                from email.utils import parsedate_to_datetime
                                try:
                                    when = parsedate_to_datetime(retry).timestamp()
                                except (ValueError, TypeError, OverflowError):
                                    when = None
                            if when is not None:
                                wait = max(60, min(86400, int(when - self.clock())))
                    elif exc.code in (401, 403):
                        wait = 3600
                outcome = {**record, "error": error, "retry_at": self.clock() + wait}
                with self.lock:
                    if isinstance(exc, urllib.error.HTTPError) and exc.code in (401, 403, 429):
                        budget = self.state["budgets"][provider]
                        budget["cooldown_until"] = max(budget["cooldown_until"], self.clock() + wait)
            with self.lock:
                records[provider] = outcome
                self._record_high_decision(ip, records, self.clock())
                try:
                    self._save()
                except (OSError, ValueError):
                    self.cache_error = True
                finally:
                    self.inflight.discard(token)
        with self.lock:
            return self._result(ip, records)

    def _result(self, ip, records):
        result = decision(ip, records, self.clock())
        confirmed = records.get("confirmed_high")
        if (result["level"] != "high" and isinstance(confirmed, dict)
                and confirmed.get("score") in (90, 100)):
            result.update(level="high", score=confirmed["score"], auto_eligible=False,
                          checked_at=confirmed.get("checked_at", 0), sources=confirmed.get("sources", []))
            result["reasons"].insert(0, "此前已确认高风险，等待两家有效来源复核为低风险")
        if self.cache_error:
            result["reasons"].append("风险缓存异常")
        return result

    def _record_high_decision(self, ip, records, now):
        result = decision(ip, records, now)
        if result["level"] == "high":
            records["confirmed_high"] = {field: result[field] for field in ("score", "checked_at", "sources")}
        elif result["level"] == "low":
            records.pop("confirmed_high", None)

    def status(self):
        with self.lock:
            return {"policy": POLICY, "cache_error": self.cache_error,
                    "budgets": copy.deepcopy(self.state["budgets"]),
                    "inflight": len(self.inflight)}
