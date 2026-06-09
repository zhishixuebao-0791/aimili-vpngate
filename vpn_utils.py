#!/usr/bin/env python3
from __future__ import annotations
import json
import os
import random
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import threading
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
IP_CACHE_FILE = DATA_DIR / "ip_cache.json"
PURITY_CACHE_FILE = DATA_DIR / "purity_cache.json"

ip_cache_lock = threading.RLock()
purity_cache_lock = threading.RLock()


def _env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        return default
    if min_value is not None and value < min_value:
        return default
    if max_value is not None and value > max_value:
        return default
    return value


def _split_env_keys(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[\s,;]+", value or "") if item.strip()]


def _load_api_port_keys() -> tuple[list[str], list[str]]:
    try:
        text = API_KEYS_FILE.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return [], []

    proxy_section, abuse_section = text, ""
    marker = "AbuseIPDB"
    if marker in text:
        proxy_section, abuse_section = text.split(marker, 1)

    proxy_keys = re.findall(r"\b[a-z0-9]{5,8}(?:-[a-z0-9]{5,8}){3}\b", proxy_section, flags=re.I)
    abuse_keys = re.findall(r"\b[a-f0-9]{64,128}\b", abuse_section, flags=re.I)
    return list(dict.fromkeys(proxy_keys)), list(dict.fromkeys(abuse_keys))


def get_proxycheck_keys() -> list[str]:
    keys = _split_env_keys(PROXYCHECK_API_KEY)
    file_proxy_keys, _ = _load_api_port_keys()
    return list(dict.fromkeys(keys + file_proxy_keys))


def get_abuseipdb_keys() -> list[str]:
    keys = _split_env_keys(ABUSEIPDB_API_KEY)
    _, file_abuse_keys = _load_api_port_keys()
    return list(dict.fromkeys(keys + file_abuse_keys))


def _choose_key(keys: list[str]) -> str | None:
    return random.choice(keys) if keys else None


PURITY_SCORE_THRESHOLD = _env_int("PURITY_SCORE_THRESHOLD", 60, 0, 100)
PURITY_MIN_PASS_RATIO = _env_int("PURITY_MIN_PASS_RATIO", 99, 0, 100)
PURITY_CACHE_TTL_SECONDS = _env_int("PURITY_CACHE_TTL_SECONDS", 7 * 24 * 3600, 60)
PURITY_ENABLE_PROXYCHECK = os.environ.get("PURITY_ENABLE_PROXYCHECK", "").strip().lower() in ("1", "true", "yes", "on")
PROXYCHECK_API_KEY = os.environ.get("PROXYCHECK_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
API_KEYS_FILE = Path(os.environ.get("API_KEYS_FILE", ROOT_DIR / "API_Port.txt")).resolve()
PURITY_CACHE_VERSION = 3

COUNTRY_TRANSLATIONS = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡",
}

def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def parse_proxy_endpoint(value: str, default_port: int) -> tuple[str | None, int | None]:
    value = value.strip()
    if not value:
        return None, None
    if "://" in value:
        parsed = urllib.parse.urlsplit(value)
        if parsed.hostname:
            return parsed.hostname, parsed.port or default_port
        return None, None
    if value.startswith("["):
        host_part, sep, rest = value.partition("]")
        host = host_part.lstrip("[")
        port = default_port
        if sep and rest.startswith(":"):
            port = _safe_int(rest[1:], default_port)
        return host or None, port
    if value.count(":") == 1:
        host, _, port_text = value.rpartition(":")
        return host or None, _safe_int(port_text, default_port)
    return value, default_port

def _proxy_config_from_env(env_name: str, forced_type: str | None = None) -> tuple[str, str, int, str | None, str | None] | None:
    val = os.environ.get(env_name)
    if not val:
        return None
    if "://" in val:
        try:
            parsed = urllib.parse.urlsplit(val)
        except Exception:
            return None
        if not parsed.hostname:
            return None
        ptype = forced_type or ("socks" if parsed.scheme.startswith("socks") else "http")
        username = urllib.parse.unquote(parsed.username) if parsed.username is not None else None
        password = urllib.parse.unquote(parsed.password or "") if parsed.username is not None else None
        return ptype, parsed.hostname, parsed.port or 10808, username, password
    host, port = parse_proxy_endpoint(val, 10808)
    if host and port:
        return forced_type or "http", host, port, None, None
    return None

def get_upstream_proxy_config() -> tuple[str | None, str | None, int | None, str | None, str | None]:
    for env_name, forced_type in [
        ("OPENVPN_UPSTREAM_SOCKS", "socks"),
        ("OPENVPN_UPSTREAM_HTTP", "http"),
        ("http_proxy", None),
        ("HTTP_PROXY", None),
        ("https_proxy", None),
        ("HTTPS_PROXY", None),
    ]:
        cfg = _proxy_config_from_env(env_name, forced_type)
        if cfg:
            ptype, host, port, username, password = cfg
            return ptype, host, port, username, password
    return None, None, None, None, None

def get_upstream_proxy() -> tuple[str | None, str | None, int | None]:
    """
    Returns (proxy_type, host, port) from environment variables.
    proxy_type is 'socks' or 'http'.
    """
    ptype, host, port, _, _ = get_upstream_proxy_config()
    return ptype, host, port

def get_upstream_proxy_auth() -> tuple[str | None, str | None]:
    """
    Returns optional (username, password) for the configured upstream proxy.
    Supports credentials embedded in proxy URLs and explicit env vars.
    """
    _, _, _, username, password = get_upstream_proxy_config()
    if username is not None:
        return username, password or ""

    user = os.environ.get("OPENVPN_UPSTREAM_USER") or os.environ.get("OPENVPN_UPSTREAM_USERNAME")
    password = os.environ.get("OPENVPN_UPSTREAM_PASS") or os.environ.get("OPENVPN_UPSTREAM_PASSWORD")
    if user is not None:
        return user, password or ""
    return None, None

def is_config_tcp(config_text: str) -> bool:
    try:
        for line in config_text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            parts = line.split()
            if parts[0].lower() == "proto" and len(parts) >= 2:
                if "tcp" in parts[1].lower():
                    return True
            elif parts[0].lower() == "remote" and len(parts) >= 4:
                if "tcp" in parts[3].lower():
                    return True
    except Exception:
        pass
    return False

def parse_remote(config_text: str, fallback_ip: str = "") -> tuple[str, int, str]:
    remote_host = fallback_ip
    remote_port = 0
    proto = "unknown"
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        if parts[0].lower() == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
        elif parts[0].lower() == "remote" and len(parts) >= 3:
            remote_host = parts[1]
            remote_port = int(parts[2]) if parts[2].isdigit() else 0
            if len(parts) >= 4:
                proto = parts[3].lower()
    return remote_host, remote_port, proto

def get_physical_interface() -> str | None:
    try:
        res = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            routes = []
            for line in res.stdout.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    try:
                        dev = parts[parts.index("dev") + 1]
                        metric = 0
                        if "metric" in parts:
                            metric = int(parts[parts.index("metric") + 1])
                        gw = parts[parts.index("via") + 1] if "via" in parts else ""
                        routes.append((gw, dev, metric))
                    except (ValueError, IndexError):
                        continue
            if routes:
                routes.sort(key=lambda x: x[2])
                for gw, dev, metric in routes:
                    if not dev.startswith(("tun", "tap", "wg", "ppp")):
                        return dev
                return routes[0][1]
    except Exception:
        pass
    return None

def tcp_latency_ms(host: str, port: int, dev: str | None = None) -> int:
    started = time.time()
    # Auto-detect address family based on host address
    af = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(5)
        if dev:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode("utf-8"))
            except OSError:
                pass
        s.connect((host, port))
        return max(1, int((time.time() - started) * 1000))
    except OSError:
        return 0
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

def ping_latency_ms(host: str, port: int, fallback_ping: int = 0) -> int:
    dev = get_physical_interface()
    # 1. Try ping with interface binding
    if dev:
        try:
            cmd = ["ping", "-c", "1", "-W", "2", "-I", dev, host]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2
            )
            if res.returncode == 0:
                match = re.search(r"time=([\d.]+)\s*ms", res.stdout)
                if match:
                    val = int(float(match.group(1)))
                    if val > 0:
                        return val
        except Exception:
            pass

    # 2. Try ping without interface binding
    try:
        cmd = ["ping", "-c", "1", "-W", "2", host]
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2
        )
        if res.returncode == 0:
            match = re.search(r"time=([\d.]+)\s*ms", res.stdout)
            if match:
                val = int(float(match.group(1)))
                if val > 0:
                    return val
    except Exception:
        pass

    # 3. Try TCP latency check
    tcp_val = tcp_latency_ms(host, port, dev)
    if tcp_val > 0:
        return tcp_val

    # 4. Fallback
    if fallback_ping > 0:
        return fallback_ping
    return 0

def check_and_fix_dns() -> None:
    """
    Checks if DNS resolution is broken.
    If names fail but direct IP connections work, appends public DNS nameservers to /etc/resolv.conf.
    Supports both IPv4 and IPv6 network environments.
    """
    try:
        socket.getaddrinfo("www.vpngate.net", 443)
        return
    except (socket.gaierror, OSError):
        pass

    network_ok = False
    # Test IPv4 DNS servers first, then IPv6
    dns_targets = [
        ("8.8.8.8", 53, socket.AF_INET),
        ("1.1.1.1", 53, socket.AF_INET),
        ("2001:4860:4860::8888", 53, socket.AF_INET6),
        ("2606:4700:4700::1111", 53, socket.AF_INET6),
    ]
    for ip, port, af in dns_targets:
        s = None
        try:
            s = socket.socket(af, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect((ip, port))
            network_ok = True
            break
        except Exception:
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    if not network_ok:
        return

    resolv_file = Path("/etc/resolv.conf")
    if resolv_file.exists():
        try:
            content = resolv_file.read_text(encoding="utf-8", errors="replace")
            if "nameserver 1.1.1.1" not in content and "nameserver 8.8.8.8" not in content:
                print("[dns_heal] Resolving names failed, but IP network is OK. Appending public DNS to /etc/resolv.conf...", flush=True)
                with open("/etc/resolv.conf", "a", encoding="utf-8") as f:
                    f.write("\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n")
        except Exception as e:
            print(f"[dns_heal] Failed to write DNS fallback: {e}", flush=True)

def load_ip_cache() -> dict[str, dict[str, Any]]:
    with ip_cache_lock:
        try:
            if IP_CACHE_FILE.exists():
                return json.loads(IP_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

def save_ip_cache(cache: dict[str, dict[str, Any]]) -> None:
    with ip_cache_lock:
        try:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            IP_CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

def enrich_ip_info(nodes: list[dict[str, Any]]) -> None:
    # 1. Read cache thread-safely
    with ip_cache_lock:
        cache = load_ip_cache()

    ips_to_query = []
    now = time.time()

    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if not ip:
            continue
        if ip in cache and now - cache[ip].get("cached_at", 0) < 7 * 24 * 3600:
            cached = cache[ip]
            node["owner"] = cached.get("owner", "")
            node["asn"] = cached.get("asn", "")
            node["as_name"] = cached.get("as_name", "")
            node["location"] = cached.get("location", "")
            node["ip_type"] = cached.get("ip_type", "")
            node["quality"] = cached.get("quality", "")
        else:
            if ip not in ips_to_query:
                ips_to_query.append(ip)

    if not ips_to_query:
        return

    # 2. Perform HTTP query outside lock
    new_entries = {}
    chunk_size = 100
    for i in range(0, len(ips_to_query), chunk_size):
        chunk = ips_to_query[i : i + chunk_size]
        payload = json.dumps(chunk).encode("utf-8")
        request = urllib.request.Request(
            "http://ip-api.com/batch?lang=zh-CN&fields=status,message,query,country,regionName,city,isp,org,as,asname,proxy,hosting,mobile",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "vpngate-manager/2.2"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
                if not isinstance(data, list):
                    continue
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    if item.get("status") != "success":
                        continue
                    query_ip = item.get("query")
                    if not query_ip:
                        continue

                    ip_type = "residential"
                    if item.get("mobile"):
                        ip_type = "mobile"
                    elif item.get("hosting") or item.get("proxy"):
                        ip_type = "hosting"

                    quality = "normal"
                    if item.get("proxy"):
                        quality = "proxy"
                    elif item.get("hosting"):
                        quality = "datacenter"
                    elif item.get("mobile"):
                        quality = "mobile"

                    loc = " ".join(part for part in [item.get("country"), item.get("regionName"), item.get("city")] if part)

                    new_entries[query_ip] = {
                        "owner": item.get("org") or item.get("isp") or "",
                        "asn": item.get("as") or "",
                        "as_name": item.get("asname") or "",
                        "location": loc,
                        "ip_type": ip_type,
                        "quality": quality,
                        "cached_at": now,
                    }
        except Exception as e:
            print(f"[enrich_ip_info] Query failed: {e}", flush=True)

    if not new_entries:
        return

    # 3. Save cache thread-safely (reload & update to avoid overwrite of concurrent queries)
    with ip_cache_lock:
        cache = load_ip_cache()
        cache.update(new_entries)
        save_ip_cache(cache)

    # 4. Enrich nodes with newly queried info
    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if ip in new_entries:
            cached = new_entries[ip]
            node["owner"] = cached.get("owner", "")
            node["asn"] = cached.get("asn", "")
            node["as_name"] = cached.get("as_name", "")
            node["location"] = cached.get("location", "")
            node["ip_type"] = cached.get("ip_type", "")
            node["quality"] = cached.get("quality", "")


def load_purity_cache() -> dict[str, dict[str, Any]]:
    with purity_cache_lock:
        try:
            if PURITY_CACHE_FILE.exists():
                data = json.loads(PURITY_CACHE_FILE.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
        except Exception:
            pass
        return {}


def save_purity_cache(cache: dict[str, dict[str, Any]]) -> None:
    with purity_cache_lock:
        try:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            PURITY_CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass


def _clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def _purity_grade(score: int) -> str:
    if score < 20:
        return "clean"
    if score <= 60:
        return "neutral"
    if score < 85:
        return "risky"
    return "blocked"


def _contains_any(text: str, keywords: tuple[str, ...]) -> str | None:
    lower = text.lower()
    for keyword in keywords:
        if keyword in lower:
            return keyword
    return None


def _query_proxycheck(ip: str) -> dict[str, Any] | None:
    keys = get_proxycheck_keys()
    if not (PURITY_ENABLE_PROXYCHECK or keys):
        return None
    attempts = keys[:]
    random.shuffle(attempts)
    if not attempts:
        attempts = [""]
    last_error = ""
    for key in attempts:
        params = {"p": "0", "tag": "0"}
        if key:
            params["key"] = key
        query = urllib.parse.urlencode(params)
        request = urllib.request.Request(
            f"https://proxycheck.io/v3/{urllib.parse.quote(ip)}?{query}",
            headers={"User-Agent": "vpngate-manager/2.3"},
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
            if not isinstance(data, dict) or data.get("status") not in ("ok", "warning"):
                last_error = str(data.get("message") if isinstance(data, dict) else data)
                continue
            result = data.get(ip)
            if not isinstance(result, dict):
                last_error = "proxycheck result missing"
                continue
            return result
        except Exception as exc:
            last_error = str(exc)
            continue
    return {"_error": last_error or "proxycheck failed"}


def _query_abuseipdb(ip: str) -> dict[str, Any] | None:
    keys = get_abuseipdb_keys()
    if not keys:
        return None
    attempts = keys[:]
    random.shuffle(attempts)
    last_error = ""
    for key in attempts:
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
        request = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?{query}",
            headers={
                "Accept": "application/json",
                "Key": key,
                "User-Agent": "vpngate-manager/2.3",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
            result = data.get("data") if isinstance(data, dict) else None
            if isinstance(result, dict):
                return result
            last_error = "abuseipdb result missing"
        except Exception as exc:
            last_error = str(exc)
            continue
    return {"_error": last_error or "abuseipdb failed"}


def _local_purity_score(node: dict[str, Any]) -> tuple[int, list[str]]:
    score = 6
    reasons: list[str] = ["local baseline"]
    ip_type = str(node.get("ip_type") or "").lower()
    quality = str(node.get("quality") or "").lower()

    if ip_type == "mobile":
        score -= 3
        reasons.append("mobile ISP")
    elif ip_type == "residential":
        reasons.append("residential/ISP")
    elif ip_type == "hosting":
        score += 22
        reasons.append("hosting network")

    if quality == "proxy":
        score += 38
        reasons.append("ip-api proxy flag")
    elif quality == "datacenter":
        score += 26
        reasons.append("datacenter quality")
    elif quality == "mobile":
        score -= 2
        reasons.append("mobile quality")

    owner_text = " ".join(
        str(node.get(key) or "")
        for key in ("owner", "as_name", "asn", "remote_host")
    )
    hard_keywords = (
        "tor exit", "cloudflare", "akamai", "cdn", "hosting",
        "host ", "datacenter", "data center", "colo", "server", "vps",
        "digitalocean", "linode", "vultr", "ovh", "hetzner", "contabo",
        "amazon", "aws", "google cloud", "microsoft", "azure", "oracle",
        "alibaba", "tencent", "leaseweb", "m247", "choopa", "hivelocity",
    )
    medium_keywords = (
        "cloud", "internet services", "communications", "network services",
        "backbone", "carrier", "transit", "broadband network",
    )
    hit = _contains_any(owner_text, hard_keywords)
    if hit:
        score += 18
        reasons.append(f"suspicious operator keyword: {hit}")
    else:
        hit = _contains_any(owner_text, medium_keywords)
        if hit:
            score += 4
            reasons.append(f"operator keyword: {hit}")

    sessions = _safe_int(node.get("sessions"), 0)
    if sessions >= 300:
        score += 6
        reasons.append("high VPNGate session sharing")
    elif sessions >= 100:
        score += 3
        reasons.append("medium VPNGate session sharing")

    latency = _safe_int(node.get("latency_ms"), 0)
    if latency >= 1000:
        score += 6
        reasons.append("very high latency")
    elif latency >= 500:
        score += 2
        reasons.append("high latency")

    return _clamp_score(score), reasons


def assess_ip_purity(node: dict[str, Any]) -> dict[str, Any]:
    ip = node.get("ip") or node.get("remote_host")
    if not ip:
        return {
            "purity_score": 100,
            "purity_grade": "blocked",
            "purity_reasons": ["missing IP"],
            "purity_sources": ["local-rules"],
            "purity_checked_at": time.time(),
            "purity_raw_score": 100,
            "purity_hard_block": True,
            "cache_version": PURITY_CACHE_VERSION,
        }

    now = time.time()
    cache = load_purity_cache()
    cached = cache.get(str(ip))
    if (
        isinstance(cached, dict)
        and cached.get("cache_version") == PURITY_CACHE_VERSION
        and now - float(cached.get("purity_checked_at", 0) or 0) < PURITY_CACHE_TTL_SECONDS
    ):
        return dict(cached)

    score, reasons = _local_purity_score(node)
    sources = ["local-rules", "ip-api"]
    hard_block = False

    proxycheck = _query_proxycheck(str(ip))
    if proxycheck is not None:
        sources.append("proxycheck")
        if proxycheck.get("_error"):
            reasons.append(f"proxycheck error: {proxycheck['_error']}")
        else:
            detections = proxycheck.get("detections")
            if isinstance(detections, dict):
                confidence = _safe_int(detections.get("confidence"), 0)
                if confidence:
                    if confidence >= 95:
                        score = max(score, 70)
                    elif confidence >= 85:
                        score = max(score, 55)
                    elif confidence >= 70:
                        score = max(score, 42)
                    elif confidence >= 50:
                        score = max(score, 30)
                    reasons.append(f"proxycheck confidence {confidence}")
                for key in ("anonymous", "proxy", "vpn", "tor", "hosting", "scraper"):
                    if detections.get(key) is True:
                        reasons.append(f"proxycheck {key}")
                        if key in ("anonymous", "tor"):
                            score = max(score, 90)
                            hard_block = True
                        elif key in ("proxy", "vpn"):
                            score = max(score, 52 if confidence < 95 else 68)
                        elif key == "hosting":
                            score = max(score, 38 if confidence < 95 else 55)
                        elif key == "scraper":
                            score = max(score, 45)

    abuse = _query_abuseipdb(str(ip))
    if abuse is not None:
        sources.append("abuseipdb")
        if abuse.get("_error"):
            reasons.append(f"abuseipdb error: {abuse['_error']}")
        else:
            abuse_score = _safe_int(abuse.get("abuseConfidenceScore"), 0)
            if abuse_score:
                if abuse_score >= 90:
                    score = max(score, 92)
                elif abuse_score >= 75:
                    score = max(score, 82)
                elif abuse_score >= 50:
                    score = max(score, 65)
                elif abuse_score >= 25:
                    score = max(score, 42)
                else:
                    score = max(score, abuse_score)
                reasons.append(f"abuseipdb score {abuse_score}")
                if abuse_score >= 90:
                    hard_block = True

    score = _clamp_score(score)
    result = {
        "purity_score": score,
        "purity_raw_score": score,
        "purity_grade": _purity_grade(score),
        "purity_reasons": reasons[:12],
        "purity_sources": sources,
        "purity_checked_at": now,
        "purity_hard_block": hard_block,
        "cache_version": PURITY_CACHE_VERSION,
    }

    cache[str(ip)] = result
    save_purity_cache(cache)
    return result


def assess_nodes_purity(nodes: list[dict[str, Any]], threshold: int | None = None) -> None:
    effective_threshold = PURITY_SCORE_THRESHOLD if threshold is None else _clamp_score(threshold)
    scored_nodes: list[dict[str, Any]] = []
    for node in nodes:
        result = assess_ip_purity(node)
        node.update(result)
        scored_nodes.append(node)

    if scored_nodes and PURITY_MIN_PASS_RATIO > 0:
        min_pass_count = (len(scored_nodes) * PURITY_MIN_PASS_RATIO + 99) // 100
        current_pass_count = len([
            node for node in scored_nodes
            if _safe_int(node.get("purity_score"), 100) <= effective_threshold
        ])
        if current_pass_count < min_pass_count:
            calibratable = [
                node for node in scored_nodes
                if not node.get("purity_hard_block")
            ]
            calibratable.sort(key=lambda item: (
                _safe_int(item.get("purity_raw_score"), _safe_int(item.get("purity_score"), 100)),
                _safe_int(item.get("latency_ms"), 999999),
            ))
            for node in calibratable:
                if current_pass_count >= min_pass_count:
                    break
                if _safe_int(node.get("purity_score"), 100) > effective_threshold:
                    node["purity_score"] = effective_threshold
                    node["purity_grade"] = _purity_grade(_safe_int(node.get("purity_score"), 0))
                    reasons = node.get("purity_reasons")
                    if not isinstance(reasons, list):
                        reasons = []
                    reasons.append(f"batch pass-floor calibration {PURITY_MIN_PASS_RATIO}%")
                    node["purity_reasons"] = reasons[:12]
                    current_pass_count += 1

    for node in scored_nodes:
        if _safe_int(node.get("purity_score"), 100) > effective_threshold:
            node["probe_status"] = "unavailable"
            reason_text = "; ".join(str(item) for item in node.get("purity_reasons", [])[:4])
            node["probe_message"] = f"Purity score {node['purity_score']} > {effective_threshold}; {reason_text}"


def diagnose_api_failure(api_url: str = "https://www.vpngate.net/api/iphone/") -> tuple[int, str]:
    try:
        parsed = urllib.parse.urlsplit(api_url)
        domain = parsed.hostname or "www.vpngate.net"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except Exception:
        domain = "www.vpngate.net"
        port = 443

    # 1. 检查本地 DNS 解析是否完全失效
    dns_ok = False
    for test_domain in ["api.ipify.org", "dns.google", "one.one.one.one"]:
        try:
            socket.getaddrinfo(test_domain, 443)
            dns_ok = True
            break
        except Exception:
            pass

    # 2. 检查是否能解析 API 域名
    api_dns_ok = False
    api_addr = None  # (af, ip) tuple
    try:
        results = socket.getaddrinfo(domain, port, 0, socket.SOCK_STREAM)
        if results:
            api_dns_ok = True
            api_addr = (results[0][0], results[0][4][0])  # (address_family, ip)
    except Exception:
        pass

    if not api_dns_ok:
        if not dns_ok:
            return 1006, "[ERR_LOCAL_DNS_BROKEN] 本地 DNS 解析器完全失效。原因: 无法解析任何外部域名，请检查系统 DNS 配置(如 /etc/resolv.conf)及外网连接。"
        else:
            return 1007, f"[ERR_API_DOMAIN_BLOCKED] 解析 API 域名 {domain} 失败。原因: 其他外部域名解析正常，确认该官方 API 域名遭 DNS 污染或本地防火墙拦截。"

    # 3. 检查 TCP 连接 API 域名
    api_conn_ok = False
    api_af, api_ip = api_addr
    s = None
    try:
        s = socket.socket(api_af, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((api_ip, port))
        api_conn_ok = True
    except Exception:
        pass
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    if not api_conn_ok:
        ext_conn_ok = False
        # Test both IPv4 and IPv6 external connectivity
        ext_targets = [
            ("8.8.8.8", 53, socket.AF_INET),
            ("1.1.1.1", 53, socket.AF_INET),
            ("2001:4860:4860::8888", 53, socket.AF_INET6),
            ("2606:4700:4700::1111", 53, socket.AF_INET6),
        ]
        for test_ip, test_port, af in ext_targets:
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((test_ip, test_port))
                ext_conn_ok = True
                break
            except Exception:
                pass
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
        if ext_conn_ok:
            return 1008, f"[ERR_API_IP_BLOCKED_OR_DOWN] 连接 API 服务器失败。原因: 外部网络连接通畅，但无法建立到 {domain} ({api_ip}:{port}) 的连接，可能是由于官方 IP 遭 GFW/防火墙 IP 阻断封锁或官方服务器宕机。"
        else:
            return 1009, "[ERR_VPS_OUTBOUND_BLOCKED] VPS 完全断网。原因: 任何外部测试连接均失败（IPv4 和 IPv6 均不可达），请检查 VPS 网卡和宿主机连接。"

    return 1010, f"[ERR_API_TLS_INTERFERENCE] HTTPS/TLS 握手被干扰。原因: 可以建立 TCP 连接但请求超时，通常是由于防火墙通过 SNI 阻断了 TLS 握手流。"


def diagnose_openvpn_failure(log_tail: list[str]) -> tuple[int, str]:
    joined_log = "\n".join(log_tail).lower()
    
    if "command not found" in joined_log or "no such file or directory" in joined_log:
        return 2001, "[ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统中未安装 OpenVPN 软件，或环境变量 PATH 不正确。"
    
    if "cannot allocate tun" in joined_log or "cannot open tun/tap dev" in joined_log or "cannot ioctl" in joined_log or "cannot allocate tun/tap dev" in joined_log or "dev/net/tun" in joined_log or "operation not permitted" in joined_log:
        return 2009, "[ERR_OVPN_TUN_NOT_AVAILABLE] 无法创建或访问虚拟网卡 (TUN 设备)。原因: ① 缺少 tun 内核模块；② 当前运行在容器(如 LXC/OpenVZ/Docker)中且宿主机未授予网卡创建权限/未启用 CAP_NET_ADMIN 权限；③ `/dev/net/tun` 文件权限不足；④ 未使用 root 用户运行。如果是 Docker，请添加 `--cap-add=NET_ADMIN` 和 `--device=/dev/net/tun` 参数重新运行。"
        
    if "auth_failed" in joined_log or "authentication failed" in joined_log:
        return 2005, "[ERR_OVPN_AUTH_FAILED] OpenVPN 身份验证失败。原因: 节点配置的用户名密码不正确，或者该免费节点已失效/限制连接。"
        
    if "cannot resolve host address" in joined_log or "resolve: host name" in joined_log:
        return 2003, "[ERR_OVPN_DNS_RESOLVE] 节点服务器域名解析失败。原因: 本地 DNS 解析异常，或者节点域名已失效。"
        
    if "tls error: tls key negotiation failed" in joined_log or "tls error: tls handshake failed" in joined_log:
        return 2006, "[ERR_OVPN_TLS_BLOCKED] TLS 握手超时/失败。原因: 可能是由于物理链路极差导致握手包丢失，或者受 VPS 防火墙规则/网络监管(如 GFW)深度包检测拦截了 OpenVPN 协议流量。"
        
    if "connection timed out" in joined_log or "timeout" in joined_log:
        return 2004, "[ERR_OVPN_NODE_UNREACHABLE] 节点连接超时。原因: 远程节点已关机、VPS 本身出站流量被本地防火墙拦截，或者目的 IP:端口遭 ISP/GFW 屏蔽拦截。"
    if "connection refused" in joined_log:
        return 2004, "[ERR_OVPN_NODE_UNREACHABLE] 节点连接被拒绝。原因: 目的服务器未在指定端口监听，或者主动拒绝了连接。"
        
    if "permission denied" in joined_log or "root privileges" in joined_log or "need root" in joined_log:
        return 2002, "[ERR_OVPN_PERMISSION_DENIED] 权限不足。原因: 运行 OpenVPN 需要 root 权限，请确保以 root 用户身份或使用 sudo 运行本系统。"

    if "options error" in joined_log:
        return 2007, "[ERR_OVPN_ROUTE_NOPULL] 获取/解析 PUSH 配置参数冲突。原因: 某些推送选项在当前版本的客户端或配置环境中不可用。"
        
    return 2010, "[ERR_OVPN_UNKNOWN] OpenVPN 其他运行时异常。原因: 连接握手期间发生其他协议错误，详细信息请查看日志尾部。"


def diagnose_local_obstructions(proxy_port: int = 7928, host: str = "127.0.0.1") -> tuple[int, str] | None:
    import sys
    # 1. 检查端口是否被占用
    is_ipv6 = ":" in host or host == ""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, proxy_port))
    except OSError as e:
        if e.errno == 98 or e.errno == 10048 or "already in use" in str(e).lower() or "not supported" in str(e).lower():
            if e.errno in (98, 10048) or "already in use" in str(e).lower():
                return 3005, f"[ERR_PORT_IN_USE] 本地代理端口 {proxy_port} 被占用。原因: 其他进程已抢占该端口，导致本系统代理网关启动失败。请运行 'lsof -i :{proxy_port}' 检查占用进程。"
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    if sys.platform.startswith("linux"):
        # 1.5 检查 /dev/net/tun 虚拟网卡接口是否可用与具备权限
        tun_path = Path("/dev/net/tun")
        if not tun_path.exists():
            return 3009, "[ERR_TUN_DEV_NOT_FOUND] 系统中不存在虚拟网卡设备节点 `/dev/net/tun`。原因: 内核未加载 tun 模块，或宿主机禁用了 TUN 设备创建权限。请尝试运行 `modprobe tun` 加载模块，或在 VPS 控制面板中开启 TUN 支持。"
        try:
            with open(tun_path, "r+b") as f:
                pass
        except PermissionError:
            return 3010, "[ERR_TUN_PERMISSION_DENIED] 无权访问虚拟网卡设备节点 `/dev/net/tun`。原因: 当前用户对该节点没有读写权限。请确保使用 root 权限运行，或者运行 `chmod 666 /dev/net/tun` 赋予读写权限。"
        except Exception:
            pass

        # 2. 检查 IPv4 转发是否开启
        ip_forward_path = Path("/proc/sys/net/ipv4/ip_forward")
        if ip_forward_path.exists():
            try:
                val = ip_forward_path.read_text(encoding="utf-8").strip()
                if val == "0":
                    return 3001, "[ERR_ROUTE_FORWARD_DISABLED] 系统未开启 IPv4 流量转发。原因: /proc/sys/net/ipv4/ip_forward 值为 0，会导致 VPN 隧道内的流量无法进行正常的网络转发。"
            except Exception:
                pass

        # 3. 检查本机防火墙策略
        # 检查 UFW
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and "Status: active" in res.stdout:
                if str(proxy_port) not in res.stdout:
                    return 3007, f"[ERR_FIREWALL_BLOCKING_FORWARD] 本机 UFW 防火墙处于激活状态，但未在规则中允许代理端口 {proxy_port}。这可能会阻断客户端的连接。"
        except Exception:
            pass

        # 检查 Firewalld
        try:
            res = subprocess.run(["systemctl", "is-active", "firewalld"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout.strip() == "active":
                return 3007, "[ERR_FIREWALL_BLOCKING_FORWARD] 本机 Firewalld 防火墙正在运行。请确保您已将代理端口及 VPN 网卡(tun0)加入信任区域以避免流量被拦截。"
        except Exception:
            pass

        # 检查 iptables 默认策略
        try:
            res = subprocess.run(["iptables", "-S"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                lines = res.stdout.splitlines()
                has_output_drop = False
                has_forward_drop = False
                for line in lines:
                    if line.startswith("-P OUTPUT DROP"):
                        has_output_drop = True
                    elif line.startswith("-P FORWARD DROP"):
                        has_forward_drop = True
                
                if has_output_drop:
                    return 3007, "[ERR_FIREWALL_BLOCKING_FORWARD] 本机 iptables OUTPUT 默认策略被设为 DROP。这会导致 VPS 出站数据包被静默丢弃，从而彻底阻碍网关运行。"
                if has_forward_drop:
                    return 3007, "[ERR_FIREWALL_BLOCKING_FORWARD] 本机 iptables FORWARD 默认策略被设为 DROP。且未配置相应的转发规则，这通常会拦截 VPN 网卡的流量穿透。"
        except Exception:
            pass

        # 4. 检查系统反向路径过滤 (rp_filter) 设置
        rp_all_path = Path("/proc/sys/net/ipv4/conf/all/rp_filter")
        if rp_all_path.exists():
            try:
                val = rp_all_path.read_text(encoding="utf-8").strip()
                if val == "1":
                    return 3008, "[ERR_ROUTE_RP_FILTER_STRICT] 系统启用了严格的反向路径过滤(rp_filter=1)。原因: 在启用策略路由时，严格的路径过滤会导致通过虚拟网卡 tun0 的回包被内核静默丢弃，导致连接超时。请将 net.ipv4.conf.all.rp_filter 设置为 2 或 0。"
            except Exception:
                pass

    return None
