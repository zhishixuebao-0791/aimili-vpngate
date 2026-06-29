#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import math
import os
import queue
import re
import select
import shlex
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid
import traceback

# Prefer IPv4 resolution to avoid slow AAAA DNS timeouts (e.g. in WSL),
# but fall back to system default (IPv6) if IPv4 resolution fails.
# This ensures pure-IPv6 VPS (with NAT64/clatd) can still function.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        # Try IPv4 first for speed; fall back to system default (allows IPv6/NAT64)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server

def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value

def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return default
    return parsed

API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1260, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1260, 1)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 300, 1)
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 1)
NODE_PROBE_TIMEOUT_SECONDS = env_int("NODE_PROBE_TIMEOUT_SECONDS", 5, 1)
NODE_TIMEOUT_LATENCY_MS = -1
LATENCY_CHECK_INTERVAL_CHOICES_MINUTES = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60]
LATENCY_THRESHOLD_CHOICES_MS = [200, 300, 400, 500, 600, 700, 800, 900, 1000]
DEFAULT_LATENCY_CHECK_INTERVAL_MINUTES = 30
DEFAULT_LATENCY_THRESHOLD_MS = 500
FIXED_REGION_LATENCY_CHECK_SECONDS = DEFAULT_LATENCY_CHECK_INTERVAL_MINUTES * 60
FIXED_REGION_LATENCY_FAILOVER_MS = DEFAULT_LATENCY_THRESHOLD_MS
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = env_int("LOCAL_PROXY_PORT", 7928, 1, 65535)
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = env_int("UI_PORT", 8787, 1, 65535)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)
NODE_LATENCY_LIMIT_MS = DEFAULT_LATENCY_THRESHOLD_MS
PURITY_DISPLAY_FIXED_SCORE = 60

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"
MANUAL_BLACKLIST_FILE = DATA_DIR / "manual_blacklist.json"
LOGIN_REFRESH_REQUIRED_FILE = DATA_DIR / "login_refresh_required.json"
VERSION_NOTICE_FILE = DATA_DIR / "version_notice.json"
NODE_ACTIVITY_LOG_FILE = DATA_DIR / "node_activity.log"
UPDATE_REPO_OWNER = os.environ.get("AIMILI_UPDATE_REPO_OWNER", "zhishixuebao-0791")
UPDATE_REPO_NAME = os.environ.get("AIMILI_UPDATE_REPO_NAME", "aimili-vpngate")

lock = threading.RLock()
maintenance_lock = threading.Lock()
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = True
last_active_ping_time = 0.0
last_active_latency = 0

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
server_start_time = time.time()

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    try:
        NODE_ACTIVITY_LOG_FILE.touch(exist_ok=True)
    except OSError:
        pass
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def mark_login_refresh_required(reason: str = "manual marker") -> None:
    ensure_dirs()
    payload = {"reason": reason, "created_at": time.time()}
    write_json(LOGIN_REFRESH_REQUIRED_FILE, payload)

def consume_login_refresh_required() -> dict[str, Any] | None:
    if not LOGIN_REFRESH_REQUIRED_FILE.exists():
        return None
    try:
        payload = read_json(LOGIN_REFRESH_REQUIRED_FILE, {})
    except Exception:
        payload = {}
    try:
        LOGIN_REFRESH_REQUIRED_FILE.unlink()
    except OSError:
        pass
    return payload if isinstance(payload, dict) else {}

def git_output(args: list[str], timeout: int = 3) -> str:
    try:
        res = subprocess.run(
            ["git", *args],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return ""

def current_git_commit() -> str:
    return git_output(["rev-parse", "HEAD"])

def current_git_tag() -> str:
    return git_output(["describe", "--tags", "--exact-match"])

def github_api_get(path: str, timeout: int = 3) -> Any:
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AimiliVPN-Version-Check",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))

def latest_github_version_ref() -> tuple[str, str, str]:
    try:
        release = github_api_get(f"/repos/{UPDATE_REPO_OWNER}/{UPDATE_REPO_NAME}/releases/latest")
        tag_name = str(release.get("tag_name") or "")
        if tag_name:
            commit = github_api_get(f"/repos/{UPDATE_REPO_OWNER}/{UPDATE_REPO_NAME}/commits/{urllib.parse.quote(tag_name, safe='')}")
            sha = str(commit.get("sha") or "")
            if sha:
                return tag_name, sha, "release"
    except Exception:
        pass

    tags = github_api_get(f"/repos/{UPDATE_REPO_OWNER}/{UPDATE_REPO_NAME}/tags?per_page=1")
    if not isinstance(tags, list) or not tags:
        return "", "", ""
    latest = tags[0]
    return (
        str(latest.get("name") or ""),
        str((latest.get("commit") or {}).get("sha") or ""),
        "tag",
    )

def check_version_notice() -> dict[str, Any]:
    today = time.strftime("%Y-%m-%d", time.localtime())
    current_commit = current_git_commit()
    current_tag = current_git_tag()
    result = {
        "ok": True,
        "update_available": False,
        "show_notice": False,
        "current_commit": current_commit,
        "current_tag": current_tag,
        "latest_tag": "",
        "latest_commit": "",
        "command": "ml update",
        "message": "",
    }

    if not current_commit:
        result["ok"] = False
        result["message"] = "当前目录不是可识别的 Git 版本，跳过版本检测"
        return result

    try:
        latest_tag, latest_commit, version_source = latest_github_version_ref()
        result["version_source"] = version_source
        if not latest_tag or not latest_commit:
            result["message"] = "远程仓库尚未发布 tag，跳过版本提示"
            return result
        result["latest_tag"] = latest_tag
        result["latest_commit"] = latest_commit

        update_available = latest_commit != current_commit
        try:
            compare = github_api_get(
                f"/repos/{UPDATE_REPO_OWNER}/{UPDATE_REPO_NAME}/compare/{current_commit}...{latest_commit}"
            )
            status = str(compare.get("status") or "")
            result["compare_status"] = status
            update_available = status in ("behind", "diverged")
        except Exception as exc:
            result["compare_error"] = str(exc)

        result["update_available"] = update_available
        if not update_available:
            result["message"] = "当前版本已包含最新 tag"
            return result

        notice = read_json(VERSION_NOTICE_FILE, {})
        last_shown_date = str(notice.get("last_shown_date") or "")
        last_tag = str(notice.get("latest_tag") or "")
        if last_shown_date != today or last_tag != latest_tag:
            write_json(VERSION_NOTICE_FILE, {
                "last_shown_date": today,
                "latest_tag": latest_tag,
                "latest_commit": latest_commit,
                "shown_at": time.time(),
            })
            result["show_notice"] = True
        result["message"] = "有新的版本发布，可在终端中输入 ml update 命令更新"
        return result
    except Exception as exc:
        result["ok"] = False
        result["message"] = f"版本检测失败: {exc}"
        return result

def trigger_login_refresh_if_needed() -> bool:
    global is_connecting
    if is_connecting or maintenance_lock.locked():
        return False
    marker = consume_login_refresh_required()
    if marker is None and cached_nodes():
        return False
    reason = str((marker or {}).get("reason") or "first login refresh")
    is_connecting = True
    set_state(is_connecting=True, last_check_message=f"首次登录触发节点拉取与测速排序: {reason}")
    threading.Thread(
        target=refresh_test_prune_and_maybe_switch,
        args=(f"login-triggered refresh: {reason}", "auto"),
        daemon=True,
    ).start()
    return True

def upstream_proxy_auth_file() -> str | None:
    username, password = vpn_utils.get_upstream_proxy_auth()
    if username is None:
        return None
    try:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        UPSTREAM_PROXY_AUTH_FILE.write_text(f"{username}\n{password or ''}\n", encoding="utf-8")
        try:
            UPSTREAM_PROXY_AUTH_FILE.chmod(0o600)
        except OSError:
            pass
        return str(UPSTREAM_PROXY_AUTH_FILE)
    except Exception as exc:
        print(f"[上游代理认证] 写入认证文件失败: {exc}", flush=True)
        return None

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

def save_ui_config(ui_cfg: dict[str, Any]) -> None:
    auth_file = DATA_DIR / "ui_auth.json"
    with lock:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")

def normalize_ip_value(value: Any) -> str:
    ip = str(value or "").strip()
    if not ip:
        return ""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return ip
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return ip.lower()
    except OSError:
        return ""

def node_ip_value(node: dict[str, Any]) -> str:
    return normalize_ip_value(node.get("ip")) or normalize_ip_value(node.get("remote_host"))

def node_ip_values(node: dict[str, Any] | None) -> set[str]:
    if not isinstance(node, dict):
        return set()
    values: set[str] = set()
    for key in ("ip", "remote_host", "egress_ip", "proxy_ip", "blacklisted_ip"):
        ip = normalize_ip_value(node.get(key))
        if ip:
            values.add(ip)
    return values

def node_egress_ip_values(node: dict[str, Any] | None) -> set[str]:
    if not isinstance(node, dict):
        return set()
    values: set[str] = set()
    for key in ("egress_ip", "proxy_ip"):
        ip = normalize_ip_value(node.get(key))
        if ip:
            values.add(ip)
    return values

def manual_blacklist_match_for_node(node: dict[str, Any] | None, manual: dict[str, dict[str, Any]] | None = None) -> str:
    if not isinstance(node, dict):
        return ""
    manual = manual if manual is not None else load_manual_blacklist()
    for ip in node_egress_ip_values(node):
        if ip in manual:
            return ip
    return ""

def load_manual_blacklist() -> dict[str, dict[str, Any]]:
    raw = read_json(MANUAL_BLACKLIST_FILE, {})
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    changed = False
    for key, entry in raw.items():
        ip = normalize_ip_value(key)
        if not ip and isinstance(entry, dict):
            ip = normalize_ip_value(entry.get("ip"))
        if not ip:
            changed = True
            continue
        if not isinstance(entry, dict):
            entry = {"ip": ip}
            changed = True
        entry["ip"] = ip
        entry.setdefault("reason", "manual blacklist")
        entry.setdefault("added_at", time.time())
        cleaned[ip] = entry
    if changed:
        write_json(MANUAL_BLACKLIST_FILE, cleaned)
    return cleaned

def save_manual_blacklist(data: dict[str, dict[str, Any]]) -> None:
    normalized: dict[str, dict[str, Any]] = {}
    for key, entry in data.items():
        ip = normalize_ip_value(key)
        if not ip:
            continue
        entry = entry if isinstance(entry, dict) else {}
        normalized[ip] = {
            "ip": ip,
            "reason": str(entry.get("reason") or "manual blacklist"),
            "added_at": float(entry.get("added_at", time.time()) or time.time()),
        }
    write_json(MANUAL_BLACKLIST_FILE, normalized)

def manual_blacklist_entries(search: str = "") -> list[dict[str, Any]]:
    query = normalize_ip_value(search) or str(search or "").strip()
    entries = list(load_manual_blacklist().values())
    if query:
        entries = [entry for entry in entries if query in str(entry.get("ip", ""))]
    return sorted(entries, key=lambda item: str(item.get("ip", "")))

def apply_manual_blacklist_to_node(node: dict[str, Any], manual: dict[str, dict[str, Any]] | None = None) -> bool:
    manual = manual if manual is not None else load_manual_blacklist()
    ip = manual_blacklist_match_for_node(node, manual)
    if ip:
        node["manual_blacklisted"] = True
        node["probe_status"] = "unavailable"
        node["probe_message"] = f"Manual blacklist: {ip}"
        node["blacklisted_ip"] = ip
        return True
    was_manual = bool(node.get("manual_blacklisted")) or str(node.get("probe_message") or "").startswith("Manual blacklist")
    node["manual_blacklisted"] = False
    node.pop("blacklisted_ip", None)
    if was_manual and node_passes_current_latency(node):
        node["probe_status"] = "available"
        node["probe_message"] = "Manual blacklist entry IP ignored; egress IP is not blacklisted"
    return False

def apply_manual_blacklist_to_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    manual = load_manual_blacklist()
    for node in nodes:
        apply_manual_blacklist_to_node(node, manual)
    return nodes

def apply_manual_blacklist_to_storage() -> None:
    with lock:
        nodes = read_json(NODES_FILE, [])
        if not isinstance(nodes, list):
            return
        manual = load_manual_blacklist()
        changed = False
        for node in nodes:
            if not isinstance(node, dict):
                continue
            before = (
                node.get("manual_blacklisted"),
                node.get("blacklisted_ip"),
                node.get("probe_status"),
                node.get("probe_message"),
            )
            apply_manual_blacklist_to_node(node, manual)
            after = (
                node.get("manual_blacklisted"),
                node.get("blacklisted_ip"),
                node.get("probe_status"),
                node.get("probe_message"),
            )
            if before != after:
                changed = True
        if changed:
            write_json(NODES_FILE, nodes)

def add_manual_blacklist_ip(ip: str, reason: str = "manual blacklist") -> dict[str, Any]:
    normalized = normalize_ip_value(ip)
    if not normalized:
        raise ValueError("请输入有效 IP")
    data = load_manual_blacklist()
    data[normalized] = {
        "ip": normalized,
        "reason": reason or "manual blacklist",
        "added_at": time.time(),
    }
    save_manual_blacklist(data)
    apply_manual_blacklist_to_storage()
    cleanup_favorite_node_ids()
    disconnected = disconnect_active_if_manual_blacklisted(normalized)
    if disconnected:
        trigger_egress_blacklist_failover(f"Manual blacklist active egress IP: {normalized}", exclude_ids=set())
        return data[normalized]
    return data[normalized]

def resolve_node_egress_ip_for_blacklist(node_id: str) -> str:
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")

    nodes = read_nodes()
    node = next((item for item in nodes if isinstance(item, dict) and str(item.get("id") or "") == node_id), None)
    if not node:
        raise ValueError(f"Node not found: {node_id}")

    if node_id == active_openvpn_node_id and active_openvpn_running():
        state_ip = normalize_ip_value(read_json(STATE_FILE, {}).get("proxy_ip"))
        if state_ip:
            return state_ip
        health = check_proxy_health()
        health_ip = normalize_ip_value(health.get("ip"))
        if health.get("ok") and health_ip:
            return health_ip

    for ip in sorted(node_egress_ip_values(node)):
        if ip:
            return ip

    tested = test_node_by_id(node_id)
    for ip in sorted(node_egress_ip_values(tested)):
        if ip:
            return ip

    raise ValueError("未检测到该节点真实出口 IP，请先点击检测后再拉黑")

def add_manual_blacklist_node_egress(node_id: str, reason: str = "manual blacklist") -> dict[str, Any]:
    egress_ip = resolve_node_egress_ip_for_blacklist(node_id)
    entry = add_manual_blacklist_ip(egress_ip, reason or f"node {node_id} egress blacklist")
    return {"node_id": str(node_id or "").strip(), "ip": egress_ip, "entry": entry}

def remove_manual_blacklist_ip(ip: str) -> dict[str, Any]:
    normalized = normalize_ip_value(ip)
    if not normalized:
        raise ValueError("请输入有效 IP")
    data = load_manual_blacklist()
    existed = normalized in data
    if existed:
        data.pop(normalized, None)
        save_manual_blacklist(data)
    removed_node_ids: set[str] = set()
    restored_node_ids: set[str] = set()
    latency_threshold = get_latency_threshold_ms()
    with lock:
        nodes = read_json(NODES_FILE, [])
        if isinstance(nodes, list):
            for node in nodes:
                if not isinstance(node, dict) or normalized not in node_egress_ip_values(node):
                    continue
                latency = parse_int(node.get("latency_ms"))
                if latency > 0 and latency <= latency_threshold:
                    node["manual_blacklisted"] = False
                    node.pop("blacklisted_ip", None)
                    node["probe_status"] = "available"
                    node["probe_message"] = f"Manual blacklist removed: {normalized}"
                    restored_node_ids.add(str(node.get("id") or ""))
                else:
                    removed_node_ids.add(str(node.get("id") or ""))
            if removed_node_ids:
                nodes = [n for n in nodes if not (isinstance(n, dict) and str(n.get("id") or "") in removed_node_ids)]
            write_json(NODES_FILE, sort_all_nodes([n for n in nodes if isinstance(n, dict)]))
    return {
        "existed": existed,
        "removed_node_ids": sorted(removed_node_ids),
        "restored_node_ids": sorted(restored_node_ids),
    }

def disconnect_active_if_manual_blacklisted(ip: str) -> bool:
    global active_openvpn_node_id
    if not ip or not active_openvpn_node_id:
        return False
    nodes = read_json(NODES_FILE, [])
    if not isinstance(nodes, list):
        return False
    active_node = next((node for node in nodes if isinstance(node, dict) and node.get("id") == active_openvpn_node_id), None)
    state_proxy_ip = normalize_ip_value(read_json(STATE_FILE, {}).get("proxy_ip"))
    active_egress_ips = node_egress_ip_values(active_node)
    if (active_node and ip in active_egress_ips) or (state_proxy_ip and state_proxy_ip == ip):
        old_active_id = active_openvpn_node_id
        stop_active_openvpn()
        active_openvpn_node_id = ""
        if active_node:
            active_node["active"] = False
            active_node["egress_ip"] = state_proxy_ip or active_node.get("egress_ip", "")
            apply_manual_blacklist_to_node(active_node)
        write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", active_node_latency="无活动连接", last_check_message=f"手动拉黑当前节点 IP: {ip}")
        return bool(old_active_id)
    return False

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": UI_HOST,
            "port": UI_PORT,
            "proxy_port": LOCAL_PROXY_PORT,
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_fail_fallback": True,
            "latency_check_interval_minutes": DEFAULT_LATENCY_CHECK_INTERVAL_MINUTES,
            "latency_threshold_ms": DEFAULT_LATENCY_THRESHOLD_MS,
            "latency_policy_updated_at": 0,
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback", "latency_check_interval_minutes", "latency_threshold_ms", "latency_policy_updated_at"]:
                    if key not in data:
                        updated = True
                if (
                    data.get("routing_mode") == "fixed_ip"
                    and not data.get("fixed_node_id")
                    and not data.get("default_route_auto_migrated")
                ):
                    config["routing_mode"] = "auto"
                    config["default_route_auto_migrated"] = True
                    updated = True
            except Exception:
                pass
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True

        normalized_port = bounded_int(config.get("port"), UI_PORT, 1, 65535)
        if normalized_port != config.get("port"):
            config["port"] = normalized_port
            updated = True

        normalized_proxy_port = bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535)
        if normalized_proxy_port == normalized_port:
            fallback_proxy_port = LOCAL_PROXY_PORT if LOCAL_PROXY_PORT != normalized_port else 7928
            if fallback_proxy_port == normalized_port:
                fallback_proxy_port = 7929
            normalized_proxy_port = fallback_proxy_port
        if normalized_proxy_port != config.get("proxy_port"):
            config["proxy_port"] = normalized_proxy_port
            updated = True

        normalized_latency_interval = parse_int(config.get("latency_check_interval_minutes"))
        if normalized_latency_interval not in LATENCY_CHECK_INTERVAL_CHOICES_MINUTES:
            normalized_latency_interval = DEFAULT_LATENCY_CHECK_INTERVAL_MINUTES
        if normalized_latency_interval != config.get("latency_check_interval_minutes"):
            config["latency_check_interval_minutes"] = normalized_latency_interval
            updated = True

        normalized_latency_threshold = parse_int(config.get("latency_threshold_ms"))
        if normalized_latency_threshold not in LATENCY_THRESHOLD_CHOICES_MS:
            normalized_latency_threshold = DEFAULT_LATENCY_THRESHOLD_MS
        if normalized_latency_threshold != config.get("latency_threshold_ms"):
            config["latency_threshold_ms"] = normalized_latency_threshold
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
                
        return config

def get_latency_threshold_ms(ui_cfg: dict[str, Any] | None = None) -> int:
    cfg = ui_cfg if ui_cfg is not None else load_ui_config()
    value = parse_int(cfg.get("latency_threshold_ms"))
    return value if value in LATENCY_THRESHOLD_CHOICES_MS else DEFAULT_LATENCY_THRESHOLD_MS

def get_latency_check_interval_minutes(ui_cfg: dict[str, Any] | None = None) -> int:
    cfg = ui_cfg if ui_cfg is not None else load_ui_config()
    value = parse_int(cfg.get("latency_check_interval_minutes"))
    return value if value in LATENCY_CHECK_INTERVAL_CHOICES_MINUTES else DEFAULT_LATENCY_CHECK_INTERVAL_MINUTES

def get_latency_check_interval_seconds(ui_cfg: dict[str, Any] | None = None) -> int:
    return get_latency_check_interval_minutes(ui_cfg) * 60

def wait_latency_check_interval() -> dict[str, Any]:
    cfg = load_ui_config()
    policy_seen = float(cfg.get("latency_policy_updated_at") or 0)
    start_time = time.time()
    while True:
        interval = get_latency_check_interval_seconds(cfg)
        target_time = start_time + interval
        now = time.time()
        if now >= target_time:
            return load_ui_config()
        time.sleep(min(5.0, max(0.5, target_time - now)))
        latest = load_ui_config()
        latest_policy = float(latest.get("latency_policy_updated_at") or 0)
        if latest_policy > policy_seen:
            cfg = latest
            policy_seen = latest_policy
            start_time = latest_policy

# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = bounded_int(_init_cfg["proxy_port"], LOCAL_PROXY_PORT, 1024, 65535)
    if "port" in _init_cfg:
        UI_PORT = bounded_int(_init_cfg["port"], UI_PORT, 1, 65535)
    if "host" in _init_cfg:
        UI_HOST = _init_cfg["host"]
except Exception:
    pass

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

_last_cleanup_time = 0.0

def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    with lock:
        if now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        with lock:
                            path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def describe_node_for_activity(node: dict[str, Any] | None) -> str:
    if not isinstance(node, dict):
        return "node=<unknown>"
    node_id = str(node.get("id") or "")
    ip = node_ip_value(node) or str(node.get("ip") or node.get("remote_host") or "")
    port = str(node.get("remote_port") or node.get("port") or "")
    country = str(node.get("country") or node.get("country_long") or "")
    latency = str(node.get("latency_ms") or node.get("ping") or "")
    parts = []
    if node_id:
        parts.append(f"id={node_id}")
    if ip:
        parts.append(f"ip={ip}")
    if port:
        parts.append(f"port={port}")
    if country:
        parts.append(f"country={country}")
    if latency:
        parts.append(f"latency={latency}ms")
    return " ".join(parts) if parts else "node=<unknown>"

def log_node_activity(event: str, message: str, node: dict[str, Any] | None = None, exc: BaseException | None = None) -> None:
    try:
        ensure_dirs()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"[{timestamp}] [{event}] {message}"
        node_desc = describe_node_for_activity(node)
        if node_desc != "node=<unknown>":
            line += f" | {node_desc}"
        if exc is not None:
            line += f" | exception={type(exc).__name__}: {exc}"
        with lock:
            with open(NODE_ACTIVITY_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                if exc is not None:
                    f.write(traceback.format_exc() + "\n")
        if event in ("ERROR", "CRASH", "STALL", "SWITCH_FAILED"):
            log_to_json("ERROR", "NodeActivity", line)
        elif event in ("WARNING", "SLOW_ACTIVE", "BLACKLIST_DISCONNECT"):
            log_to_json("WARNING", "NodeActivity", line)
        else:
            log_to_json("INFO", "NodeActivity", line)
    except Exception as log_exc:
        print(f"[NodeActivityLog Error] {log_exc}", flush=True)

def install_crash_log_hooks() -> None:
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        try:
            ensure_dirs()
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            with lock:
                with open(NODE_ACTIVITY_LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"[{timestamp}] [CRASH] Unhandled exception: {exc_type.__name__}: {exc_value}\n")
                    traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)
            log_to_json("ERROR", "Crash", f"Unhandled exception: {exc_type.__name__}: {exc_value}")
        finally:
            sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = handle_exception

    if hasattr(threading, "excepthook"):
        def handle_thread_exception(args):
            try:
                ensure_dirs()
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                with lock:
                    with open(NODE_ACTIVITY_LOG_FILE, "a", encoding="utf-8") as f:
                        f.write(f"[{timestamp}] [CRASH] Thread {args.thread.name if args.thread else '<unknown>'} crashed: {args.exc_type.__name__}: {args.exc_value}\n")
                        traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback, file=f)
                log_to_json("ERROR", "Crash", f"Thread crashed: {args.exc_type.__name__}: {args.exc_value}")
            except Exception as hook_exc:
                print(f"[CrashHook Error] {hook_exc}", flush=True)
        threading.excepthook = handle_thread_exception

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def read_nodes() -> list[dict[str, Any]]:
    raw = read_json(NODES_FILE, [])
    if not isinstance(raw, list):
        return []
    return apply_manual_blacklist_to_nodes([item for item in raw if isinstance(item, dict)])

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    _proxy_display = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:{LOCAL_PROXY_PORT}"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    state["manual_blacklisted_nodes"] = len(load_manual_blacklist())
    
    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    try:
        cleanup_favorite_node_ids()
        ui_cfg = load_ui_config()
    except Exception:
        pass
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["fav_fail_fallback"] = ui_cfg.get("fav_fail_fallback", True)
    state["latency_check_interval_minutes"] = get_latency_check_interval_minutes(ui_cfg)
    state["latency_threshold_ms"] = get_latency_threshold_ms(ui_cfg)
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def clear_active_connection_state(message: str) -> None:
    global active_openvpn_process, active_openvpn_node_id
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(
        active_openvpn_node_id="",
        is_connecting=False,
        active_node_latency="无活动连接",
        last_check_message=message,
    )

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def proxy_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def recv_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected EOF while reading proxy response")
        data += chunk
    return data

def read_http_response_head(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("Proxy response header too large")
    if b"\r\n\r\n" not in data:
        raise RuntimeError("Incomplete HTTP proxy response header")
    return data

def socks5_address_bytes(host: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 4, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("SOCKS5 target host name is too long")
    return 3, bytes([len(host_bytes)]) + host_bytes

def read_socks5_connect_reply(sock: socket.socket) -> None:
    header = recv_exact_from_socket(sock, 4)
    if header[0] != 5:
        raise RuntimeError("Invalid SOCKS5 reply version")
    atyp = header[3]
    if atyp == 1:
        recv_exact_from_socket(sock, 4)
    elif atyp == 3:
        domain_len = recv_exact_from_socket(sock, 1)[0]
        recv_exact_from_socket(sock, domain_len)
    elif atyp == 4:
        recv_exact_from_socket(sock, 16)
    else:
        raise RuntimeError(f"Invalid SOCKS5 reply address type: {atyp}")
    recv_exact_from_socket(sock, 2)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 connection request rejected, code={header[1]}")

def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True) -> str:
    import socket
    import ssl
    import urllib.parse

    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(12)
        s.connect((phost, pport))
        proxy_user, proxy_pass = vpn_utils.get_upstream_proxy_auth()
        if ptype == "socks":
            # SOCKS5 Handshake
            if proxy_user is not None:
                s.sendall(b"\x05\x02\x00\x02")
            else:
                s.sendall(b"\x05\x01\x00")
            resp = recv_exact_from_socket(s, 2)
            if len(resp) < 2 or resp[0] != 5:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            if resp[1] == 2:
                if proxy_user is None:
                    raise RuntimeError("SOCKS5 proxy requires username/password authentication")
                user_bytes = proxy_user.encode("utf-8")
                pass_bytes = (proxy_pass or "").encode("utf-8")
                if len(user_bytes) > 255 or len(pass_bytes) > 255:
                    raise RuntimeError("SOCKS5 proxy credentials are too long")
                s.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
                auth_resp = recv_exact_from_socket(s, 2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            elif resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication method unsupported")
            # SOCKS5 Connect
            atyp, addr_bytes = socks5_address_bytes(domain)
            req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            read_socks5_connect_reply(s)
            # If HTTPS, wrap socket with SSL
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else: # http proxy
            if is_https:
                # HTTP CONNECT tunnel
                authority = format_host_port(domain, port)
                auth_header = proxy_basic_auth_header(proxy_user, proxy_pass or "") if proxy_user is not None else ""
                req_str = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = read_http_response_head(s)
                status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                status_parts = status_line.split()
                status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
                if status_code != 200:
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {status_line}")
                # Wrap socket with SSL
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                # Direct HTTP request through proxy: request URI must be absolute
                pass

        # Send HTTP GET request
        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path
            
        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"{proxy_basic_auth_header(proxy_user, proxy_pass or '') if ptype == 'http' and not is_https and proxy_user is not None else ''}"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        # Read response
        response_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > 10 * 1024 * 1024: # max 10MB safety guard
                break
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # Parse HTTP response
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")
    
    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    # Check for HTTP status code
    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    # Handle chunked transfer encoding
    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL
    
    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 监测到上游代理 ({ptype}://{phost}:{pport})，尝试通过代理获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试使用直连/默认系统代理...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    now = time.time()
    raw = read_json(BLACKLIST_FILE, {})
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    changed = False
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            changed = True
            continue
        until = float(entry.get("until", 0) or 0)
        if until and until > now:
            cleaned[str(key)] = entry
        else:
            changed = True
    if changed:
        write_json(BLACKLIST_FILE, cleaned)
    return cleaned

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    node_id = str(node.get("id") or "").strip()
    if not node_id:
        return
    blacklist = load_blacklist()
    now = time.time()
    blacklist[node_id] = {
        "id": node_id,
        "ip": node.get("ip") or node.get("remote_host") or "",
        "country": node.get("country", ""),
        "reason": message,
        "marked_at": now,
        "until": now + INVALID_BACKOFF_SECONDS,
    }
    write_json(BLACKLIST_FILE, blacklist)

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "purity_score": PURITY_DISPLAY_FIXED_SCORE,
        "purity_raw_score": PURITY_DISPLAY_FIXED_SCORE,
        "purity_grade": "disabled",
        "purity_reasons": ["purity filter disabled"],
        "purity_sources": ["disabled"],
        "purity_checked_at": time.time(),
        "purity_hard_block": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips = set()
    
    # 检查本地是否有节点缓存，以确定最大重试尝试次数
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 2
    
    # 尝试 URLs 队列: 1. HTTPS(验证证书) 2. HTTPS(不验证证书) 3. HTTP
    attempts_targets = [
        (API_URL, True),
        (API_URL, False)
    ]
    if API_URL.startswith("https://"):
        attempts_targets.append((API_URL.replace("https://", "http://"), True))
        
    log_to_json("INFO", "Main", "开始拉取官方 API 节点列表...")
    
    last_err = None
    for url, verify_ssl in attempts_targets:
        for i in range(max_attempts):
            if i > 0:
                time.sleep(1.5)
            try:
                msg = f"尝试拉取 {url} (SSL验证: {verify_ssl}, 第 {i+1} 次尝试)..."
                print(f"[fetch_candidates] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                api_text = fetch_api_text(url, verify_ssl)
                rows = parse_vpngate_rows(api_text)
                for row in rows[:MAX_SCAN_ROWS]:
                    ip = row.get("IP", "")
                    if not ip or ip in seen_ips:
                        continue
                    encoded = row.get("OpenVPN_ConfigData_Base64", "")
                    if not encoded:
                        continue
                    try:
                        config_text = decode_config(encoded)
                        node = row_to_node(row, config_text)
                        apply_manual_blacklist_to_node(node)
                    except Exception as row_exc:
                        print(f"[fetch_candidates] 跳过损坏的节点配置记录: {row_exc}", flush=True)
                        log_to_json("WARNING", "Main", f"跳过损坏的节点配置记录: {row_exc}")
                        continue
                    entry = blacklist.get(node["id"])
                    if entry and float(entry.get("until", 0) or 0) > time.time():
                        continue
                    candidates.append(node)
                    seen_ips.add(ip)
                if candidates:
                    break
            except Exception as e:
                last_err = e
                print(f"[fetch_candidates] 拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}", flush=True)
                log_to_json("WARNING", "Main", f"拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}")
        if candidates:
            break
            
    if not candidates:
        err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
        full_err_msg = f"获取官方 API 节点最终失败: {last_err} | 诊断结果: {diag_msg}"
        print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
        log_to_json("ERROR", "Main", f"[错误代码 {err_code}] {full_err_msg}")
        set_state(
            last_fetch_status="error",
            last_fetch_error_code=err_code,
            last_fetch_message=diag_msg
        )
        if last_err:
            raise RuntimeError(diag_msg) from last_err
        else:
            raise RuntimeError(diag_msg)
                
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=f"Fetched {len(candidates)} unique candidates across multiple attempts.",
        blacklisted_nodes=len(blacklist),
    )
    log_to_json("INFO", "Main", f"成功获取官方 API 节点，共 {len(candidates)} 个候选节点")
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_nodes()

_openvpn_version = None

def split_openvpn_command() -> list[str]:
    try:
        return shlex.split(OPENVPN_CMD, posix=(os.name != "nt")) or ["openvpn"]
    except ValueError as exc:
        raise RuntimeError(f"OPENVPN_CMD 配置无法解析: {exc}") from exc

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = split_openvpn_command()
        res = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = split_openvpn_command()
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])
    
    if os.path.exists("/etc/ssl/certs"):
        command.extend(["--capath", "/etc/ssl/certs"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            auth_file = upstream_proxy_auth_file()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
    except Exception:
        pass
        
    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None, wait_timeout: float = 8) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=wait_timeout)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        own_markers = [
            str(DATA_DIR),
            str(CONFIG_DIR),
            str(AUTH_FILE),
            str(UPSTREAM_PROXY_AUTH_FILE),
        ]
        killed_pids: list[int] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            return
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            pid = int(proc_dir.name)
            if pid == os.getpid():
                continue
            try:
                raw = (proc_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if not raw:
                continue
            args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
            if not args:
                continue
            cmdline = " ".join(args)
            executable = Path(args[0]).name.lower()
            if "openvpn" not in executable and "openvpn" not in cmdline.lower():
                continue
            if any(marker and marker in cmdline for marker in own_markers):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_pids.append(pid)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    print(f"[Cleanup] No permission to terminate OpenVPN PID {pid}", flush=True)
        if killed_pids:
            time.sleep(0.5)
            for pid in killed_pids:
                try:
                    raw = (proc_root / str(pid) / "cmdline").read_bytes()
                    cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
                    if any(marker and marker in cmdline for marker in own_markers):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except (OSError, PermissionError):
                    pass
            print(f"[Cleanup] Terminated AimiliVPN OpenVPN processes: {killed_pids}", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0", keep_process: bool | None = None) -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]
    openvpn_logs: list[str] = []

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                openvpn_logs.append(line_str)
                lines.put(line_str)
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line_str}", flush=True)
                    level = "INFO"
                    line_lower = line_str.lower()
                    if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
                        level = "ERROR"
                    elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
                        level = "WARNING"
                    log_to_json(level, "VPN", f"[OpenVPN] {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-50:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    # Bulk write accumulated startup logs
    for line_str in openvpn_logs:
        level = "INFO"
        line_lower = line_str.lower()
        if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
            level = "ERROR"
        elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
            level = "WARNING"
        log_to_json(level, "VPN", f"[OpenVPN] {line_str}")

    timed_out = is_probe_timeout_message(message)
    if not ok:
        if timed_out:
            message = f"[错误代码 1002] OpenVPN timeout after {limit}s. (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
        else:
            err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
            message = f"[错误代码 {err_code}] {diag_msg} (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
    startup_done[0] = True
    should_keep_process = keep_alive if keep_process is None else keep_process
    if not should_keep_process or not ok:
        stop_process(process, wait_timeout=1 if timed_out else 8)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0") -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    
    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", "[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由")

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        cleanup_policy_routing()
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if node:
                config_to_delete = node.get("config_file")
                
        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        kill_existing_openvpn_processes()
        
        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def mark_purity_disabled(node: dict[str, Any]) -> None:
    node["purity_score"] = PURITY_DISPLAY_FIXED_SCORE
    node["purity_raw_score"] = PURITY_DISPLAY_FIXED_SCORE
    node["purity_grade"] = "disabled"
    node["purity_reasons"] = ["purity filter disabled"]
    node["purity_sources"] = ["disabled"]
    node["purity_checked_at"] = time.time()
    node["purity_hard_block"] = False

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        nodes,
        key=lambda n: (
            parse_int(n.get("latency_ms")) if parse_int(n.get("latency_ms")) > 0 else 999999,
            0 if n.get("active") else 1,
            0 if n.get("probe_status") == "available" else 1,
            -parse_int(n.get("score")),
            str(n.get("id") or ""),
        )
    )

def merge_nodes_preserve_old(old_nodes: list[dict[str, Any]], new_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    old_map = {str(n.get("id") or ""): n for n in old_nodes if isinstance(n, dict)}
    for node in old_nodes:
        node_id = str(node.get("id") or "")
        if node_id and node_id not in seen_ids:
            merged.append(node)
            seen_ids.add(node_id)
    for node in new_nodes:
        node_id = str(node.get("id") or "")
        if not node_id or node_id in seen_ids:
            continue
        old = old_map.get(node_id)
        if old:
            preserved = node.copy()
            for key in (
                "probe_status",
                "probe_message",
                "probed_at",
                "latency_ms",
                "owner",
                "asn",
                "as_name",
                "location",
                "ip_type",
                "quality",
                "egress_ip",
                "manual_blacklisted",
                "blacklisted_ip",
            ):
                if key in old:
                    preserved[key] = old[key]
            merged.append(preserved)
        else:
            merged.append(node)
        seen_ids.add(node_id)
    return merged

def prune_failed_nodes(nodes: list[dict[str, Any]], favorite_ids: set[str], keep_ids: set[str] | None = None) -> list[dict[str, Any]]:
    keep_ids = keep_ids or set()
    manual = load_manual_blacklist()
    threshold = get_latency_threshold_ms()
    kept: list[dict[str, Any]] = []
    for node in nodes:
        node_id = str(node.get("id") or "")
        latency = parse_int(node.get("latency_ms"))
        protected = node_id in favorite_ids or node_id in keep_ids
        if protected:
            kept.append(node)
            continue
        if latency == NODE_TIMEOUT_LATENCY_MS or latency > threshold:
            continue
        egress_blacklisted = bool(manual_blacklist_match_for_node(node, manual) or node.get("manual_blacklisted"))
        if egress_blacklisted:
            node["active"] = False
            node["manual_blacklisted"] = True
            node["probe_status"] = "unavailable"
            node["probe_message"] = node.get("probe_message") or "Manual blacklist egress IP"
            kept.append(node)
            continue
        if (
            node.get("probe_status") == "available"
            or node.get("probe_status") == "unavailable"
        ):
            kept.append(node)
    return sort_all_nodes(kept)

def node_passes_current_latency(node: dict[str, Any] | None) -> bool:
    if not node:
        return False
    threshold = get_latency_threshold_ms()
    latency = parse_int(node.get("latency_ms"))
    return latency > 0 and latency <= threshold

def node_should_be_removed_after_unfavorite(node: dict[str, Any] | None) -> bool:
    if not node:
        return False
    threshold = get_latency_threshold_ms()
    latency = parse_int(node.get("latency_ms"))
    return latency == NODE_TIMEOUT_LATENCY_MS or latency > threshold

def remove_nodes_by_ids(node_ids: set[str]) -> None:
    if not node_ids:
        return
    with lock:
        nodes = read_json(NODES_FILE, [])
        if not isinstance(nodes, list):
            return
        kept = [n for n in nodes if not (isinstance(n, dict) and str(n.get("id") or "") in node_ids)]
        if len(kept) != len(nodes):
            write_json(NODES_FILE, sort_all_nodes(kept))

def remove_nodes_by_ips(ips: set[str]) -> list[str]:
    normalized = {normalize_ip_value(ip) for ip in ips}
    normalized.discard("")
    if not normalized:
        return []
    removed: list[str] = []
    with lock:
        nodes = read_json(NODES_FILE, [])
        if not isinstance(nodes, list):
            return []
        kept = []
        for node in nodes:
            if isinstance(node, dict) and node_egress_ip_values(node).intersection(normalized):
                removed.append(str(node.get("id") or ""))
                continue
            kept.append(node)
        if removed:
            write_json(NODES_FILE, sort_all_nodes(kept))
    return removed

def mark_node_connect_failed(node_id: str, message: str) -> None:
    node_id = str(node_id or "")
    if not node_id:
        return
    with lock:
        nodes = read_json(NODES_FILE, [])
        if not isinstance(nodes, list):
            return
        changed = False
        for node in nodes:
            if not isinstance(node, dict) or str(node.get("id") or "") != node_id:
                continue
            node["active"] = False
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            changed = True
            break
        if changed:
            write_json(NODES_FILE, sort_all_nodes(nodes))

def connect_first_available_candidate(
    candidates: list[dict[str, Any]],
    reason: str,
    exclude_ids: set[str] | None = None,
) -> tuple[bool, str]:
    exclude_ids = exclude_ids or set()
    manual = load_manual_blacklist()
    seen: set[str] = set()
    ordered: list[dict[str, Any]] = []
    for node in candidates:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or "")
        if (
            not node_id
            or node_id in seen
            or node_id in exclude_ids
            or node.get("probe_status") != "available"
            or node.get("manual_blacklisted")
            or manual_blacklist_match_for_node(node, manual)
            or not node_passes_current_latency(node)
        ):
            continue
        ordered.append(node)
        seen.add(node_id)

    ordered.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999, str(n.get("id") or "")))
    if not ordered:
        msg = f"{reason}; no switchable available candidate"
        set_state(last_check_message=msg)
        log_to_json("WARNING", "VPN", msg)
        return False, msg

    if is_connecting:
        msg = f"{reason}; failover deferred because another connection or test is running"
        set_state(last_check_message=msg)
        log_to_json("WARNING", "VPN", msg)
        return False, msg

    failures: list[str] = []
    for node in ordered:
        node_id = str(node.get("id") or "")
        if node_id == active_openvpn_node_id and active_openvpn_running():
            msg = f"{reason}; active node already selected: {node_id}"
            set_state(last_check_message=msg)
            return True, msg
        try:
            connect_node(node_id)
            msg = f"{reason}; switched to {node_id}"
            set_state(last_check_message=msg)
            return True, msg
        except Exception as exc:
            fail_msg = f"{node_id}: {exc}"
            failures.append(fail_msg)
            mark_node_connect_failed(node_id, str(exc))
            log_to_json("WARNING", "VPN", f"{reason}; candidate failed; {fail_msg}")
            continue

    msg = f"{reason}; all {len(ordered)} candidates failed"
    if failures:
        msg = f"{msg}; last error: {failures[-1]}"
    clear_active_connection_state(msg)
    log_to_json("ERROR", "VPN", msg)
    return False, msg

def switch_to_best_current_available(reason: str, exclude_ids: set[str] | None = None) -> bool:
    exclude_ids = exclude_ids or set()
    nodes = read_nodes()
    manual = load_manual_blacklist()
    candidates = [
        n for n in nodes
        if n.get("probe_status") == "available"
        and not n.get("manual_blacklisted")
        and not manual_blacklist_match_for_node(n, manual)
        and str(n.get("id") or "") not in exclude_ids
        and node_passes_current_latency(n)
    ]
    candidates.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999, str(n.get("id") or "")))
    if not candidates:
        set_state(last_check_message=f"{reason}; 当前列表没有可切换的非拉黑可用节点")
        return False
    switched, _ = connect_first_available_candidate(candidates, reason, exclude_ids=exclude_ids)
    return switched

def trigger_egress_blacklist_failover(reason: str, exclude_ids: set[str] | None = None) -> None:
    if maintenance_lock.locked():
        switch_to_best_current_available(reason, exclude_ids=exclude_ids)
        return

    def run_refresh() -> None:
        try:
            refresh_test_prune_and_maybe_switch(reason)
        except Exception as exc:
            log_to_json("ERROR", "VPN", f"{reason}; refresh failover failed: {exc}")
            switch_to_best_current_available(reason, exclude_ids=exclude_ids)

    threading.Thread(target=run_refresh, daemon=True).start()

def enforce_active_not_manual_blacklisted() -> bool:
    global active_openvpn_node_id
    manual = load_manual_blacklist()
    if not manual or not active_openvpn_node_id:
        return False
    nodes = read_json(NODES_FILE, [])
    if not isinstance(nodes, list):
        return False
    old_id = str(active_openvpn_node_id or "")
    active_node = next((n for n in nodes if isinstance(n, dict) and n.get("id") == old_id), None)
    state_proxy_ip = normalize_ip_value(read_json(STATE_FILE, {}).get("proxy_ip"))
    ip = manual_blacklist_match_for_node(active_node, manual) if active_node else ""
    if not ip and state_proxy_ip in manual:
        ip = state_proxy_ip
    if not ip:
        return False
    if active_node:
        active_node["active"] = False
        active_node["manual_blacklisted"] = True
        active_node["blacklisted_ip"] = ip
        active_node["egress_ip"] = state_proxy_ip or active_node.get("egress_ip", "")
        active_node["probe_status"] = "unavailable"
        active_node["probe_message"] = f"Active node is manually blacklisted: {ip}"
        write_json(NODES_FILE, sort_all_nodes(nodes))
    stop_active_openvpn()
    active_openvpn_node_id = ""
    set_state(
        active_openvpn_node_id="",
        active_node_latency="No active connection",
        last_check_message=f"Active egress IP is manually blacklisted: {ip}",
    )
    trigger_egress_blacklist_failover(f"Active egress IP is manually blacklisted: {ip}", exclude_ids={old_id})
    return True

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_config_path(node_id: str) -> Path:
    safe_id = safe_name(node_id)
    return CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"

def resolve_probe_ipv4(host: str) -> str:
    if not host:
        return ""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if ip:
                return ip
    except Exception:
        pass
    return ""

def add_temporary_probe_route(ip: str, dev: str) -> bool:
    if not sys.platform.startswith("linux") or not ip or not dev:
        return False
    try:
        res = subprocess.run(
            ["ip", "route", "add", f"{ip}/32", "dev", dev],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return res.returncode == 0
    except Exception:
        return False

def delete_temporary_probe_route(ip: str, dev: str) -> None:
    if not sys.platform.startswith("linux") or not ip or not dev:
        return
    try:
        subprocess.run(
            ["ip", "route", "del", f"{ip}/32", "dev", dev],
            capture_output=True,
            timeout=2,
        )
    except Exception:
        pass

def build_interface_probe_request(url: str) -> tuple[str, str, str]:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    route_ip = resolve_probe_ipv4(host)
    if not route_ip or route_ip == host:
        return url, route_ip, ""
    netloc = route_ip
    if parsed.port:
        netloc = f"{route_ip}:{parsed.port}"
    probe_url = urllib.parse.urlunparse(parsed._replace(netloc=netloc))
    return probe_url, route_ip, host

def measure_interface_egress_latency(dev: str, timeout: int = 8, deadline: float | None = None) -> dict[str, Any]:
    targets = [
        ("http://cp.cloudflare.com/generate_204", False),
        ("http://api.ipify.org", True),
        ("http://ip.sb", True),
        ("http://1.1.1.1/cdn-cgi/trace", False),
    ]
    best: dict[str, Any] | None = None
    last_error = ""
    for url, body_is_ip in targets:
        effective_timeout = timeout
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"ok": False, "latency_ms": NODE_TIMEOUT_LATENCY_MS, "error": f"node probe timeout after {NODE_PROBE_TIMEOUT_SECONDS}s", "via": dev}
            effective_timeout = max(1, min(timeout, int(math.ceil(remaining))))
        probe_url, route_ip, host_header = build_interface_probe_request(url)
        route_added = add_temporary_probe_route(route_ip, dev)
        cmd = [
            "curl",
            "-4",
            "-sS",
            "--interface",
            dev,
            "-o",
            "-",
            "-w",
            "\n%{time_total} %{http_code}",
            "--max-time",
            str(effective_timeout),
        ]
        if host_header:
            cmd.extend(["-H", f"Host: {host_header}"])
        cmd.append(probe_url)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=effective_timeout + 1)
            if res.returncode != 0:
                last_error = (res.stderr or res.stdout or "").strip()[-180:]
                continue
            lines = res.stdout.strip().splitlines()
            if not lines:
                last_error = "empty curl response"
                continue
            time_info = lines[-1].strip().split()
            if len(time_info) != 2:
                last_error = f"bad curl timing: {lines[-1][-120:]}"
                continue
            total_time_str, http_code = time_info
            if http_code not in ("200", "204"):
                last_error = f"http {http_code}"
                continue
            latency_ms = int(float(total_time_str) * 1000)
            ip = ""
            body = "\n".join(lines[:-1]).strip()
            if body_is_ip and re.match(r"^[0-9a-fA-F:.]+$", body):
                ip = body
            elif "ip=" in body:
                for part in body.splitlines():
                    if part.startswith("ip="):
                        ip = part.removeprefix("ip=").strip()
                        break
            result = {"ok": True, "latency_ms": latency_ms, "ip": ip, "via": dev, "url": url}
            if best is None or latency_ms < parse_int(best.get("latency_ms")):
                best = result
        except Exception as exc:
            last_error = str(exc)
        finally:
            if route_added:
                delete_temporary_probe_route(route_ip, dev)
    if best:
        return best
    if deadline is not None and time.monotonic() >= deadline:
        return {"ok": False, "latency_ms": NODE_TIMEOUT_LATENCY_MS, "error": f"node probe timeout after {NODE_PROBE_TIMEOUT_SECONDS}s", "via": dev}
    return {"ok": False, "latency_ms": 0, "error": last_error or f"egress latency probe failed via {dev}", "via": dev}

def active_node_real_latency(node_id: str) -> dict[str, Any] | None:
    if active_openvpn_node_id and node_id == active_openvpn_node_id and active_openvpn_running():
        return check_proxy_health()
    return None

def is_probe_timeout_message(message: Any) -> bool:
    text = str(message or "").lower()
    return any(token in text for token in ("timeout", "timed out", "超时"))

def timeout_probe_result(node_info: dict[str, Any], message: str | None = None) -> dict[str, Any]:
    result = {
        "id": str(node_info.get("id") or ""),
        "ip": node_info.get("ip") or node_info.get("remote_host") or "",
        "remote_host": node_info.get("remote_host") or node_info.get("ip") or "",
        "remote_port": parse_int(node_info.get("remote_port")),
        "host_name": node_info.get("host_name", ""),
        "sessions": node_info.get("sessions", 0),
        "latency_ms": NODE_TIMEOUT_LATENCY_MS,
        "probe_status": "unavailable",
        "probe_message": message or f"Node probe timeout after {NODE_PROBE_TIMEOUT_SECONDS}s",
        "probed_at": time.time(),
        "owner": node_info.get("owner", ""),
        "asn": node_info.get("asn", ""),
        "as_name": node_info.get("as_name", ""),
        "location": node_info.get("location", ""),
        "ip_type": node_info.get("ip_type", ""),
        "quality": node_info.get("quality", ""),
        "egress_ip": "",
    }
    mark_purity_disabled(result)
    return result

def test_node_real_egress(node_info: dict[str, Any], purity_check: bool) -> dict[str, Any]:
    node_id = str(node_info.get("id") or "")
    latency_threshold = get_latency_threshold_ms()
    probe_deadline = time.monotonic() + NODE_PROBE_TIMEOUT_SECONDS
    manual = load_manual_blacklist()

    active_result = active_node_real_latency(node_id)
    if active_result is not None:
        latency = parse_int(active_result.get("latency_ms"))
        if not active_result.get("ok") and is_probe_timeout_message(active_result.get("error")):
            latency = NODE_TIMEOUT_LATENCY_MS
        egress_ip = normalize_ip_value(active_result.get("ip"))
        active_blacklisted_ip = egress_ip if egress_ip in manual else ""
        ok = bool(active_result.get("ok")) and latency > 0 and latency <= latency_threshold
        if active_blacklisted_ip:
            ok = False
        message = f"Active proxy egress latency ok: {latency} ms" if ok else active_result.get("error", f"Active proxy latency {latency} ms > {latency_threshold} ms")
        if active_blacklisted_ip:
            message = f"Manual blacklist egress IP: {active_blacklisted_ip}"
        result = {
            "id": node_id,
            "ip": node_info.get("ip") or node_info.get("remote_host") or "",
            "remote_host": node_info.get("remote_host") or node_info.get("ip") or "",
            "remote_port": parse_int(node_info.get("remote_port")),
            "host_name": node_info.get("host_name", ""),
            "sessions": node_info.get("sessions", 0),
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": node_info.get("owner", ""),
            "asn": node_info.get("asn", ""),
            "as_name": node_info.get("as_name", ""),
            "location": node_info.get("location", ""),
            "ip_type": node_info.get("ip_type", ""),
            "quality": node_info.get("quality", ""),
            "egress_ip": active_result.get("ip", ""),
        }
        if active_blacklisted_ip:
            result["manual_blacklisted"] = True
            result["blacklisted_ip"] = active_blacklisted_ip
        mark_purity_disabled(result)
        return result

    config_text = node_info.get("config_text") or ""
    if not config_text:
        return {
            "id": node_id,
            "latency_ms": 0,
            "probe_status": "unavailable",
            "probe_message": "Missing OpenVPN config",
            "probed_at": time.time(),
            "egress_ip": "",
        }

    temp_path = test_config_path(node_id)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        return {
            "id": node_id,
            "latency_ms": 0,
            "probe_status": "unavailable",
            "probe_message": f"Failed to write configuration: {e}",
            "probed_at": time.time(),
            "egress_ip": "",
        }

    tun_idx = None
    process = None
    ok = False
    message = ""
    latency = 0
    egress_ip = ""
    try:
        tun_idx = get_free_test_index()
        dev_name = f"tun{tun_idx}"
        remaining = max(1, math.ceil(probe_deadline - time.monotonic()))
        ok, message, process = run_openvpn_until_ready(
            str(temp_path),
            keep_alive=False,
            route_nopull=True,
            timeout=min(NODE_PROBE_TIMEOUT_SECONDS, remaining),
            dev=dev_name,
            keep_process=True,
        )
        if not ok and is_probe_timeout_message(message):
            latency = NODE_TIMEOUT_LATENCY_MS
        if ok and time.monotonic() >= probe_deadline:
            ok = False
            latency = NODE_TIMEOUT_LATENCY_MS
            message = f"Node probe timeout after {NODE_PROBE_TIMEOUT_SECONDS}s"
        if ok and process is not None:
            probe = measure_interface_egress_latency(dev_name, timeout=NODE_PROBE_TIMEOUT_SECONDS, deadline=probe_deadline)
            latency = parse_int(probe.get("latency_ms"))
            egress_ip = str(probe.get("ip") or "")
            ok = bool(probe.get("ok")) and latency > 0 and latency <= latency_threshold
            if not probe.get("ok"):
                message = str(probe.get("error") or "egress latency probe failed")
                if is_probe_timeout_message(message) or latency == NODE_TIMEOUT_LATENCY_MS:
                    latency = NODE_TIMEOUT_LATENCY_MS
            elif latency > latency_threshold:
                message = f"Real egress latency {latency} ms > {latency_threshold} ms"
            else:
                message = f"Real egress latency ok: {latency} ms"
    finally:
        stop_process(process, wait_timeout=1 if latency == NODE_TIMEOUT_LATENCY_MS else 8)
        if tun_idx is not None:
            release_test_index(tun_idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    if latency == NODE_TIMEOUT_LATENCY_MS:
        return timeout_probe_result(node_info, message)

    result = {
        "id": node_id,
        "ip": node_info.get("ip") or node_info.get("remote_host") or "",
        "remote_host": node_info.get("remote_host") or node_info.get("ip") or "",
        "remote_port": parse_int(node_info.get("remote_port")),
        "host_name": node_info.get("host_name", ""),
        "sessions": node_info.get("sessions", 0),
        "latency_ms": latency,
        "probe_status": "available" if ok else "unavailable",
        "probe_message": message,
        "probed_at": time.time(),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "egress_ip": egress_ip,
    }
    blacklisted_ip = manual_blacklist_match_for_node(result, manual)
    if blacklisted_ip:
        result["probe_status"] = "unavailable"
        result["probe_message"] = f"Manual blacklist egress IP: {blacklisted_ip}"
        result["manual_blacklisted"] = True
        result["blacklisted_ip"] = blacklisted_ip
    mark_purity_disabled(result)
    if ok and not blacklisted_ip:
        vpn_utils.enrich_ip_info([result])
        # Purity scoring/filtering is intentionally disabled. Keep the old call
        # here commented for future rollback reference.
        # if purity_check:
        #     vpn_utils.assess_nodes_purity([result])
    return result

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        node_info = node.copy()

    tested = test_node_real_egress(node_info, purity_check=False)

    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node.update({k: v for k, v in tested.items() if k != "id"})
            apply_manual_blacklist_to_node(node)
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            cleanup_favorite_node_ids(sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(node_ids: list[str], cleanup_favorites: bool = True) -> list[dict[str, Any]]:
    with lock:
        nodes = read_nodes()
        to_test = [n for n in nodes if n.get("id") in node_ids]
        
    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        _, n_info = args
        return test_node_real_egress(n_info, purity_check=False)

    updated_nodes_map = {}
    max_workers = min(5, max(1, len(to_test)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
            except Exception as e:
                timeout_error = isinstance(e, TimeoutError) or is_probe_timeout_message(e)
                error_node = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": NODE_TIMEOUT_LATENCY_MS if timeout_error else 0,
                    "egress_ip": "",
                }
                mark_purity_disabled(error_node)
                updated_nodes_map[nid] = error_node
                
    # 批量查询并丰富可用节点的地理及 ISP 信息，防止并发时被定位 API 接口限流
    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
            for node in successful_nodes:
                mark_purity_disabled(node)
            # Purity scoring/filtering is intentionally disabled. Keep the old
            # call commented for future rollback reference.
            # vpn_utils.assess_nodes_purity(successful_nodes)
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    with lock:
        current_nodes = read_nodes()
        manual = load_manual_blacklist()
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
            apply_manual_blacklist_to_node(n, manual)
        if cleanup_favorites:
            fav_ids = set(favorite_node_ids(load_ui_config()))
            current_nodes = [
                n for n in current_nodes
                if parse_int(n.get("latency_ms")) != NODE_TIMEOUT_LATENCY_MS
                or str(n.get("id") or "") in fav_ids
            ]
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        if cleanup_favorites:
            cleanup_favorite_node_ids(sorted_nodes)
        
    return list(updated_nodes_map.values())

fixed_region_failover_lock = threading.Lock()
fixed_favorites_failover_lock = threading.Lock()

def country_matches(node: dict[str, Any], target_country: str) -> bool:
    if not target_country:
        return True
    country = str(node.get("country") or "")
    translated = vpn_utils.COUNTRY_TRANSLATIONS.get(country, country)
    return country == target_country or translated == target_country

def filter_routing_candidates(nodes: list[dict[str, Any]], ui_cfg: dict[str, Any], exclude_active: bool = True) -> list[dict[str, Any]]:
    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")
    manual = load_manual_blacklist()
    candidates = [
        n for n in nodes
        if n.get("probe_status") == "available"
        and not manual_blacklist_match_for_node(n, manual)
        and (not exclude_active or not n.get("active"))
        and node_passes_current_latency(n)
    ]

    if routing_mode == "fixed_region" and target_country:
        candidates = [n for n in candidates if country_matches(n, target_country)]
    elif routing_mode in ("favorites", "fixed_favorites"):
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        fav_candidates = [n for n in candidates if n.get("id") in fav_ids]
        if fav_candidates:
            candidates = fav_candidates
        elif not ui_cfg.get("fav_fail_fallback", True):
            candidates = []
        else:
            candidates = [n for n in candidates if n.get("id") not in fav_ids]

    if routing_mode == "fixed_region":
        routing_ip_type = ui_cfg.get("routing_ip_type", "all")
        if routing_ip_type == "residential":
            candidates = [n for n in candidates if n.get("ip_type") in ("residential", "mobile")]
        elif routing_ip_type == "hosting":
            candidates = [n for n in candidates if n.get("ip_type") == "hosting"]

    candidates.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999, -parse_int(n.get("score"))))
    return candidates

def node_in_routing_test_scope(node: dict[str, Any], ui_cfg: dict[str, Any]) -> bool:
    routing_mode = ui_cfg.get("routing_mode", "auto")
    if node.get("manual_blacklisted") or manual_blacklist_match_for_node(node):
        return False
    if routing_mode == "auto":
        return True
    if routing_mode == "fixed_region":
        target_country = str(ui_cfg.get("force_country") or "")
        if target_country and not country_matches(node, target_country):
            return False
        routing_ip_type = ui_cfg.get("routing_ip_type", "all")
        if routing_ip_type == "residential":
            return node.get("ip_type") in ("residential", "mobile")
        if routing_ip_type == "hosting":
            return node.get("ip_type") == "hosting"
        return True
    if routing_mode in ("favorites", "fixed_favorites"):
        fav_ids = set(favorite_node_ids(ui_cfg))
        return str(node.get("id") or "") in fav_ids
    if routing_mode == "fixed_ip":
        target_id = str(ui_cfg.get("fixed_node_id") or active_openvpn_node_id or "")
        return bool(target_id and str(node.get("id") or "") == target_id)
    return False

def test_current_routing_scope_and_maybe_switch(reason: str) -> str:
    global active_openvpn_node_id, is_connecting
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        msg = "路由切换测速排序任务正在运行，跳过本次触发"
        set_state(last_check_message=msg)
        return msg

    previous_connecting = is_connecting
    active_id = active_openvpn_node_id
    is_connecting = True
    try:
        ui_cfg = load_ui_config()
        routing_mode = ui_cfg.get("routing_mode", "auto")
        fav_ids = set(favorite_node_ids(ui_cfg))
        nodes = read_nodes()
        scope_ids = [
            str(n.get("id") or "")
            for n in nodes
            if str(n.get("id") or "") and node_in_routing_test_scope(n, ui_cfg)
        ]

        if not scope_ids:
            msg = f"路由模式切换完成，但当前模式没有可测速节点: {routing_mode}"
            set_state(is_connecting=False, last_check_message=msg)
            return msg

        with lock:
            current_nodes = read_nodes()
            for node in current_nodes:
                if str(node.get("id") or "") in scope_ids:
                    node["probe_status"] = "testing"
                    node["probe_message"] = f"Testing latency for routing mode switch: {routing_mode}"
                    node["latency_ms"] = 0
            write_json(NODES_FILE, sort_all_nodes(current_nodes))

        set_state(is_connecting=True, last_check_message=f"正在按新路由模式测速排序: {reason}")
        test_multiple_nodes(scope_ids, cleanup_favorites=False)

        with lock:
            tested_nodes = read_nodes()
            keep_ids: set[str] = set()
            if routing_mode == "fixed_ip" and active_id:
                keep_ids.add(active_id)
            tested_nodes = [
                node for node in tested_nodes
                if not (
                    str(node.get("id") or "") in scope_ids
                    and parse_int(node.get("latency_ms")) == NODE_TIMEOUT_LATENCY_MS
                    and str(node.get("id") or "") not in fav_ids
                    and str(node.get("id") or "") not in keep_ids
                )
            ]
            write_json(NODES_FILE, sort_all_nodes(tested_nodes))

        if routing_mode == "fixed_ip":
            msg = "固定 IP 模式已完成当前固定节点测速；不自动切换"
            set_state(is_connecting=False, last_check_message=msg)
            return msg

        all_nodes = read_nodes()
        candidates = filter_routing_candidates(all_nodes, ui_cfg, exclude_active=False)
        favorite_available = any(
            str(n.get("id") or "") in fav_ids
            and n.get("probe_status") == "available"
            and node_passes_current_latency(n)
            for n in all_nodes
        )
        if routing_mode in ("favorites", "fixed_favorites") and not favorite_available and not ui_cfg.get("fav_fail_fallback", True):
            msg = "收藏节点全部不可用，且已禁用非收藏节点回退；保持当前连接不切换"
            set_state(is_connecting=False, last_check_message=msg)
            return msg

        if not candidates:
            msg = f"路由模式 {routing_mode} 测速完成，但没有符合规则的可用节点"
            set_state(is_connecting=False, last_check_message=msg)
            return msg

        is_connecting = False
        switched, msg = connect_first_available_candidate(candidates, f"routing mode {routing_mode} failover")
        set_state(last_check_message=msg)
        return msg
    except Exception as exc:
        msg = f"路由模式切换测速失败: {exc}"
        print(f"[路由切换] {msg}", flush=True)
        log_to_json("ERROR", "VPN", msg)
        set_state(last_check_message=msg)
        return msg
    finally:
        is_connecting = False
        maintenance_lock.release()

def favorite_node_ids(ui_cfg: dict[str, Any]) -> list[str]:
    fav_ids = ui_cfg.get("favorite_node_ids", [])
    if not isinstance(fav_ids, list):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for item in fav_ids:
        node_id = str(item or "").strip()
        if node_id and node_id not in seen:
            result.append(node_id)
            seen.add(node_id)
    return result

def node_can_be_favorited(node: dict[str, Any] | None) -> bool:
    if not node:
        return False
    if node.get("manual_blacklisted") or manual_blacklist_match_for_node(node):
        return False
    return node.get("probe_status") == "available"

def cleanup_favorite_node_ids(nodes: list[dict[str, Any]] | None = None) -> list[str]:
    ui_cfg = load_ui_config()
    fav_ids = favorite_node_ids(ui_cfg)
    if not fav_ids:
        return []
    if nodes is None:
        nodes = read_nodes()
    node_map = {str(n.get("id") or ""): n for n in nodes if isinstance(n, dict)}
    cleaned = [
        node_id
        for node_id in fav_ids
        if node_map.get(node_id) is not None
        and not node_map[node_id].get("manual_blacklisted")
        and not manual_blacklist_match_for_node(node_map[node_id])
    ]
    if cleaned != fav_ids:
        ui_cfg["favorite_node_ids"] = cleaned
        auth_file = DATA_DIR / "ui_auth.json"
        with lock:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    return cleaned

def refresh_and_switch_fixed_region(reason: str) -> None:
    if not fixed_region_failover_lock.acquire(blocking=False):
        print(f"[固定地区切换] 已有固定地区刷新切换任务运行中，跳过本次触发: {reason}", flush=True)
        return
    try:
        ui_cfg = load_ui_config()
        if ui_cfg.get("routing_mode") != "fixed_region":
            return
        if not ui_cfg.get("connection_enabled", True):
            return
        msg = f"固定地区模式触发新旧节点合并测速排序。原因: {reason}"
        print(f"[固定地区切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        refresh_test_prune_and_maybe_switch(reason)
    except Exception as exc:
        print(f"[固定地区切换] 刷新测速排序并切换失败: {exc}", flush=True)
        log_to_json("ERROR", "VPN", f"固定地区刷新切换失败: {exc}")
    finally:
        fixed_region_failover_lock.release()

def refresh_and_switch_fixed_favorites(reason: str) -> None:
    if not fixed_favorites_failover_lock.acquire(blocking=False):
        print(f"[固定收藏切换] 已有固定收藏刷新切换任务运行中，跳过本次触发: {reason}", flush=True)
        return
    try:
        ui_cfg = load_ui_config()
        if ui_cfg.get("routing_mode") != "fixed_favorites":
            return
        if not ui_cfg.get("connection_enabled", True):
            return

        fav_ids = favorite_node_ids(ui_cfg)
        if not fav_ids:
            set_state(last_check_message="固定收藏菜单模式没有收藏节点，无法自动切换")
            return

        msg = f"固定收藏菜单模式触发新旧节点合并测速排序。原因: {reason}"
        print(f"[固定收藏切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        refresh_test_prune_and_maybe_switch(reason)
    except Exception as exc:
        print(f"[固定收藏切换] 收藏节点测速排序并切换失败: {exc}", flush=True)
        log_to_json("ERROR", "VPN", f"固定收藏刷新切换失败: {exc}")
    finally:
        fixed_favorites_failover_lock.release()

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        return
        
    ui_cfg = load_ui_config()
    connection_enabled = ui_cfg.get("connection_enabled", True)
    if not connection_enabled:
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return

    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_ip":
        print("[自动切换] 当前处于固定 IP 模式，不进行自动连接或切换。", flush=True)
        return

    # Find the next best available node
    with lock:
        nodes = read_nodes()
        candidates = filter_routing_candidates(nodes, ui_cfg, exclude_active=True)
        
    if candidates:
        msg = "Current connection failed; trying available failover candidates"
        print(f"[auto switch] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        connect_first_available_candidate(candidates, msg)
        return
    else:
        msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        if routing_mode == "fixed_region" and target_country:
            msg = f"没有可用的【{target_country}】备选节点，已断开连接，将在后台持续尝试获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)
        
        def bg_fetch_and_switch():
            try:
                refresh_test_prune_and_maybe_switch("auto switch fallback")
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)
        
        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def refresh_test_prune_and_maybe_switch(reason: str, routing_mode_override: str | None = None) -> str:
    global active_openvpn_node_id, is_connecting
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        msg = "高延迟刷新任务正在运行，跳过本次触发"
        set_state(last_check_message=msg)
        return msg

    previous_connecting = is_connecting
    is_connecting = True
    active_id = active_openvpn_node_id
    try:
        ui_cfg = load_ui_config()
        routing_mode = routing_mode_override or ui_cfg.get("routing_mode", "auto")
        latency_threshold = get_latency_threshold_ms(ui_cfg)
        fav_ids = set(favorite_node_ids(ui_cfg))
        fixed_ip_mode = routing_mode == "fixed_ip"

        set_state(is_connecting=True, last_check_message=f"正在拉取新节点并合并旧节点测速排序: {reason}")
        old_nodes = read_nodes()
        old_by_id = {str(n.get("id") or ""): n for n in old_nodes if isinstance(n, dict)}
        new_nodes = fetch_candidates()
        merged = merge_nodes_preserve_old(old_nodes, new_nodes)

        with lock:
            if len(merged) > 1000:
                merged = merged[:1000]
            for n in merged:
                node_id = str(n.get("id") or "")
                if node_id and node_id not in old_by_id:
                    n["probe_status"] = "testing"
                    n["probe_message"] = "Testing latency before publishing final status"
                    n["latency_ms"] = 0
                config_path_value = n.get("config_file")
                if config_path_value:
                    config_path = Path(config_path_value)
                    if not config_path.exists() and n.get("config_text"):
                        try:
                            config_path.write_text(n["config_text"], encoding="utf-8")
                        except Exception:
                            pass
            write_json(NODES_FILE, merged)

        test_ids = [str(n.get("id") or "") for n in merged if n.get("id")]
        if test_ids:
            test_multiple_nodes(test_ids, cleanup_favorites=False)

        with lock:
            tested_nodes = read_nodes()
            keep_unavailable_active_without_fallback = False
            if routing_mode in ("favorites", "fixed_favorites") and not ui_cfg.get("fav_fail_fallback", True):
                favorite_available = any(
                    str(node.get("id") or "") in fav_ids
                    and node.get("probe_status") == "available"
                    and node_passes_current_latency(node)
                    for node in tested_nodes
                )
                keep_unavailable_active_without_fallback = not favorite_available and bool(active_id)
            for node in tested_nodes:
                if node.get("id") == active_id:
                    node["latency_ms"] = max(parse_int(node.get("latency_ms")), latency_threshold + 1)
                    if not fixed_ip_mode and not keep_unavailable_active_without_fallback:
                        node["active"] = False
                        node["probe_status"] = "unavailable"
                        node["probe_message"] = reason
                    elif keep_unavailable_active_without_fallback:
                        node["active"] = True
                        node["probe_status"] = "unavailable"
                        node["probe_message"] = "全部收藏节点不可用，且已禁用非收藏节点回退；保持当前连接"
                elif not fixed_ip_mode:
                    node["active"] = False

            if not fixed_ip_mode and active_id and not keep_unavailable_active_without_fallback:
                stop_active_openvpn()
                active_openvpn_node_id = ""

            keep_ids = {active_id} if (fixed_ip_mode or keep_unavailable_active_without_fallback) and active_id else set()
            pruned = prune_failed_nodes(tested_nodes, fav_ids, keep_ids=keep_ids)
            write_json(NODES_FILE, pruned)

        if fixed_ip_mode:
            msg = "固定 IP 模式已完成新旧节点测速与剔除；当前连接不自动切换"
            set_state(is_connecting=False, last_check_message=msg)
            return msg

        if keep_unavailable_active_without_fallback:
            msg = "收藏节点全部不可用，且已禁用非收藏节点回退；保持当前连接不切换"
            set_state(is_connecting=False, last_check_message=msg)
            return msg

        ui_cfg = load_ui_config()
        if routing_mode_override:
            ui_cfg = dict(ui_cfg)
            ui_cfg["routing_mode"] = routing_mode_override
            ui_cfg["force_country"] = ""
            ui_cfg["routing_ip_type"] = "all"
        candidates = filter_routing_candidates(pruned, ui_cfg, exclude_active=False)
        if not candidates:
            msg = "节点测速排序完成，但没有符合当前路由模式的可用节点"
            set_state(active_openvpn_node_id="", is_connecting=False, last_check_message=msg, active_node_latency="无活动连接")
            return msg

        is_connecting = False
        switched, msg = connect_first_available_candidate(candidates, "refresh/test failover")
        set_state(last_check_message=msg)
        return msg
    except Exception as exc:
        msg = f"高延迟刷新失败: {exc}"
        print(f"[高延迟刷新] {msg}", flush=True)
        log_to_json("ERROR", "VPN", msg)
        set_state(last_check_message=msg)
        return msg
    finally:
        is_connecting = False
        maintenance_lock.release()

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")
    stopped_existing = False
    with lock:
        if is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        is_connecting = True
        set_state(is_connecting=True, active_node_latency="正在连接", last_check_message=f"正在初始化连接配置: {node_id}")
        
    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        old_node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None) if active_openvpn_node_id else None
        if apply_manual_blacklist_to_node(node):
            write_json(NODES_FILE, nodes)
            raise RuntimeError(f"Node egress IP is manually blacklisted: {node.get('blacklisted_ip') or node.get('egress_ip') or node.get('proxy_ip')}")
        if old_node and old_node.get("id") != node_id:
            log_node_activity("SWITCH_REQUEST", f"Switch requested from {old_node.get('id')} to {node_id}", node)
        else:
            log_node_activity("CONNECT_REQUEST", f"Connect requested for {node_id}", node)
        
        ui_cfg = load_ui_config()
        ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip":
            ui_cfg["fixed_node_id"] = node_id
        auth_file = DATA_DIR / "ui_auth.json"
        with lock:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        
        set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")
        stop_active_openvpn()
        stopped_existing = True

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            log_node_activity("SWITCH_FAILED", f"OpenVPN failed while connecting {node_id}: {message}", node)
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            print(f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", flush=True)
            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)
            
        with lock:
            active_openvpn_process = process
            active_openvpn_node_id = node_id
        
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing("tun0")
        
        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
            
        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
                item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            proxy_latency = parse_int(res.get("latency_ms"))
            if proxy_latency > 0:
                last_active_latency = proxy_latency
            proxy_ip = normalize_ip_value(res.get("ip"))
            manual = load_manual_blacklist()
            if proxy_ip and proxy_ip in manual:
                with lock:
                    active_openvpn_process = process
                    active_openvpn_node_id = node_id
                    current_nodes = read_nodes()
                    for item in current_nodes:
                        if item.get("id") == node_id:
                            item["active"] = False
                            item["egress_ip"] = proxy_ip
                            item["manual_blacklisted"] = True
                            item["blacklisted_ip"] = proxy_ip
                            item["probe_status"] = "unavailable"
                            item["probe_message"] = f"Manual blacklist egress IP: {proxy_ip}"
                            break
                    write_json(NODES_FILE, sort_all_nodes(current_nodes))
                stop_active_openvpn()
                with lock:
                    active_openvpn_node_id = ""
                    active_openvpn_process = None
                set_state(
                    active_openvpn_node_id="",
                    is_connecting=False,
                    proxy_ok=False,
                    proxy_ip=proxy_ip,
                    proxy_latency_ms=proxy_latency,
                    proxy_error=f"Manual blacklist egress IP: {proxy_ip}",
                    active_node_latency="无活动连接",
                    last_check_message=f"节点出口 IP 命中手动拉黑，已断开: {proxy_ip}",
                )
                log_node_activity("BLACKLIST_DISCONNECT", f"Connected node egress IP is manually blacklisted: {proxy_ip}", node)
                raise RuntimeError(f"Node egress IP is manually blacklisted: {proxy_ip}")
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=proxy_latency,
                proxy_error=""
            )
            node["egress_ip"] = proxy_ip or res.get("ip", "")
        else:
            proxy_error = res.get("error", "proxy health check failed")
            with lock:
                current_nodes = read_nodes()
                for item in current_nodes:
                    if item.get("id") == node_id:
                        item["active"] = False
                        item["probe_status"] = "unavailable"
                        item["probe_message"] = f"Proxy health check failed: {proxy_error}"
                        break
                write_json(NODES_FILE, sort_all_nodes(current_nodes))
                active_openvpn_node_id = ""
                active_openvpn_process = None
            stop_process(process)
            set_state(
                active_openvpn_node_id="",
                is_connecting=False,
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=proxy_error,
                active_node_latency="No active connection",
                last_check_message=f"Proxy health check failed for {node_id}: {proxy_error}",
            )
            raise RuntimeError(f"Proxy health check failed: {proxy_error}")
            
        latency_str = f"{last_active_latency} ms" if res.get("ok") and last_active_latency > 0 else "检测超时"
        write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        if old_node and old_node.get("id") != node_id:
            log_node_activity("SWITCH", f"Switched from {old_node.get('id')} to {node_id}", node)
        else:
            log_node_activity("CONNECTED", f"Connected to {node_id}", node)
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    except Exception as exc:
        try:
            failed_node = None
            for item in read_nodes():
                if item.get("id") == node_id:
                    failed_node = item
                    break
            log_node_activity("SWITCH_FAILED", f"Connect failed for {node_id}", failed_node, exc)
        except Exception:
            pass
        if stopped_existing or (active_openvpn_node_id == node_id and not active_openvpn_running()):
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            set_state(is_connecting=False, last_check_message=f"连接失败: {exc}")
        raise
    finally:
        with lock:
            is_connecting = False

def maintain_valid_nodes(force: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        msg = "节点维护任务正在运行，请稍后再试"
        set_state(last_check_message=msg)
        return msg
    is_connecting = True
    try:
        if force:
            with lock:
                stop_active_openvpn()
        elif not active_openvpn_running():
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    target_id = active_openvpn_node_id or ui_cfg.get("fixed_node_id", "")
                    if target_id:
                        nodes = read_nodes()
                        if any(n.get("id") == target_id for n in nodes):
                            print(f"[维护线程] 检测到固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
                            is_connecting = False
                            try:
                                connect_node(target_id)
                            except Exception as e:
                                print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
                            is_connecting = True
                else:
                    has_active_id = False
                    with lock:
                        if active_openvpn_node_id:
                            has_active_id = True
                            stop_active_openvpn()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        is_connecting = False
                        auto_switch_node()
                        is_connecting = True

        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            diag_msg = str(exc)
            if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                err_code, raw_diag = vpn_utils.diagnose_api_failure(API_URL)
                diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg)
            candidates = []

        if not candidates:
            return "没有拉取到新节点"

        with lock:
            active_node = None
            if active_openvpn_node_id:
                current_nodes = read_nodes()
                active_node = next((n for n in current_nodes if n.get("id") == active_openvpn_node_id), None)
                
            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            
            if active_node:
                merged.append(active_node)
                seen_ids.add(active_node["id"])
                
            for cand in candidates:
                if cand["id"] not in seen_ids:
                    merged.append(cand)
                    seen_ids.add(cand["id"])
                    
            if len(merged) > 1000:
                merged = merged[:1000]
                
            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass
                        
            write_json(NODES_FILE, merged)

        # Test all non-active nodes from the list
        with lock:
            current_nodes = read_nodes()
            to_test = [n for n in current_nodes if not n.get("active")]
            to_test_ids = [n["id"] for n in to_test]
            
        msg = f"开始对列表中所有候选节点进行周期连通性与延迟测试，待检测节点共 {len(to_test_ids)} 个"
        print(f"[周期检测] {msg}", flush=True)
        log_to_json("INFO", "Main", msg)
        
        set_state(is_connecting=True, last_check_message="正在并发检测所有节点可用性...")
        test_multiple_nodes(to_test_ids)
        is_connecting = False
        
        with lock:
            merged = read_nodes()
            
            # Identify available, unavailable, and active nodes
            available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
            unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
            active_node = next((n["id"] for n in merged if n.get("active")), "无")
            
            status_report = (
                f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                f"【不可用节点】{len(unavailable_nodes)} 个; "
                f"当前【正在正常运行的活动连接节点】为: {active_node}。"
            )
            print(f"[周期检测] {status_report}", flush=True)
            log_to_json("INFO", "Main", status_report)
            
            if active_node != "无" and not active_openvpn_running():
                warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                print(warn_msg, flush=True)
                log_to_json("WARNING", "Main", warn_msg)
            
            if not active_openvpn_running():
                ui_cfg = load_ui_config()
                connection_enabled = ui_cfg.get("connection_enabled", True)
                if connection_enabled:
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    target_country = ui_cfg.get("force_country", "")
                    
                    if routing_mode != "fixed_ip":
                        available_candidates = filter_routing_candidates(merged, ui_cfg, exclude_active=True)
                        if available_candidates:
                            auto_switch_node()

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} non-active nodes."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )
        return message
    except Exception as e:
        raise e
    finally:
        is_connecting = False
        maintenance_lock.release()


def collector_loop() -> None:
    global last_collector_heartbeat
    while True:
        last_collector_heartbeat = time.time()
        success = False
        try:
            if not cached_nodes():
                print("[守护线程] 当前没有节点缓存，执行首次节点拉取与可用性检测...", flush=True)
                log_to_json("INFO", "Main", "当前没有节点缓存，执行首次节点拉取与可用性检测...")
                res = refresh_test_prune_and_maybe_switch("first startup")
                if "没有拉取到新节点" not in res:
                    success = True
                log_to_json("INFO", "Main", f"首次同步与检测任务完成，结果: {res}")
            else:
                ui_cfg = load_ui_config()
                routing_mode = ui_cfg.get("routing_mode", "auto")
                if (
                    ui_cfg.get("connection_enabled", True)
                    and routing_mode != "fixed_ip"
                    and not active_openvpn_node_id
                    and not active_openvpn_running()
                ):
                    print("[守护线程] 节点缓存已存在但没有活动连接，按当前路由模式执行一次测速排序与切换。", flush=True)
                    log_to_json("INFO", "Main", "节点缓存已存在但没有活动连接，按当前路由模式执行一次测速排序与切换。")
                    res = test_current_routing_scope_and_maybe_switch("startup cached nodes")
                    if "没有可测速节点" not in res:
                        success = True
                    log_to_json("INFO", "Main", f"缓存节点启动测速切换完成，结果: {res}")
                else:
                    success = True
                    set_state(last_check_message="节点缓存已存在，后台不再无条件刷新；仅在活动节点延迟超过阈值时刷新")
        except Exception as exc:
            err_msg = f"周期节点同步任务执行异常: {exc}"
            print(f"[错误] {err_msg}", flush=True)
            log_to_json("ERROR", "Main", err_msg)
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")
            
        if not active_openvpn_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS
            
        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AimiliVPN - 安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.45);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">AimiliVPN</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" name="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" name="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value.trim();
      const pwd = document.getElementById("password").value.trim();
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");
      
      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";
      
      try {
        const response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        });
        
        const data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AimiliVPN 节点池管理系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
      --bg-dark: #0b0f19;
      --bg-surface: rgba(22, 30, 49, 0.6);
      --bg-surface-hover: rgba(30, 41, 67, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-color-hover: rgba(99, 102, 241, 0.35);
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --success-gradient: linear-gradient(135deg, #34d399 0%, #059669 100%);
      --danger: #f43f5e;
      --danger-gradient: linear-gradient(135deg, #fb7185 0%, #e11d48 100%);
      --warning: #f59e0b;
      --warning-gradient: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
      --active-row-bg: rgba(16, 185, 129, 0.06);
      --active-row-border: rgba(16, 185, 129, 0.25);
    }

    body {
      margin: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(79, 70, 229, 0.05) 0px, transparent 50%);
      background-attachment: fixed;
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 16px 32px;
      background: rgba(11, 15, 25, 0.7);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    h1 {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
      display: inline-block;
    }

    .btn-group {
      display: flex;
      gap: 12px;
    }

    button, .btn-telegram {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
      white-space: nowrap;
      text-decoration: none;
      box-sizing: border-box;
    }

    button:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-telegram {
      background: rgba(43, 162, 223, 0.15);
      border: 1px solid rgba(43, 162, 223, 0.3);
      color: #2ba2df;
    }

    .btn-telegram:hover {
      background: rgba(43, 162, 223, 0.25);
      border-color: rgba(43, 162, 223, 0.5);
      color: #2ba2df;
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(79, 70, 229, 0.04) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(99, 102, 241, 0.12);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
    }
    
    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    
    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    
    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }
    
    .active-card-meta {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-secondary);
      flex-wrap: wrap;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.04);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }

    /* New style additions */
    .header-badge-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      height: 24px;
      box-sizing: border-box;
    }
    .header-badge-link:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--border-color-hover);
      color: var(--text-primary);
      transform: translateY(-1px);
    }
    .flex-row-container {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
      margin-bottom: 24px;
    }
    .flex-row-container > * {
      flex: 1;
      min-width: 320px;
      margin-bottom: 0 !important;
    }
    .toolbar {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar select {
      width: 180px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: #0f172a;
    }

    .toolbar input {
      flex: 1;
      min-width: 250px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .toolbar input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.8);
    }

    .table-wrapper {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .table-container {
      overflow-x: auto;
    }

    table {
      width: 100%;
      min-width: 1380px;
      border-collapse: collapse;
      text-align: left;
      table-layout: fixed;
    }

    th, td {
      padding: 14px 14px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .testing {
      background: rgba(59, 130, 246, 0.12);
      color: #93c5fd;
      border-color: rgba(59, 130, 246, 0.24);
    }

    .testing-dots::after {
      content: "";
      animation: testingDots 1.2s steps(4, end) infinite;
    }

    @keyframes testingDots {
      0% { content: ""; }
      25% { content: "."; }
      50% { content: ".."; }
      75%, 100% { content: "..."; }
    }

    .current-badge {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .latency-val {
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }
    
    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }
    
    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
      }
      .btn-group {
        width: 100%;
        margin-top: 12px;
      }
      .btn-group button, .btn-group .btn-telegram {
        flex: 1;
      }
      .btn-group .dropdown {
        flex: 1;
        display: flex;
      }
      .btn-group .dropdown button {
        width: 100%;
        flex: 1;
      }
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
    }
    
    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(22, 30, 49, 0.95);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    .dropdown-content a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    }
    .dropdown-content a:hover {
      background: rgba(255,255,255,0.08);
    }
    
    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: auto;
      background-color: rgba(9, 13, 22, 0.7);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.9);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: 90%;
      max-width: 480px;
      padding: 32px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }
    
    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }
    select option {
      background-color: #0f172a;
      color: #f8fafc;
    }
    
    /* Option Card Styles for Proxy/Routing Settings */
    .option-group {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-top: 6px;
    }
    
    @media (max-width: 640px) {
      .option-group {
        grid-template-columns: repeat(2, 1fr);
      }
    }
    
    @media (max-width: 480px) {
      .option-group {
        grid-template-columns: 1fr;
      }
    }
    
    .option-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 12px 14px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      user-select: none;
      position: relative;
      text-align: left;
    }
    
    .option-card:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(99, 102, 241, 0.25);
      transform: translateY(-1px);
    }
    
    .option-card.active {
      background: rgba(99, 102, 241, 0.08);
      border-color: var(--primary);
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.15);
    }
    
    .option-card-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 4px;
    }
    
    .option-card-desc {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.3;
    }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      AimiliVPN 节点管理系统
    </h1>
    <div id="status" class="status" style="display: none;"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="btn-group">

    <div class="dropdown">
      <button id="github_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        GITHUB
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="github_dropdown" class="dropdown-content">
        <a href="https://github.com/baoweise-bot/aimili-vpngate" target="_blank">正式版</a>
        <a href="https://github.com/baoweise-bot/aimili-vpngate/tree/bate" target="_blank">测试版</a>
      </div>
    </div>
    <a href="https://t.me/arestemple" target="_blank" class="btn-telegram">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.287 5.906c-.778.324-2.334.994-4.666 2.01-.378.15-.577.298-.595.442-.03.243.275.339.69.47l.175.055c.408.133.958.288 1.243.294.26.006.549-.1.868-.32 2.179-1.471 3.304-2.214 3.374-2.23.05-.012.12-.026.166.016.047.041.042.12.037.141-.03.129-1.227 1.241-1.846 1.817-.193.18-.33.307-.358.336-.063.065-.129.13-.19.193-.34.347-.597.609-.043.974.265.175.474.319.684.457.228.15.457.301.765.503.074.049.143.098.207.143.297.206.58.404.916.373.195-.018.398-.2.502-.754.25-1.332.74-4.22.842-5.281.01-.088.001-.22-.103-.312-.104-.092-.252-.09-.323-.087a1.52 1.52 0 0 0-.254.04z"/></svg>
      Telegram
    </a>
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      更新节点
    </button>
    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openCredentialsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </a>
        <a href="javascript:void(0)" onclick="openNetworkModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </a>
        <a href="javascript:void(0)" onclick="openGatewayModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置
        </a>
        <a href="javascript:void(0)" onclick="openLogsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          日志
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          退出
        </a>
      </div>
    </div>
  </div>
</header>
<main>
  
    <!-- 当前连接活动节点卡片 -->
    <section class="active-node-section" id="active_node_card" style="margin-bottom: 24px;">
      <!-- Rendered dynamically by render() -->
    </section>



  <section class="toolbar">
    <select id="status_filter">
      <option value="all">全部节点</option>
      <option value="available">可用节点</option>
      <option value="unavailable">失效节点</option>
    </select>
    <select id="country_filter">
      <option value="">所有国家</option>
    </select>
    <select id="ip_type_filter">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="hosting">机房IP</option>
    </select>
    <button id="btn_favorites" class="toolbar-btn" type="button" onclick="toggleFavoritesView()" style="margin-left: auto; height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.907c.961 0 1.371 1.24.588 1.81l-3.97 2.883a1 1 0 00-.364 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.971-2.883a1 1 0 00-1.175 0l-3.97 2.883c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.364-1.118l-3.97-2.883c-.783-.57-.372-1.81.588-1.81h4.906a1 1 0 00.951-.69l1.519-4.674z" />
      </svg>
      收藏菜单
    </button>
    <button id="btn_blacklist" class="toolbar-btn" type="button" onclick="toggleBlacklistView()" style="height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M18.364 5.636l-12.728 12.728M12 3a9 9 0 110 18 9 9 0 010-18z" />
      </svg>
      拉黑菜单
    </button>
  </section>
  <div id="favorites_panel" style="display: none; background: rgba(22, 30, 49, 0.85); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid var(--border-color); border-radius: 16px; padding: 20px; margin-bottom: 20px; animation: modalFadeIn 0.25s ease-out;">
    <div style="display: flex; flex-direction: column; gap: 16px;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div style="display: flex; align-items: flex-start; gap: 12px;">
          <button class="toolbar-btn" type="button" onclick="returnToAllNodes()" style="height: 34px; padding: 0 12px; font-size: 13px;">← 返回</button>
          <div style="display: flex; flex-direction: column; gap: 4px;">
          <span style="font-size: 15px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 6px;">
            ⭐ 收藏管理面板
          </span>
          <span style="font-size: 13px; color: var(--text-secondary);">
            在这里管理收藏节点，以及设置收藏节点全部不可用后的回退策略。
          </span>
          </div>
        </div>
      </div>
      
      <div style="border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px;">
        <label style="display: flex; align-items: flex-start; gap: 10px; cursor: pointer; user-select: none;">
          <input type="checkbox" id="fav_fail_fallback_checkbox" style="margin-top: 3px; cursor: pointer;" onchange="handleFavFallbackChange(this.checked)" checked />
          <div style="display: flex; flex-direction: column; gap: 2px;">
            <span style="font-size: 14px; font-weight: 500; color: var(--text-primary);">全部收藏节点不可用后，自动切换到其他最低延迟可用节点</span>
            <span style="font-size: 12px; color: var(--text-secondary);">勾选后，当收藏节点全部失效且没有收藏节点可切换时，系统会切换到当前批次中延迟最低的非收藏可用节点。</span>
          </div>
        </label>
        <div id="fav_fallback_warning" style="display: none; margin-top: 12px; padding: 10px 14px; background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.25); border-radius: 8px; font-size: 12px; color: var(--danger); line-height: 1.4; animation: modalFadeIn 0.2s ease-out;">
          ⚠️ <strong>警告</strong>：您已取消勾选此项。如果当前收藏的节点全部不可用，系统将不再切换到非收藏节点，并保持当前连接到的不可用节点。
        </div>
      </div>
    </div>
  </div>

  <div id="blacklist_panel" style="display: none; background: rgba(22, 30, 49, 0.85); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid var(--border-color); border-radius: 16px; padding: 20px; margin-bottom: 20px; animation: modalFadeIn 0.25s ease-out;">
    <div style="display: flex; flex-direction: column; gap: 16px;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
        <div style="display: flex; align-items: flex-start; gap: 12px;">
          <button id="btn_blacklist_back" class="toolbar-btn" type="button" onclick="returnToAllNodes()" style="height:34px; padding: 0 12px; font-size: 13px;">← 返回</button>
          <div style="display: flex; flex-direction: column; gap: 4px;">
            <span style="font-size: 15px; font-weight: 600; color: var(--text-primary);">⛔ 拉黑IP管理面板</span>
            <span style="font-size: 13px; color: var(--text-secondary);">被拉黑 IP 的节点会始终显示不可用，检测或更新节点都不会改回可用。</span>
          </div>
        </div>
      </div>
      <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
        <input id="blacklist_ip_input" class="input-field" style="max-width: 280px;" placeholder="输入要搜索或添加的 IP" />
        <button class="toolbar-btn" type="button" onclick="searchBlacklistIp()" style="height: 40px;">搜索</button>
        <button class="toolbar-btn" type="button" onclick="addBlacklistIp()" style="height: 40px; color: var(--danger); border-color: rgba(244,63,94,0.35);">添加</button>
      </div>
      <div id="blacklist_msg" style="display:none; color: var(--danger); font-size: 13px; font-weight: 600;"></div>
      <div id="blacklist_list" style="display: flex; flex-direction: column; gap: 10px;"></div>
    </div>
  </div>

  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 90px;">状态</th>
            <th style="width: 220px;">IP 地址 : 端口</th>
            <th>物理位置</th>
            <th>运营主体 / ISP</th>
            <th style="width: 110px;">IP 类型</th>
            <th style="width: 260px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: none; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

  <!-- Credentials Modal (网页安全设置) -->
  <div id="credentials_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </h3>
        <button type="button" onclick="closeCredentialsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="credentials_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="credentials_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_username">管理账号</label>
          <input type="text" id="cred_username" class="input-field" required placeholder="请输入管理账号">
        </div>
        
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_password">安全密码</label>
          <input type="password" id="cred_password" class="input-field" placeholder="留空则保留当前密码">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_port">网页管理端口</label>
          <input type="number" id="cred_port" class="input-field" required min="1" max="65535" placeholder="8787">
        </div>
        
        <div class="form-group" style="margin-bottom: 20px;">
          <label class="form-label" for="cred_suffix">登录安全后缀 (仅字母和数字)</label>
          <input type="text" id="cred_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeCredentialsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="credentials_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (代理及网络设置，包括出站路由) -->
  <div id="network_modal" class="modal">
    <div class="modal-content" style="max-width: 480px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </h3>
        <button type="button" onclick="closeNetworkModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="network_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="network_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 代理出站端口</label>
          <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" placeholder="7928">
        </div>

        <div style="border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站路由模式</label>
            <input type="hidden" id="net_routing_mode" value="auto">
            <div class="option-group" id="routing_mode_group">
              <div class="option-card active" data-value="auto" onclick="setRoutingMode('auto')">
                <div class="option-card-title">自动配置</div>
                <div class="option-card-desc">智能切换，最稳定</div>
              </div>
              <div class="option-card" data-value="fixed_ip" onclick="setRoutingMode('fixed_ip')">
                <div class="option-card-title">固定 IP</div>
                <div class="option-card-desc">锁定IP，不自动切换</div>
              </div>
              <div class="option-card" data-value="fixed_region" onclick="setRoutingMode('fixed_region')">
                <div class="option-card-title">固定地区</div>
                <div class="option-card-desc">锁定特定国家地区</div>
              </div>
              <div class="option-card" data-value="fixed_favorites" onclick="setRoutingMode('fixed_favorites')">
                <div class="option-card-title">固定收藏菜单</div>
                <div class="option-card-desc">只切换收藏最低延迟</div>
              </div>
            </div>
          </div>
          
          <div id="net_force_country_group" class="form-group" style="margin-bottom: 16px; display: none;">
            <label class="form-label" for="net_force_country">锁定国家地区</label>
            <select id="net_force_country" class="input-field" style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
              <option value="">正在加载节点国家...</option>
            </select>
          </div>
          
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站类型过滤</label>
            <input type="hidden" id="net_routing_ip_type" value="all">
            <div class="option-group" id="routing_ip_type_group">
              <div class="option-card active" data-value="all" onclick="setRoutingIpType('all')">
                <div class="option-card-title">所有IP</div>
                <div class="option-card-desc">机房 + 住宅</div>
              </div>
              <div class="option-card" data-value="residential" onclick="setRoutingIpType('residential')">
                <div class="option-card-title">住宅IP</div>
                <div class="option-card-desc">静态家宽</div>
              </div>
              <div class="option-card" data-value="hosting" onclick="setRoutingIpType('hosting')">
                <div class="option-card-title">机房IP</div>
                <div class="option-card-desc">普通机房</div>
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
            <div class="form-group" style="margin-bottom: 0;">
              <label class="form-label" for="net_latency_check_interval">活动节点巡检间隔</label>
              <select id="net_latency_check_interval" class="input-field" onchange="updateLatencyPolicyWarning()">
                <option value="5">5分钟</option>
                <option value="10">10分钟</option>
                <option value="15">15分钟</option>
                <option value="20">20分钟</option>
                <option value="25">25分钟</option>
                <option value="30" selected>30分钟</option>
                <option value="35">35分钟</option>
                <option value="40">40分钟</option>
                <option value="45">45分钟</option>
                <option value="50">50分钟</option>
                <option value="55">55分钟</option>
                <option value="60">60分钟</option>
              </select>
            </div>
            <div class="form-group" style="margin-bottom: 0;">
              <label class="form-label" for="net_latency_threshold">延迟筛选阈值</label>
              <select id="net_latency_threshold" class="input-field" onchange="updateLatencyPolicyWarning()">
                <option value="200">200ms</option>
                <option value="300">300ms</option>
                <option value="400">400ms</option>
                <option value="500" selected>500ms</option>
                <option value="600">600ms</option>
                <option value="700">700ms</option>
                <option value="800">800ms</option>
                <option value="900">900ms</option>
                <option value="1000">1000ms</option>
              </select>
            </div>
          </div>
          
          <div id="net_routing_warning" style="font-size: 12px; color: var(--text-secondary); line-height: 1.4; padding: 8px 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 6px; margin-top: 8px;">
            ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeNetworkModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="network_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Gateway Modal (网关自检与代理测试) -->
  <div id="gateway_modal" class="modal">
    <div class="modal-content" style="max-width: 600px; width: 90%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置与自检
        </h3>
        <button type="button" onclick="closeGatewayModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- 服务列表 -->
      <div id="gateway_services_list" style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px;">
        <div style="text-align: center; color: var(--text-secondary); padding: 20px 0;">
          <svg style="animation: spin 1s linear infinite; width: 20px; height: 20px; display: inline-block; margin-bottom: 8px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
          <div>正在加载系统网关状态...</div>
        </div>
      </div>

      <!-- 分割线 -->
      <div style="border-top: 1px dashed rgba(255, 255, 255, 0.08); margin: 20px 0;"></div>

      <!-- 本地代理出口检测 -->
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 12px; padding: 16px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
          <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2); width: 36px; height: 36px; border-radius: 8px; flex-shrink: 0;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary); width: 18px; height: 18px;"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
          </div>
          <div>
            <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary);">本地代理出口检测</h4>
            <p style="margin: 2px 0 0 0; font-size: 12px; color: var(--text-secondary);">检测 HTTP/SOCKS5 代理出站连通性与 IP</p>
          </div>
        </div>
        
        <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0, 0, 0, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 13px; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary); text-align: right;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn-primary" style="height: 36px; padding: 0 16px; font-size: 13px;">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            开始检测
          </button>
        </div>
      </div>
      
      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeGatewayModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>

  <!-- Logs Modal (日志监控与分类筛选) -->
  <div id="logs_modal" class="modal">
    <div class="modal-content" style="max-width: 800px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          今日运行日志
        </h3>
        
        <div style="display: flex; align-items: center; gap: 10px; margin-left: auto;">
          <label class="form-label" for="log_filter_select" style="margin: 0; font-size: 13px; color: var(--text-secondary);">日志筛选:</label>
          <select id="log_filter_select" class="input-field" style="width: 140px; height: 32px; font-size: 12px; border-radius: 6px; padding: 0 8px; background: rgba(255, 255, 255, 0.03);" onchange="filterAndRenderLogs()">
            <option value="all">全部日志</option>
            <option value="proxy">代理相关 (Proxy)</option>
            <option value="vpn">VPN 连接 (VPN)</option>
            <option value="system">系统运行 (Main/Route)</option>
          </select>
        </div>
        
        <button type="button" onclick="closeLogsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" style="background: #050811; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 10px; height: 400px; padding: 16px; overflow-y: auto; font-family: 'JetBrains Mono', Consolas, Courier, monospace; font-size: 12px; line-height: 1.5; text-align: left; white-space: pre-wrap; word-break: break-all; color: #a5b4fc; box-shadow: inset 0 4px 20px rgba(0,0,0,0.8); position: relative; margin-bottom: 20px;">
        <div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">
          暂无今日运行日志记录。
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; gap: 8px;">
          <button type="button" onclick="copyLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
            一键复制
          </button>
          <button type="button" onclick="exportLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            导出日志
          </button>
        </div>
        <button type="button" onclick="closeLogsModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>

  <div id="version_update_modal" class="modal">
    <div class="modal-content" style="max-width: 460px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary);">发现新版本</h3>
        <button type="button" onclick="closeVersionUpdateModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      <div style="font-size: 14px; color: var(--text-secondary); line-height: 1.7;">
        <div id="version_update_message">有新的版本发布，可在终端中输入 ml update 命令更新</div>
        <div id="version_update_tag" style="margin-top: 8px; color: var(--text-primary); font-family: 'JetBrains Mono', monospace;"></div>
      </div>
      <div style="margin-top: 18px; padding: 12px; border-radius: 10px; background: rgba(0,0,0,0.25); border: 1px solid var(--border-color); font-family: 'JetBrains Mono', monospace; color: #a5b4fc;">ml update</div>
      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeVersionUpdateModal()" style="height: 38px; padding: 0 20px; font-weight: 600;">取消</button>
      </div>
    </div>
  </div>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set();
let currentPage = 1;
const pageSize = 99999;
let currentPageNodes = [];
let showBlacklistPanel = false;
let blacklistItems = [];
let blacklistSearchActive = false;
let blacklistMsgTimer = null;

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  const dict = {
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
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测", "testing": "测试中<span class=\"testing-dots\"></span>"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (parseInt(ms || 0) < 0) return 'latency-poor';
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function displayLatencyForNode(n, activeNodeId) {
  if (!n) return 0;
  if ((n.active || n.id === activeNodeId) && state.proxy_ok && state.proxy_latency_ms) {
    return parseInt(state.proxy_latency_ms || 0) || 0;
  }
  return parseInt(n.latency_ms || 0) || 0;
}

function latencySortValue(ms) {
  const val = parseInt(ms || 0) || 0;
  return val > 0 ? val : 999999;
}

function latencyCell(ms) {
  const val = parseInt(ms || 0) || 0;
  if (val === -1) {
    return `<span class="latency-val latency-poor">-1</span>`;
  }
  return val ? `<span class="latency-val ${getLatencyClass(val)}">${val} ms</span>` : "-";
}

function riskDisplay(n) {
  return {
    text: "60%",
    cls: "latency-good",
    title: "纯净度过滤已关闭，风险值固定显示 60%"
  };
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => n ? translateCountry(n.country) : "").filter(Boolean))).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions)) {
    return;
  }
  
  select.innerHTML = '<option value="">所有国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function getFilteredNodes() {
  const selectedCountry = $("country_filter").value;
  const selectedIpType = $("ip_type_filter").value;
  const selectedStatus = $("status_filter").value;
  return nodes.filter(n => {
    if (!n) return false;
    if (selectedCountry && translateCountry(n.country) !== selectedCountry) {
      return false;
    }
    if (selectedIpType) {
      if (selectedIpType === "residential" && !["residential", "mobile"].includes(n.ip_type)) {
        return false;
      }
      if (selectedIpType === "hosting" && n.ip_type !== "hosting") {
        return false;
      }
    }
    if (selectedStatus === "available" && n.probe_status !== "available" && !n.active) {
      return false;
    }
    if (selectedStatus === "unavailable" && (n.probe_status !== "unavailable" || n.active)) {
      return false;
    }
    const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
    if (showFavoritesOnly && !favoriteIds.includes(n.id)) {
      return false;
    }
    if (showBlacklistPanel && !n.manual_blacklisted) {
      return false;
    }
    return true;
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if (!a || !b) return 0;
    const activeNodeId = state.active_openvpn_node_id;
    const aLatency = latencySortValue(displayLatencyForNode(a, activeNodeId));
    const bLatency = latencySortValue(displayLatencyForNode(b, activeNodeId));
    if (aLatency !== bLatency) return aLatency - bLatency;
    if ((a.active ? 0 : 1) !== (b.active ? 0 : 1)) return (a.active ? 0 : 1) - (b.active ? 0 : 1);
    if ((a.probe_status === "available" ? 0 : 1) !== (b.probe_status === "available" ? 0 : 1)) {
      return (a.probe_status === "available" ? 0 : 1) - (b.probe_status === "available" ? 0 : 1);
    }
    const aId = a.id || "";
    const bId = b.id || "";
    return aId.localeCompare(bId);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n && (n.active || n.id === activeNodeId));
  const tableHead = document.querySelector(".table-container table thead");
  if (tableHead && tableHead.dataset.extended !== "1") {
    tableHead.innerHTML = `
      <tr>
        <th style="width: 76px;">状态</th>
        <th style="width: 72px;">延迟</th>
        <th style="width: 82px;">风险值</th>
        <th style="width: 190px;">IP 地址 : 端口</th>
        <th>物理位置</th>
        <th style="width: 128px;">ASN</th>
        <th>运营主体 / ISP</th>
        <th style="width: 92px;">网络质量</th>
        <th style="width: 92px;">IP 类型</th>
        <th style="width: 260px;">操作</th>
      </tr>`;
    tableHead.dataset.extended = "1";
  }
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting && !activeNode) {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>正在连接</span>
              <strong>${esc(state.active_node_latency || '正在连接...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const activeLatency = displayLatencyForNode(activeNode, activeNodeId);
    const latencyText = latencyCell(activeLatency);
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(translateCountry(activeNode.country))} 节点</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const shown = getFilteredNodes();
  
  if ($("total")) $("total").textContent = nodes.length; 
  if ($("target")) $("target").textContent = state.target_valid_nodes || 3;
  if ($("active")) $("active").textContent = activeNode ? 1 : 0; 
  
  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  if ($("status")) { $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：${localProxy} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`; }
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  updateFavPanelUI();
  renderBlacklistPanel();

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    const emptyMsg = showBlacklistPanel
      ? "当前主节点列表中没有命中的拉黑节点，可在上方拉黑菜单中查看或管理持久拉黑 IP。"
      : (showFavoritesOnly ? "未找到符合过滤条件的收藏节点。" : "未找到符合过滤条件的备选节点。");
    $("rows").innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">${emptyMsg}</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      if (!n) return '';
      const isManualBlacklisted = !!n.manual_blacklisted;
      const isCurrentlyActive = activeNode && n.id === activeNode.id && !isManualBlacklisted;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isManualBlacklisted ? 'unavailable' : (isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked'));
      const badgeText = isManualBlacklisted ? '不可用' : (isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status));
      const displayLatency = displayLatencyForNode(n, activeNodeId);
      const latencyText = latencyCell(displayLatency);
      const displayLocation = n.location || translateCountry(n.country) || "-";
      const displayAsn = n.asn || "-";
      const displayQuality = {"normal": "普通", "proxy": "代理", "datacenter": "机房", "mobile": "移动"}[n.quality] || translateQuality(n.quality);
      const risk = riskDisplay(n);
      
      const isTesting = testingNodeIds.has(n.id);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = isManualBlacklisted || n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${(isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">切换</button>`;
      
      const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
      const isFav = favoriteIds.includes(n.id);
      const favoriteDisabled = !isFav && (isManualBlacklisted || n.probe_status !== "available");
      const favBtn = isFav
        ? `<button class="test-btn" style="color: var(--warning); border-color: rgba(245, 158, 11, 0.4); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">★ 已收藏</button>`
        : (favoriteDisabled
        ? `<button class="test-btn" disabled style="color: var(--text-secondary); border-color: var(--border-color); opacity: 0.45; padding: 0 8px; height: 30px; cursor:not-allowed;">☆ 不可收藏</button>`
        : `<button class="test-btn" style="color: var(--text-secondary); border-color: var(--border-color); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">☆ 收藏</button>`);

      const blacklistBtn = n.manual_blacklisted
        ? `<button class="test-btn" disabled style="color: var(--danger); border-color: rgba(244,63,94,0.4); opacity: 0.8; padding: 0 8px; height: 30px;">已拉黑</button>`
        : isFav
        ? `<button class="test-btn" disabled style="color: var(--text-secondary); border-color: var(--border-color); opacity: 0.45; padding: 0 8px; height: 30px; cursor:not-allowed;">拉黑</button>`
        : `<button class="test-btn" style="color: var(--danger); border-color: rgba(244,63,94,0.35); padding: 0 8px; height: 30px;" onclick="blacklistNode('${esc(n.id)}', event)">拉黑</button>`;

      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td>${latencyText}</td>
        <td title="${esc(risk.title)}">${risk.text === "-" ? "-" : `<span class="latency-val ${risk.cls}">${esc(risk.text)}</span>`}</td>
        <td class="mono" style="white-space: nowrap; max-width: 190px; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.ip||n.remote_host)}:${n.remote_port||""}">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(displayLocation)}">${esc(displayLocation)}</td>
        <td class="mono" style="white-space: normal; max-width: 128px; overflow-wrap: anywhere;" title="${esc(displayAsn)}">${esc(displayAsn)}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.owner||n.as_name||"-")}">${esc(n.owner||n.as_name||"-")}</td>
        <td style="white-space: nowrap; max-width: 92px; overflow: hidden; text-overflow: ellipsis;" title="${esc((n.purity_reasons || []).join('; '))}">${esc(displayQuality)}</td>
        <td style="white-space: nowrap; max-width: 92px; overflow: hidden; text-overflow: ellipsis;" title="${esc(translateIpType(n.ip_type))}">${esc(translateIpType(n.ip_type))}</td>
        <td>
          <div class="table-actions">
            ${testBtn}
            ${blacklistBtn}
            ${favBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();
  
  try {
    const response = await fetch("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n && n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
        if (result.node.probe_status !== "available" || result.node.manual_blacklisted) {
          state.favorite_node_ids = (Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : []).filter(x => x !== id);
        }
        stableSortNodes();
      }
    }
  } catch (e) {
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

async function toggleFavorite(id, event) {
  if (event) event.stopPropagation();
  try {
    const response = await fetch("./api/toggle_favorite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok) {
      state.favorite_node_ids = Array.isArray(result.favorite_node_ids) ? result.favorite_node_ids : [];
      if (Array.isArray(result.removed_node_ids) && result.removed_node_ids.length) {
        const removed = new Set(result.removed_node_ids);
        nodes = nodes.filter(n => n && !removed.has(n.id));
      }
      render();
    } else {
      showBlacklistMessage(result.error || "该节点当前不能收藏");
      await load();
    }
  } catch (e) {
    console.error("切换收藏失败", e);
  }
}

async function blacklistNode(nodeId, event) {
  if (event) event.stopPropagation();
  const targetNodeId = String(nodeId || "").trim();
  const targetNode = nodes.find(n => n && n.id === targetNodeId);
  if (!targetNode) {
    showBlacklistMessage("无法识别节点IP");
    return;
  }
  try {
    const response = await fetch("./api/manual_blacklist_add", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({node_id: targetNodeId})
    });
    const result = await response.json();
    if (!result.ok) {
      showBlacklistMessage(result.error || "拉黑失败");
      return;
    }
    blacklistItems = Array.isArray(result.items) ? result.items : [];
    await load();
  } catch(e) {
    showBlacklistMessage("拉黑失败");
  }
}

let pollInterval = null;

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch("./api/nodes");
      const data = await resp.json();
      nodes = Array.isArray(data.nodes) ? data.nodes : [];
      state = data.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();
      
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          await fetch("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function connectNode(id){
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  startConnectionPolling();
  
  try {
    const r = await fetch("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}





async function loadManualBlacklist(search = "") {
  const url = search ? `./api/manual_blacklist?search=${encodeURIComponent(search)}` : "./api/manual_blacklist";
  const response = await fetch(url);
  const data = await response.json();
  if (data.ok) {
    blacklistItems = Array.isArray(data.items) ? data.items : [];
    blacklistSearchActive = !!search;
    if (data.not_found) {
      showBlacklistMessage("没有这个IP");
    }
  }
}

async function load(){
  const r=await fetch("./api/nodes"); 
  const d=await r.json(); 
  nodes=Array.isArray(d.nodes) ? d.nodes : []; 
  state=d.state||{}; 
  if (showBlacklistPanel) {
    try { await loadManualBlacklist(blacklistSearchActive ? ($("blacklist_ip_input")?.value || "") : ""); } catch(e) {}
  }
  
  stableSortNodes();
  updateCountryFilter();
  render();

  if (state.is_connecting) {
    startConnectionPolling();
  }
}

function closeVersionUpdateModal() {
  const modal = $("version_update_modal");
  if (modal) modal.style.display = "none";
}

async function checkVersionNotice() {
  try {
    const res = await fetch("./api/version_check");
    if (!res.ok) return;
    const data = await res.json();
    if (!data || !data.show_notice) return;
    const msg = $("version_update_message");
    const tag = $("version_update_tag");
    if (msg) msg.textContent = data.message || "有新的版本发布，可在终端中输入 ml update 命令更新";
    if (tag) tag.textContent = data.latest_tag ? `最新版本: ${data.latest_tag}` : "";
    const modal = $("version_update_modal");
    if (modal) modal.style.display = "flex";
  } catch (e) {}
}
$("country_filter").onchange=()=>{ currentPage = 1; render(); };
$("ip_type_filter").onchange=()=>{ currentPage = 1; render(); };
$("status_filter").onchange=()=>{ currentPage = 1; render(); };

$("refresh").onclick=async()=>{ 
  $("refresh").disabled=true; 
  $("refresh").textContent="正在后台更新..."; 
  try{
    await fetch("./api/refresh_nodes",{method:"POST"});
    state.is_connecting = true;
    startConnectionPolling();
    await load();
  } 
  catch(e){}
  setTimeout(()=>{
    $("refresh").disabled=false; 
    $("refresh").textContent="更新节点";
  }, 3000);
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// Admin dropdown toggle & GitHub dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");
const githubBtn = $("github_btn");
const githubDropdown = $("github_dropdown");

if (adminBtn && adminDropdown) {
  adminBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = adminDropdown.style.display === "block";
    adminDropdown.style.display = isShow ? "none" : "block";
    if (githubDropdown) githubDropdown.style.display = "none";
  };
}

if (githubBtn && githubDropdown) {
  githubBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = githubDropdown.style.display === "block";
    githubDropdown.style.display = isShow ? "none" : "block";
    if (adminDropdown) adminDropdown.style.display = "none";
  };
}

document.addEventListener("click", () => {
  if (adminDropdown) adminDropdown.style.display = "none";
  if (githubDropdown) githubDropdown.style.display = "none";
});

let showFavoritesOnly = false;

function showBlacklistMessage(msg) {
  const el = $("blacklist_msg");
  if (!el) return;
  el.textContent = msg;
  el.style.display = "block";
  if (blacklistMsgTimer) clearTimeout(blacklistMsgTimer);
  blacklistMsgTimer = setTimeout(() => {
    el.style.display = "none";
  }, 2200);
}

function returnToAllNodes() {
  showFavoritesOnly = false;
  showBlacklistPanel = false;
  blacklistSearchActive = false;
  if ($("blacklist_ip_input")) $("blacklist_ip_input").value = "";
  if ($("status_filter")) $("status_filter").value = "all";
  if ($("country_filter")) $("country_filter").value = "";
  if ($("ip_type_filter")) $("ip_type_filter").value = "";
  currentPage = 1;
  render();
}

async function toggleBlacklistView() {
  if (showBlacklistPanel) {
    return;
  }
  showBlacklistPanel = !showBlacklistPanel;
  if (showBlacklistPanel) {
    showFavoritesOnly = false;
    blacklistSearchActive = false;
    if ($("blacklist_ip_input")) $("blacklist_ip_input").value = "";
    try { await loadManualBlacklist(); } catch(e) { showBlacklistMessage("加载拉黑列表失败"); }
  }
  currentPage = 1;
  render();
}

function renderBlacklistPanel() {
  const panel = $("blacklist_panel");
  if (!panel) return;
  panel.style.display = showBlacklistPanel ? "block" : "none";

  const btn = $("btn_blacklist");
  if (btn) {
    if (showBlacklistPanel) btn.classList.add("active");
    else btn.classList.remove("active");
  }

  const list = $("blacklist_list");
  if (!list) return;
  if (!blacklistItems.length) {
    if (blacklistSearchActive) {
      list.innerHTML = "";
      return;
    }
    list.innerHTML = `<div style="padding: 24px; text-align:center; color: var(--text-secondary); border: 1px dashed var(--border-color); border-radius: 10px;">没有拉黑 IP</div>`;
    return;
  }
  list.innerHTML = blacklistItems.map(item => {
    const ip = item.ip || "";
    return `<div style="display:flex; align-items:center; justify-content:space-between; gap:12px; padding:12px 14px; border:1px solid var(--border-color); border-radius:10px; background:rgba(255,255,255,0.03);">
      <div style="display:flex; flex-direction:column; gap:4px;">
        <span class="mono" style="font-size:14px; color:var(--text-primary);">${esc(ip)}</span>
        <span style="font-size:12px; color:var(--text-secondary);">添加时间：${time(item.added_at)}</span>
      </div>
      <button class="test-btn" style="color: var(--success); border-color: rgba(16,185,129,0.35); padding: 0 10px; height: 30px;" onclick="removeBlacklistIp('${esc(ip)}', event)">取消拉黑</button>
    </div>`;
  }).join("");
}

async function searchBlacklistIp() {
  const input = $("blacklist_ip_input");
  const ip = input ? input.value.trim() : "";
  if (!ip) {
    blacklistSearchActive = false;
    await loadManualBlacklist();
  } else {
    await loadManualBlacklist(ip);
  }
  renderBlacklistPanel();
}

async function resetBlacklistSearch() {
  blacklistSearchActive = false;
  if ($("blacklist_ip_input")) $("blacklist_ip_input").value = "";
  await loadManualBlacklist();
  renderBlacklistPanel();
}

async function addBlacklistIp() {
  const input = $("blacklist_ip_input");
  const ip = input ? input.value.trim() : "";
  if (!ip) {
    showBlacklistMessage("请输入IP");
    return;
  }
  try {
    const response = await fetch("./api/manual_blacklist_add", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ip})
    });
    const result = await response.json();
    if (!result.ok) {
      showBlacklistMessage(result.error || "添加失败");
      return;
    }
    blacklistSearchActive = false;
    if (input) input.value = "";
    blacklistItems = Array.isArray(result.items) ? result.items : [];
    await load();
  } catch(e) {
    showBlacklistMessage("添加失败");
  }
}

async function removeBlacklistIp(ip, event) {
  if (event) event.stopPropagation();
  try {
    const response = await fetch("./api/manual_blacklist_remove", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ip})
    });
    const result = await response.json();
    if (!result.ok) {
      showBlacklistMessage(result.error || "取消失败");
      return;
    }
    blacklistItems = Array.isArray(result.items) ? result.items : [];
    await load();
  } catch(e) {
    showBlacklistMessage("取消失败");
  }
}

function toggleFavoritesView() {
  if (showFavoritesOnly) {
    return;
  }
  showFavoritesOnly = !showFavoritesOnly;
  if (showFavoritesOnly) showBlacklistPanel = false;
  currentPage = 1;
  render();
}

function updateFavPanelUI() {
  const panel = $("favorites_panel");
  if (!panel) return;
  panel.style.display = showFavoritesOnly ? "block" : "none";
  
  const btn = $("btn_favorites");
  if (btn) {
    if (showFavoritesOnly) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }

  if (showFavoritesOnly && state) {
    const fallbackCheckbox = $("fav_fail_fallback_checkbox");
    if (fallbackCheckbox) {
      fallbackCheckbox.checked = !!state.fav_fail_fallback;
    }
    
    const warningDiv = $("fav_fallback_warning");
    if (warningDiv) {
      warningDiv.style.display = state.fav_fail_fallback ? "none" : "block";
    }

  }
}

async function handleFavFallbackChange(checked) {
  if (!state) return;
  
  if (!checked) {
    alert("⚠️ 警告：不勾选此项可能在所有收藏节点失效时造成网络彻底断开连接，无法自动切换到其他非收藏的可用节点！");
  }
  
  state.fav_fail_fallback = checked;
  updateFavPanelUI();
  
  try {
    const res = await fetch("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: state.routing_mode || "auto",
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all",
        fav_fail_fallback: checked
      })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      load();
    } else {
      alert("更新失败: " + (data.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败，请稍后重试");
    load();
  }
}

function selectOptionCard(groupName, value) {
  if (groupName === 'routing_mode') {
    const input = $("net_routing_mode");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_mode_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
    
    handleRoutingModeChange(value);
  } else if (groupName === 'routing_ip_type') {
    const input = $("net_routing_ip_type");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_ip_type_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  }
}

function setRoutingMode(value) {
  selectOptionCard('routing_mode', value);
}

function setRoutingIpType(value) {
  selectOptionCard('routing_ip_type', value);
}

function latencyPolicyValues() {
  const intervalEl = $("net_latency_check_interval");
  const thresholdEl = $("net_latency_threshold");
  return {
    interval: parseInt(intervalEl ? intervalEl.value : 30) || 30,
    threshold: parseInt(thresholdEl ? thresholdEl.value : 500) || 500
  };
}

function updateLatencyPolicyWarning() {
  const modeInput = $("net_routing_mode");
  handleRoutingModeChange(modeInput ? modeInput.value : "auto");
}

function handleRoutingModeChange(mode) {
  const countryGroup = $("net_force_country_group");
  const warningDiv = $("net_routing_warning");
  const policy = latencyPolicyValues();
  
  if (mode === "fixed_region") {
    countryGroup.style.display = "block";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定地区</strong>：限制仅连接选定国家的节点，并按当前 IP 类型过滤测速。后台每 ${policy.interval} 分钟检测当前活动节点，延迟超过 ${policy.threshold}ms 时会拉取新节点、新旧合并测速排序，并只保留符合阈值的节点。`;
  } else if (mode === "favorites") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>仅用收藏</strong>：只连接和切换您收藏的节点。如果所有收藏的节点均失效，系统不会自动切换到未收藏的节点。请确保收藏列表中有足够多且可用的节点。`;
  } else if (mode === "fixed_favorites") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定收藏菜单</strong>：只在收藏节点范围内测速排序，并切换到延迟最低的收藏节点。后台每 ${policy.interval} 分钟检测当前活动节点，延迟超过 ${policy.threshold}ms 时会重新测速排序；收藏全部不可用时是否回退到非收藏节点，由收藏管理面板的回退选项决定。`;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定IP</strong>：锁定当前连接的节点。不管该节点是否失效，系统都绝不自动切换至其他IP；如果节点由于网络故障失效，会造成代理中断（但如果OpenVPN连接意外退出，脚本将尝试为您在后台重新拉起连接同一IP）。<br><strong>提示</strong>：您可以在主页 of 节点列表中直接点击“连接”按钮来选择并锁定不同的IP节点。`;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "rgba(255, 255, 255, 0.02)";
    warningDiv.style.border = "1px solid rgba(255, 255, 255, 0.05)";
    warningDiv.innerHTML = `ℹ️ <strong>自动配置</strong>：后台每 ${policy.interval} 分钟检测当前活动节点；延迟超过 ${policy.threshold}ms 时会拉取新节点、新旧合并测速排序，剔除超过阈值的普通节点，并切换到最低延迟可用节点。`;
  }
}

function populateRoutingCountries() {
  const select = $("net_force_country");
  if (!select) return;
  const countMap = {};
  nodes.forEach(n => {
    const c = translateCountry(n.country);
    if (c) {
      countMap[c] = (countMap[c] || 0) + 1;
    }
  });
  
  const countries = Object.keys(countMap).sort();
  let html = '<option value="">请选择要锁定的国家...</option>';
  countries.forEach(c => {
    html += `<option value="${esc(c)}">${esc(c)} (${countMap[c]}个节点)</option>`;
  });
  select.innerHTML = html;
  
  if (state) {
    select.value = state.force_country ? translateCountry(state.force_country) : "";
  }
}

function openCredentialsModal() {
  $("credentials_error").style.display = "none";
  $("credentials_success").style.display = "none";
  $("credentials_form").reset();
  if (state) {
    $("cred_username").value = state.username || "";
    $("cred_password").value = "";
    $("cred_port").value = state.port || 8787;
    $("cred_suffix").value = state.secret_path || "";
  }
  $("credentials_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeCredentialsModal() {
  $("credentials_modal").style.display = "none";
}

async function saveCredentials(e) {
  e.preventDefault();
  const errorDivEl = $("credentials_error");
  const successDiv = $("credentials_success");
  const submitBtn = $("credentials_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const username = $("cred_username").value.trim();
  const password = $("cred_password").value.trim();
  const port = parseInt($("cred_port").value);
  const suffix = $("cred_suffix").value.trim();
  
  if (!username || (!password && !(state && state.password_set))) {
    errorDivEl.textContent = "用户名不能为空；首次设置时密码不能为空";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "网页管理端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (state && port === state.proxy_port) {
    errorDivEl.textContent = "网页管理端口不能与代理出站端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        password: password,
        port: port,
        secret_path: suffix
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！网页管理端口或路径已变更，页面将在 4 秒内自动跳转...";
        successDiv.style.display = "block";
        
        const inputs = $("credentials_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          const protocol = window.location.protocol;
          const host = window.location.hostname;
          window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
        }, 4000);
      } else {
        successDiv.textContent = data.reauth_required ? "账号密码保存成功，请重新登录..." : "账号密码保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          if (data.reauth_required) {
            window.location.reload();
          } else {
            closeCredentialsModal();
            load();
          }
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

function openNetworkModal() {
  $("network_error").style.display = "none";
  $("network_success").style.display = "none";
  $("network_form").reset();
  
  if (state) {
    $("net_proxy_port").value = state.proxy_port || 7928;
    $("net_latency_check_interval").value = state.latency_check_interval_minutes || 30;
    $("net_latency_threshold").value = state.latency_threshold_ms || 500;
    const mode = state.routing_mode || "auto";
    const ipType = state.routing_ip_type || "all";
    
    selectOptionCard('routing_mode', mode);
    selectOptionCard('routing_ip_type', ipType);
  }
  
  populateRoutingCountries();
  $("network_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeNetworkModal() {
  $("network_modal").style.display = "none";
}

async function saveNetwork(e) {
  e.preventDefault();
  const errorDivEl = $("network_error");
  const successDiv = $("network_success");
  const submitBtn = $("network_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const proxyPort = parseInt($("net_proxy_port").value);
  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  const routingIpType = $("net_routing_ip_type").value;
  const latencyCheckInterval = parseInt($("net_latency_check_interval").value);
  const latencyThreshold = parseInt($("net_latency_threshold").value);
  
  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    errorDivEl.textContent = "代理出站端口范围必须在 1024 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (state && proxyPort === state.port) {
    errorDivEl.textContent = "代理出站端口不能与网页管理端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "请选择一个要锁定的目标国家";
    errorDivEl.style.display = "block";
    return;
  }

  if (![5,10,15,20,25,30,35,40,45,50,55,60].includes(latencyCheckInterval)) {
    errorDivEl.textContent = "活动节点巡检间隔无效";
    errorDivEl.style.display = "block";
    return;
  }

  if (![200,300,400,500,600,700,800,900,1000].includes(latencyThreshold)) {
    errorDivEl.textContent = "延迟筛选阈值无效";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proxy_port: proxyPort,
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType,
        latency_check_interval_minutes: latencyCheckInterval,
        latency_threshold_ms: latencyThreshold
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！代理出站端口已变更，页面将在 4 秒内自动刷新...";
        successDiv.style.display = "block";
        
        const inputs = $("network_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          window.location.reload();
        }, 4000);
      } else {
        successDiv.textContent = "配置保存成功，已即时生效！";
        successDiv.style.display = "block";
        if (data.routing_refresh_started) {
          state.is_connecting = true;
          startConnectionPolling();
        }
        setTimeout(() => {
          closeNetworkModal();
          load();
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}


async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load().then(checkVersionNotice).catch(() => {});

// 每 10 秒在前台自动更新节点与状态。后台刷新时也继续轮询，便于显示“测试中...”。
setInterval(async () => {
  if (typeof state !== "undefined" && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const r = await fetch("./api/nodes");
      const d = await r.json();
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();
    } catch(e) {}
  }
}, 10000);
let gatewayPollInterval = null;

function openGatewayModal() {
  $("admin_dropdown").style.display = "none";
  $("gateway_modal").style.display = "flex";
  loadGatewayStatus();
  if (gatewayPollInterval) clearInterval(gatewayPollInterval);
  gatewayPollInterval = setInterval(loadGatewayStatus, 3000);
}

function closeGatewayModal() {
  $("gateway_modal").style.display = "none";
  if (gatewayPollInterval) {
    clearInterval(gatewayPollInterval);
    gatewayPollInterval = null;
  }
}

async function loadGatewayStatus() {
  try {
    const res = await fetch("./api/gateway_status");
    const data = await res.json();
    if (data.ok && data.services) {
      renderGatewayServices(data.services);
    }
  } catch (e) {
    console.error("加载网关状态失败", e);
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;
  
  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "正在运行" : "已停止";
    const badgeClass = s.status === "running" ? "available" : "unavailable";
    const statusPulse = s.status === "running" ? '<span class="badge-pulse"></span>' : '';
    
    html += `
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 14px; color: var(--text-primary);">${esc(s.name)}</strong>
          <span class="badge ${badgeClass}">${statusPulse}${statusText}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);">${esc(s.details || "-")}</div>
        ${s.error ? `
          <div style="font-size: 12px; color: var(--danger); background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.15); border-radius: 6px; padding: 6px 10px; margin-top: 4px; line-height: 1.4;">
            ⚠️ 诊断原因: ${esc(s.error)}
          </div>
        ` : ''}
      </div>
    `;
  });
  container.innerHTML = html;
}

let logsPollInterval = null;
let rawLogsCache = [];

function openLogsModal() {
  $("admin_dropdown").style.display = "none";
  $("logs_modal").style.display = "flex";
  loadLogs();
  if (logsPollInterval) clearInterval(logsPollInterval);
  logsPollInterval = setInterval(loadLogs, 2500);
}

function closeLogsModal() {
  $("logs_modal").style.display = "none";
  if (logsPollInterval) {
    clearInterval(logsPollInterval);
    logsPollInterval = null;
  }
}

async function loadLogs() {
  try {
    const res = await fetch("./api/logs");
    const data = await res.json();
    if (data.logs) {
      rawLogsCache = data.logs;
      filterAndRenderLogs();
    }
  } catch (e) {
    console.error("加载日志失败", e);
  }
}

function filterAndRenderLogs() {
  const filterVal = $("log_filter_select").value;
  const term = $("log_terminal_container");
  if (!term) return;
  
  let filtered = rawLogsCache;
  if (filterVal === "proxy") {
    filtered = rawLogsCache.filter(l => l.module === "Proxy");
  } else if (filterVal === "vpn") {
    filtered = rawLogsCache.filter(l => l.module === "VPN");
  } else if (filterVal === "system") {
    filtered = rawLogsCache.filter(l => !["Proxy", "VPN"].includes(l.module));
  }
  
  if (filtered.length === 0) {
    term.innerHTML = `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">暂无该类型日志。</div>`;
    return;
  }
  
  const linesHtml = filtered.map(l => {
    let color = "#a5b4fc";
    if (l.module === "Proxy") color = "#38bdf8";
    if (l.module === "VPN") color = "#34d399";
    if (l.level === "WARNING") color = "#fbbf24";
    if (l.level === "ERROR") color = "#f43f5e";
    
    return `<div style="color: ${color}; margin-bottom: 4px;">[${esc(l.timestamp)}] [${esc(l.level)}] [${esc(l.module)}] ${esc(l.message)}</div>`;
  }).join("");
  
  const isAtBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 50;
  
  term.innerHTML = linesHtml;
  
  if (isAtBottom) {
    term.scrollTop = term.scrollHeight;
  }
}

function copyLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供复制的日志。");
    return;
  }
  
  navigator.clipboard.writeText(text).then(() => {
    alert("日志内容已成功复制到剪贴板！");
  }).catch(err => {
    console.error("复制失败", err);
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("日志内容已复制到剪贴板！");
  });
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供导出的日志。");
    return;
  }
  
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const dateStr = new Date().toISOString().slice(0, 10);
  const filterVal = $("log_filter_select").value;
  a.download = `vpngate_log_${filterVal}_${dateStr}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
            cmd = [
                "curl", "-s",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "5"
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    lines = res.stdout.strip().splitlines()
                    if len(lines) >= 2:
                        ip = lines[0].strip()
                        time_info = lines[1].strip().split()
                        if len(time_info) == 2:
                            total_time_str, http_code = time_info
                            if http_code == "200" and ip:
                                latency_ms = int(float(total_time_str) * 1000)
                                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                pass
        return None

    try:
        result = _curl_check_ip("http://ip.sb")
        if result:
            return result
        result = _curl_check_ip("http://api.ipify.org")
        if result:
            return result
            
        # 此时外网测试失败，检测本地代理端口是否依然能连通。若仍能连通，直接抛出出口测试失败，不调用占用诊断
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}
            
        return {"ok": False, "error": "出口连接测试失败 (ip.sb 和 api.ipify.org 均无法连通，可能是节点已失效或 VPS 防火墙限制了 UDP/TCP 出站端口)"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting
    time.sleep(30)
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue
            if enforce_active_not_manual_blacklisted():
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                if enforce_active_not_manual_blacklisted():
                    time.sleep(5)
                    continue
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "未知错误")
                if active_openvpn_node_id:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"代理不可用: {error_msg}")
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                # If we intended to have an active VPN node but proxy failed, trigger auto-switch
                if active_openvpn_node_id:
                    ui_cfg = load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        with lock:
                            nodes = read_nodes()
                            active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                            if active_node:
                                mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                                cleanup_favorite_node_ids(nodes)
                        auto_switch_node()
                    else:
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {active_openvpn_node_id}", flush=True)
                        is_connecting = False
                        try:
                            connect_node(active_openvpn_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global last_pinger_heartbeat
    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                state = read_json(STATE_FILE, {})
                latency = parse_int(state.get("proxy_latency_ms"))
                if state.get("proxy_ok") and latency > 0:
                    set_state(active_node_latency=f"{latency} ms")
                else:
                    set_state(active_node_latency="等待出口检测")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)

def fixed_region_latency_guard() -> None:
    time.sleep(60)
    while True:
        try:
            ui_cfg = wait_latency_check_interval()
            if ui_cfg.get("routing_mode") != "fixed_region":
                continue
            if not ui_cfg.get("connection_enabled", True):
                continue
            if is_connecting or not active_openvpn_node_id or not active_openvpn_running():
                continue
            if enforce_active_not_manual_blacklisted():
                continue

            result = check_proxy_health()
            if not result.get("ok"):
                continue
            latency = parse_int(result.get("latency_ms"))
            latency_threshold = get_latency_threshold_ms(ui_cfg)
            set_state(proxy_ok=True, proxy_ip=result.get("ip", ""), proxy_latency_ms=latency, proxy_error="")
            if latency <= latency_threshold:
                continue

            interval_minutes = get_latency_check_interval_minutes(ui_cfg)
            reason = f"固定地区 {interval_minutes} 分钟巡检发现当前节点真实出口延迟 {latency} ms > {latency_threshold} ms"
            print(f"[固定地区延迟巡检] {reason}", flush=True)
            log_to_json("WARNING", "VPN", reason)
            with lock:
                nodes = read_nodes()
                active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if active_node:
                    mark_blacklisted(active_node, reason)
                    active_node["probe_status"] = "unavailable"
                    active_node["probe_message"] = reason
                    active_node["latency_ms"] = latency
                    write_json(NODES_FILE, sort_all_nodes(nodes))
                    cleanup_favorite_node_ids(nodes)

            before_id = active_openvpn_node_id
            refresh_and_switch_fixed_region(reason)
            after_id = active_openvpn_node_id
            if before_id and after_id == before_id:
                log_node_activity("STALL", f"Latency exceeded threshold but fixed_region did not switch; reason={reason}", active_node)
        except Exception as exc:
            print(f"[固定地区延迟巡检] 执行异常: {exc}", flush=True)
            log_to_json("ERROR", "VPN", f"固定地区延迟巡检异常: {exc}")

def fixed_favorites_latency_guard() -> None:
    time.sleep(60)
    while True:
        try:
            ui_cfg = wait_latency_check_interval()
            if ui_cfg.get("routing_mode") != "fixed_favorites":
                continue
            if not ui_cfg.get("connection_enabled", True):
                continue
            if is_connecting or not active_openvpn_node_id or not active_openvpn_running():
                continue
            if enforce_active_not_manual_blacklisted():
                continue

            result = check_proxy_health()
            if not result.get("ok"):
                continue
            latency = parse_int(result.get("latency_ms"))
            latency_threshold = get_latency_threshold_ms(ui_cfg)
            set_state(proxy_ok=True, proxy_ip=result.get("ip", ""), proxy_latency_ms=latency, proxy_error="")
            if latency <= latency_threshold:
                continue

            interval_minutes = get_latency_check_interval_minutes(ui_cfg)
            reason = f"固定收藏菜单 {interval_minutes} 分钟巡检发现当前节点真实出口延迟 {latency} ms > {latency_threshold} ms"
            print(f"[固定收藏延迟巡检] {reason}", flush=True)
            log_to_json("WARNING", "VPN", reason)
            with lock:
                nodes = read_nodes()
                active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if active_node:
                    mark_blacklisted(active_node, reason)
                    active_node["probe_status"] = "unavailable"
                    active_node["probe_message"] = reason
                    active_node["latency_ms"] = latency
                    write_json(NODES_FILE, sort_all_nodes(nodes))
                    cleanup_favorite_node_ids(nodes)

            before_id = active_openvpn_node_id
            refresh_and_switch_fixed_favorites(reason)
            after_id = active_openvpn_node_id
            if before_id and after_id == before_id:
                log_node_activity("STALL", f"Latency exceeded threshold but fixed_favorites did not switch; reason={reason}", active_node)
        except Exception as exc:
            print(f"[固定收藏延迟巡检] 执行异常: {exc}", flush=True)
            log_to_json("ERROR", "VPN", f"固定收藏延迟巡检异常: {exc}")

def active_latency_refresh_guard() -> None:
    time.sleep(60)
    while True:
        try:
            ui_cfg = wait_latency_check_interval()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites", "fixed_favorites"):
                continue
            if not ui_cfg.get("connection_enabled", True):
                continue
            if is_connecting or not active_openvpn_node_id or not active_openvpn_running():
                continue

            result = check_proxy_health()
            if not result.get("ok"):
                continue
            latency = parse_int(result.get("latency_ms"))
            latency_threshold = get_latency_threshold_ms(ui_cfg)
            set_state(proxy_ok=True, proxy_ip=result.get("ip", ""), proxy_latency_ms=latency, proxy_error="")
            if latency <= latency_threshold:
                continue

            interval_minutes = get_latency_check_interval_minutes(ui_cfg)
            reason = f"{routing_mode} mode {interval_minutes}m active node egress latency {latency} ms > {latency_threshold} ms"
            print(f"[活动节点延迟巡检] {reason}", flush=True)
            log_to_json("WARNING", "VPN", reason)
            before_id = active_openvpn_node_id
            active_node = None
            try:
                active_node = next((n for n in read_nodes() if n.get("id") == before_id), None) if before_id else None
            except Exception:
                active_node = None
            refresh_test_prune_and_maybe_switch(reason)
            after_id = active_openvpn_node_id
            if before_id and after_id == before_id and routing_mode != "fixed_ip":
                log_node_activity("STALL", f"Latency exceeded threshold but active node did not switch; reason={reason}", active_node)
        except Exception as exc:
            print(f"[活动节点延迟巡检] 执行异常: {exc}", flush=True)
            log_to_json("ERROR", "VPN", f"活动节点延迟巡检异常: {exc}")

def node_activity_logger_loop() -> None:
    last_seen_node_id = None
    connecting_since = None
    last_stall_log = 0.0
    last_process_error_log = 0.0
    while True:
        try:
            state = read_json(STATE_FILE, {})
            current_id = active_openvpn_node_id or str(state.get("active_openvpn_node_id") or "")
            nodes = read_nodes()
            current_node = next((n for n in nodes if n.get("id") == current_id), None) if current_id else None

            if current_id != last_seen_node_id:
                if current_id:
                    log_node_activity("CURRENT_NODE", "Current active node changed", current_node)
                elif last_seen_node_id:
                    log_node_activity("DISCONNECTED", f"Active node cleared from {last_seen_node_id}")
                last_seen_node_id = current_id

            if current_id and not active_openvpn_running():
                now = time.time()
                if now - last_process_error_log >= 60:
                    log_node_activity(
                        "ERROR",
                        f"State has active node {current_id}, but OpenVPN process is not running",
                        current_node,
                    )
                    last_process_error_log = now

            if is_connecting:
                if connecting_since is None:
                    connecting_since = time.time()
                elapsed = time.time() - connecting_since
                if elapsed > max(120, OPENVPN_TEST_TIMEOUT_SECONDS * 2) and time.time() - last_stall_log >= 60:
                    log_node_activity(
                        "STALL",
                        f"Connection or latency test has been running for {int(elapsed)}s without completing; last_message={state.get('last_check_message', '')}",
                        current_node,
                    )
                    last_stall_log = time.time()
            else:
                connecting_since = None
        except Exception as exc:
            log_node_activity("ERROR", "node_activity_logger_loop failed", exc=exc)
        time.sleep(10)

class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            trigger_login_refresh_if_needed()
            enforce_active_not_manual_blacklisted()
            nodes = read_nodes()
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = (active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path == "/api/version_check":
            self.send_json(check_version_notice())
        elif effective_path == "/api/manual_blacklist":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            search = query.get("search", [""])[0]
            entries = manual_blacklist_entries(search)
            self.send_json({
                "ok": True,
                "items": entries,
                "count": len(entries),
                "search": search,
                "not_found": bool(search and not entries),
            })
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_nodes()
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {load_ui_config().get('host', UI_HOST)}:{load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "未连接"
            if ovpn_ok:
                ovpn_details = f"已连接节点: {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    if not Path("/sys/class/net/tun0").exists():
                        ovpn_err = "[警告] 虚拟网卡 (tun0) 未启用，可能存在策略路由配置问题。"
            else:
                if active_openvpn_node_id:
                    ovpn_err = "连接已中断或 OpenVPN 核心程序异常退出。"
                    ovpn_details = f"尝试连接节点 {active_openvpn_node_id} 失败"
            openvpn_status = {
                "name": "OpenVPN 核心连接",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    openvpn_status,
                    collector_status,
                    checker_status,
                    pinger_status
                ]
            })
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries = []
            if log_file.exists():
                try:
                    with lock:
                        with open(log_file, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        entries.append(json.loads(line))
                                    except Exception:
                                        pass
                except Exception as e:
                    print(f"[API Logs] Error reading log file: {e}", flush=True)
            self.send_json({"logs": entries})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            try:
                payload = self.read_json_body()
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/update_credentials":
            try:
                payload = self.read_json_body()
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "").strip()
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                
                ui_cfg = load_ui_config()
                if not new_username or (not new_password and not ui_cfg.get("password")):
                    self.send_json({"ok": False, "error": "用户名不能为空；首次设置时密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "网页管理端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return

                expected_username = ui_cfg.get("username", "")
                expected_password = ui_cfg.get("password", "")
                expected_port = ui_cfg.get("port", 8787)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")

                ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                
                auth_file = DATA_DIR / "ui_auth.json"
                reauth_required = new_username != expected_username or (new_password and new_password != expected_password)
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                    if reauth_required:
                        active_sessions.clear()
                
                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "reauth_required": reauth_required, "message": "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台安全配置更新，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "reauth_required": reauth_required, "message": "账号密码配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                payload = self.read_json_body()
                
                new_proxy_port = payload.get("proxy_port")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                latency_check_interval = parse_int(payload.get("latency_check_interval_minutes"))
                latency_threshold = parse_int(payload.get("latency_threshold_ms"))
                
                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "代理出站端口范围必须是 1024 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites", "fixed_favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                if latency_check_interval not in LATENCY_CHECK_INTERVAL_CHOICES_MINUTES:
                    self.send_json({"ok": False, "error": "无效的活动节点巡检间隔"}, HTTPStatus.BAD_REQUEST)
                    return
                if latency_threshold not in LATENCY_THRESHOLD_CHOICES_MS:
                    self.send_json({"ok": False, "error": "无效的延迟筛选阈值"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                previous_route = (
                    ui_cfg.get("routing_mode", "auto"),
                    ui_cfg.get("force_country", ""),
                    ui_cfg.get("routing_ip_type", "all"),
                    ui_cfg.get("fav_fail_fallback", True),
                )
                previous_latency_policy = (
                    get_latency_check_interval_minutes(ui_cfg),
                    get_latency_threshold_ms(ui_cfg),
                )
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                
                if new_proxy_port_int == ui_cfg.get("port", 8787):
                    self.send_json({"ok": False, "error": "代理出站端口不能与网页管理端口相同"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["proxy_port"] = new_proxy_port_int
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["latency_check_interval_minutes"] = latency_check_interval
                ui_cfg["latency_threshold_ms"] = latency_threshold
                if previous_latency_policy != (latency_check_interval, latency_threshold):
                    ui_cfg["latency_policy_updated_at"] = time.time()
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                restart_needed = (new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，代理出站端口变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 代理出站端口变更，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    next_route = (routing_mode, force_country, routing_ip_type, ui_cfg.get("fav_fail_fallback", True))
                    routing_refresh_started = False
                    if previous_route != next_route and ui_cfg.get("connection_enabled", True):
                        threading.Thread(
                            target=test_current_routing_scope_and_maybe_switch,
                            args=("proxy settings changed",),
                            daemon=True,
                        ).start()
                        routing_refresh_started = True
                    self.send_json({
                        "ok": True,
                        "restart_needed": False,
                        "routing_refresh_started": routing_refresh_started,
                        "message": "配置更新成功，已即时生效！"
                    })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                payload = self.read_json_body()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                fav_fail_fallback = bool(payload.get("fav_fail_fallback", True))
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites", "fixed_favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = load_ui_config()
                previous_route = (
                    ui_cfg.get("routing_mode", "auto"),
                    ui_cfg.get("force_country", ""),
                    ui_cfg.get("routing_ip_type", "all"),
                    ui_cfg.get("fav_fail_fallback", True),
                )
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["fav_fail_fallback"] = fav_fail_fallback
                ui_cfg.pop("enable_force_country", None)
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "出站路由配置更新成功，已即时生效！"})
                next_route = (routing_mode, force_country, routing_ip_type, fav_fail_fallback)
                if previous_route != next_route and ui_cfg.get("connection_enabled", True):
                    threading.Thread(
                        target=test_current_routing_scope_and_maybe_switch,
                        args=("routing settings changed",),
                        daemon=True,
                    ).start()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/toggle_favorite":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                
                ui_cfg = load_ui_config()
                fav_ids = ui_cfg.get("favorite_node_ids", [])
                if not isinstance(fav_ids, list):
                    fav_ids = []
                fav_ids = favorite_node_ids({"favorite_node_ids": fav_ids})
                removed_node_ids: list[str] = []
                
                if node_id in fav_ids:
                    fav_ids.remove(node_id)
                    nodes = read_nodes()
                    node = next((n for n in nodes if n.get("id") == node_id), None)
                    if node_should_be_removed_after_unfavorite(node):
                        remove_nodes_by_ids({node_id})
                        removed_node_ids.append(node_id)
                else:
                    nodes = read_nodes()
                    node = next((n for n in nodes if n.get("id") == node_id), None)
                    if not node:
                        self.send_json({"ok": False, "error": "节点不存在"}, HTTPStatus.BAD_REQUEST)
                        return
                    if not node_can_be_favorited(node):
                        self.send_json({"ok": False, "error": "该节点当前不可用或已被拉黑，不能收藏"}, HTTPStatus.BAD_REQUEST)
                        return
                    fav_ids.append(node_id)
                
                ui_cfg["favorite_node_ids"] = fav_ids
                save_ui_config(ui_cfg)
                
                self.send_json({"ok": True, "favorite_node_ids": fav_ids, "removed_node_ids": removed_node_ids})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/manual_blacklist_add":
            try:
                payload = self.read_json_body()
                reason = str(payload.get("reason") or "manual blacklist").strip()
                node_id = str(payload.get("node_id") or "").strip()
                if node_id:
                    result = add_manual_blacklist_node_egress(node_id, reason)
                    self.send_json({
                        "ok": True,
                        "entry": result["entry"],
                        "node_id": result["node_id"],
                        "ip": result["ip"],
                        "items": manual_blacklist_entries(),
                    })
                else:
                    ip = str(payload.get("ip") or "").strip()
                    entry = add_manual_blacklist_ip(ip, reason)
                    self.send_json({"ok": True, "entry": entry, "items": manual_blacklist_entries()})
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/manual_blacklist_remove":
            try:
                payload = self.read_json_body()
                ip = str(payload.get("ip") or "").strip()
                result = remove_manual_blacklist_ip(ip)
                self.send_json({"ok": True, "removed": result.get("existed", False), "result": result, "items": manual_blacklist_entries()})
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": refresh_test_prune_and_maybe_switch("manual update")})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                if maintenance_lock.locked():
                    self.send_json({"ok": True, "message": "节点维护任务正在运行，请稍后再试", "running": True})
                else:
                    threading.Thread(target=refresh_test_prune_and_maybe_switch, args=("manual update",), daemon=True).start()
                    self.send_json({"ok": True, "message": "已在后台启动新旧节点合并测速排序流程", "running": False})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                tested_nodes = test_multiple_nodes(node_ids)
                self.send_json({"ok": True, "nodes": tested_nodes})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                ui_cfg = load_ui_config()
                ui_cfg["connection_enabled"] = False
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                stop_active_openvpn()
                with lock:
                    nodes = read_nodes()
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接")
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                payload = self.read_json_body()
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""))})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                self.read_request_body()
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)

def main() -> None:
    ensure_dirs()
    install_crash_log_hooks()
    log_node_activity("START", "AimiliVPN service starting")
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    threading.Thread(target=active_latency_refresh_guard, daemon=True).start()
    threading.Thread(target=node_activity_logger_loop, daemon=True).start()
    
    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = bounded_int(ui_cfg.get("port"), UI_PORT, 1, 65535)
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()
