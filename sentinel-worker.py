#!/usr/bin/env python3
"""
SENTINEL-WORKER — VPS & Mintbot Security Worker (NO-LLM)
========================================================
Gabungan sentinel-core (deteksi) + sentinel-send (kirim Telegram per-event)
+ health check. Jalan via Hermes cron `no_agent=True` (tanpa LLM provider,
jadi TIDAK ADA provider timeout). Atau bisa jalan standalone via cron OS.

Alur:
  1. scan docker/nginx/ssh/network logs (offset-based, first-run baseline)
  2. deteksi event (SQLi/XSS/RCE/SSRF/traversal/scanner/webhook dll)
  3. auto-ban IP berbahaya via fail2ban (HIGH/CRITICAL, eksternal)
  4. kirim 1 chat Telegram per event (delay 30s antar chat, max 15/run)
  5. health check (healthz + docker ps) — kalau ada masalah, chat CRITICAL
  6. stdout ringkas: kosong kalau tidak ada event (=> silent tick)

Usage:
  python3 sentinel-worker.py --run-once   # default untuk cron
  python3 sentinel-worker.py --check      # status
  python3 sentinel-worker.py --reset      # reset state
Env:
  SENTINEL_DRY=1    dry-run (tanpa kirim Telegram, print [DRY])
  SENTINEL_DELAY=30 delay antar chat (detik)
"""

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
STATE_DIR = Path(os.environ.get("SENTINEL_STATE_DIR", "/opt/satpol/state"))
EVENTS_FILE = STATE_DIR / "events.jsonl"
OFFSETS_FILE = STATE_DIR / "offsets.json"
STRIKES_FILE = STATE_DIR / "strikes.json"
SNAPSHOT_FILE = STATE_DIR / "snapshot.json"
SENT_FILE = STATE_DIR / "sent_ids.json"     # dedupe per-event (id event terkirim)
LOCK_FILE = STATE_DIR / "send.lock"          # single-instance lock
ENV_FILE = "/etc/satpol/env"              # TELEGRAM_BOT_TOKEN / TELEGRAM_HOME_CHANNEL

CONTAINERS = ["mintbot-api-1", "mintbot-web-1", "mintbot-worker-1"]
NGINX_LOGS = ["/var/log/nginx/sentinel-access.log", "/var/log/nginx/access.log"]
SSH_LOG = "/var/log/auth.log"
HEALTHZ_URL = "http://127.0.0.1/healthz"

STRIKE_WINDOW = 900          # 15 min sliding window
EVENT_WINDOW = 86400         # keep events 24h
MAX_EVENTS = 5000            # cap events
DELAY_BETWEEN = float(os.environ.get("SENTINEL_DELAY", "5"))   # 5s antar chat — real-time, ga numpuk
MAX_SEND_PER_RUN = int(os.environ.get("SENTINEL_MAX", "10"))   # per tick 1 menit: max 10 chat
LOCK_STALE = 60                                               # lock basi setelah 60s (cron 1 menit)
DRY_RUN = os.environ.get("SENTINEL_DRY", "") == "1"

WIB = timezone(timedelta(hours=7))
SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}

# ---------------------------------------------------------------------------
# Detection rules (regex -> (event_type, severity, score))
# ---------------------------------------------------------------------------
RULES = [
    (re.compile(r"(%27|'|\bOR\b|\bUNION\b|\bSELECT\b|\bSLEEP\s*\(|--\s*$|/\*.*\*/|information_schema)", re.I), "sql_injection_probe", "high", 8),
    (re.compile(r"(union\s+(all\s+)?select|select\s+.+from|insert\s+into|update\s+.+set|delete\s+from)", re.I), "sql_injection_probe", "critical", 12),
    (re.compile(r"(sleep\s*\(\s*\d+|benchmark\s*\(|pg_sleep|waitfor\s+delay|dbms_pipe|extractvalue|updatexml)", re.I), "sql_time_based", "critical", 14),
    (re.compile(r"(information_schema|sys\.tables|sqlite_master|pg_catalog|concat\s*\(|group_concat|cast\s*\(.*as\s+(int|char))", re.I), "sql_injection_probe", "high", 9),
    (re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|svg\s+onload)", re.I), "xss_probe", "high", 7),
    (re.compile(r"(\.\./|\.\.%2f|%2e%2e%2f|/etc/passwd|/etc/shadow|C:\\windows|win\.ini)", re.I), "path_traversal", "high", 9),
    (re.compile(r"(/proc/self/environ|/proc/self/cmdline|file:///|php://filter|data://|expect://)", re.I), "lfi_rce_probe", "high", 10),
    (re.compile(r"(\$\(|`|\|.*sh|;.*\b(bash|sh|cmd|powershell)\b|/bin/sh|/bin/bash|nc\s+-e|wget\s+http|curl\s+http)", re.I), "rce_probe", "critical", 13),
    (re.compile(r"(sqlmap|nuclei|nikto|acunetix|nessus|burpsuite|hydra|masscan|zgrab|wpscan|joomscan)", re.I), "scanner", "medium", 6),
    (re.compile(r"(360spider|semrushbot|mj12bot|ahrefsbot)", re.I), "seo_crawler", "low", 1),
    (re.compile(r"(\.env|\.git/config|\.git/HEAD|/wp-admin|wp-login|\.aws/credentials|id_rsa|\.ssh/|/actuator/|/server-status|/phpmyadmin|/adminer)", re.I), "config_probe", "medium", 5),
    (re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|100\.100\.100\.200)", re.I), "ssrf_probe", "high", 10),
    (re.compile(r"(/admin|/login|/auth|/api/v1/auth)", re.I), "auth_endpoint_hit", "low", 2),
    (re.compile(r"(password\s*=|passwd\s*=|token\s*=|api[_-]?key\s*=|secret\s*=)", re.I), "credential_probe", "medium", 5),
    (re.compile(r"(/webhook|/api/webhook|saweria|stripe|midtrans|xendit|webhook.*signature)", re.I), "webhook_hit", "medium", 5),
    (re.compile(r"(invalid\s+signature|hmac.*fail|signature.*mismatch|verification\s+failed)", re.I), "webhook_invalid_signature", "high", 9),
    (re.compile(r"(donation_id|payment_id|transaction_id|order_id)[^\s]*=0+", re.I), "webhook_zero_id", "medium", 6),
    (re.compile(r"(__proto__|constructor\[|prototype\.|\.\.\.|@type|yaml|jsessionid|\.do\?|\.jsp\?|\.php\?)", re.I), "deser_framework_probe", "medium", 5),
]

BINARY_NOISE = re.compile(r"^[\x00-\x1f\x7f-\xff\\x]{3,}", re.S)
BOOT_NOISE = re.compile(r"(Mapped \{/api/v1|RoutesResolver|NestFactory|Nest application successfully|RouterExplorer|Starting Nest|Bootstrap|Ready in|Starting\.\.\.|✓ Starting)", re.I)
IGNORE_UA = re.compile(r"(Next.js|node-fetch|axios|undici|Mozilla/5.0.*Chrome/149|Go-http-client/1.1|curl/7\.|curl/8\.)", re.I)

# ---------------------------------------------------------------------------
# Vulnerability classification
# ---------------------------------------------------------------------------
CLASSIFICATION = {
    "sql_injection_probe": ("CWE-89", "SQL Injection", "8.6"),
    "sql_time_based": ("CWE-89", "SQL Injection (Time-based)", "9.8"),
    "xss_probe": ("CWE-79", "Cross-Site Scripting", "8.2"),
    "path_traversal": ("CWE-22", "Path Traversal", "7.5"),
    "lfi_rce_probe": ("CWE-98", "Local File Inclusion", "8.1"),
    "rce_probe": ("CWE-78", "OS Command Injection", "9.8"),
    "ssrf_probe": ("CWE-918", "Server-Side Request Forgery", "9.1"),
    "ssh_bruteforce": ("CWE-307", "Brute-Force / Credential Stuffing", "7.5"),
    "scanner": ("CWE-200", "Reconnaissance / Scanning", "3.1"),
    "config_probe": ("CWE-200", "Sensitive File Exposure Probe", "5.3"),
    "webhook_invalid_signature": ("CWE-345", "Insufficient Verification (HMAC)", "8.1"),
    "webhook_zero_id": ("CWE-20", "Improper Input Validation", "5.3"),
    "credential_probe": ("CWE-522", "Credential Exposure Probe", "5.3"),
    "deser_framework_probe": ("CWE-502", "Insecure Deserialization Probe", "6.5"),
    "connection_flood": ("CWE-400", "Resource Exhaustion / DoS", "7.5"),
    "seo_crawler": ("N/A", "Bot Crawler", "0.0"),
    "auth_endpoint_hit": ("N/A", "Normal Auth Traffic", "0.0"),
    "webhook_hit": ("CWE-20", "Webhook Probe", "5.3"),
}

# Event type -> fail2ban jail untuk auto-ban
AUTO_FIX_JAIL = {
    "ssh_bruteforce": "sshd",
    "sql_injection_probe": "nginx-waf",
    "sql_time_based": "nginx-waf",
    "xss_probe": "nginx-waf",
    "path_traversal": "nginx-waf",
    "lfi_rce_probe": "nginx-waf",
    "rce_probe": "nginx-waf",
    "ssrf_probe": "nginx-waf",
    "scanner": "nginx-waf",
    "config_probe": "nginx-waf",
    "webhook_invalid_signature": "nginx-waf",
    "webhook_zero_id": "nginx-waf",
    "connection_flood": "nginx-waf",
    "deser_framework_probe": "nginx-waf",
    "credential_probe": "nginx-waf",
}
IGNORE_IPS = {"127.0.0.1", "::1", "localhost", "{{VPS_IP}}", "{{WHITELIST_1}}", "{{WHITELIST_2}}"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def parse_ts(ts):
    try:
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return 0


def event_id(ev):
    return f"{ev.get('ts')}|{ev.get('ip')}|{ev.get('type')}|{ev.get('endpoint','')}"


# ---------------------------------------------------------------------------
# Source readers
# ---------------------------------------------------------------------------
def log_line_ip(line):
    m = re.search(r"ip[=\s:]+([0-9a-fA-F.:]+)", line)
    return m.group(1) if m else None


def parse_docker_log_line(raw):
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and "log" in obj:
            return obj.get("time", ""), obj.get("log", "")
    except Exception:
        pass
    return None, raw


def get_docker_logs(container, since_lines=150):
    try:
        out = subprocess.run(["docker", "logs", "--tail", str(since_lines), container],
                             capture_output=True, text=True, timeout=20)
        return out.stdout or ""
    except Exception:
        return ""


def get_connections():
    try:
        out = subprocess.run(["ss", "-tn", "state", "established"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    conns = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            local, peer = parts[3], parts[4]
            try:
                lip, lport = local.rsplit(":", 1)
                pip, pport = peer.rsplit(":", 1)
            except ValueError:
                continue
            if pip not in ("127.0.0.1", "::1") and not pip.startswith("172."):
                conns.append({"local": local, "peer": peer, "ip": pip, "port": pport})
    return conns


# ---------------------------------------------------------------------------
# Event emission & matching
# ---------------------------------------------------------------------------
def emit_event(events, src, ip, event_type, severity, endpoint, detail, ts=None, ua=None):
    ts = ts or now_iso()
    events.append({
        "ts": ts, "src": src, "ip": ip, "type": event_type,
        "severity": severity, "endpoint": endpoint, "detail": detail[:300],
        "ua": (ua or "")[:120],
    })


def match_rules(text, ip, src, endpoint, ts=None, ua=None, events=None):
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    if not text or len(text) < 4:
        return
    if BOOT_NOISE.search(text):
        return
    if BINARY_NOISE.match(text) or "\\x16\\x03" in text or "mstshash=" in text:
        return
    found = []
    for rx, etype, sev, score in RULES:
        if rx.search(text):
            found.append((etype, sev, score))
    if not found:
        return
    found.sort(key=lambda x: SEV_ORDER[x[1]], reverse=True)
    etype, sev, _ = found[0]
    if sev == "low" and ua and IGNORE_UA.search(ua):
        return
    detail = f"payload match: {text[:200]}"
    if events is not None:
        emit_event(events, src, ip, etype, sev, endpoint, detail, ts=ts, ua=ua)
    return found


def scan_docker_logs(events):
    offsets = load_json(OFFSETS_FILE, {})
    for container in CONTAINERS:
        try:
            path = Path("/var/lib/docker/containers")
            cid = None
            for p in path.glob("*"):
                try:
                    name = subprocess.run(["docker", "inspect", "--format", "{{.Name}}", p.name],
                                          capture_output=True, text=True, timeout=5).stdout.strip().lstrip("/")
                    if name == container:
                        cid = p.name
                        break
                except Exception:
                    continue
            if not cid:
                continue
            logfile = path / cid / f"{cid}-json.log"
            if not logfile.exists():
                continue
            key = f"docker:{container}"
            offset = offsets.get(key)
            first_run = offset is None
            size = os.path.getsize(logfile)
            with open(logfile, "rb") as f:
                if offset is not None and offset <= size:
                    f.seek(offset)
                data = f.read()
                offset = f.tell()
            offsets[key] = size
            if first_run:
                save_json(OFFSETS_FILE, offsets)
                continue
            for line in data.splitlines():
                ts, msg = parse_docker_log_line(line.decode("utf-8", errors="replace"))
                if not msg:
                    continue
                msg = msg.strip()
                if not msg:
                    continue
                ip = log_line_ip(msg)
                endpoint = None
                ua = None
                m = re.search(r'(?:GET|POST|PUT|PATCH|DELETE|OPTIONS)\s+(\S+)', msg)
                if m:
                    endpoint = m.group(1)
                m = re.search(r'"(Mozilla[^"]*)"', msg)
                if m:
                    ua = m.group(1)
                match_rules(msg, ip or "?", container, endpoint, ts=ts, ua=ua, events=events)
        except Exception:
            pass
    save_json(OFFSETS_FILE, offsets)


def scan_nginx_logs(events):
    offsets = load_json(OFFSETS_FILE, {})
    for path in NGINX_LOGS:
        p = Path(path)
        if not p.exists():
            continue
        key = f"nginx:{path}"
        offset = offsets.get(key)
        size = os.path.getsize(p)
        first_run = offset is None
        if offset is None or offset > size:
            offset = 0
        with open(p, "rb") as f:
            f.seek(offset)
            data = f.read()
            offsets[key] = size
        if first_run:
            save_json(OFFSETS_FILE, offsets)
            continue
        for line in data.splitlines():
            line = line.decode("utf-8", errors="replace")
            m = re.match(r'^(\S+)\|([^|]+)\|(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\|([^|]*)\|(\d+)\|(.*)$', line)
            if not m:
                m = re.match(r'^(\S+)\s+.*?\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)', line)
                if not m:
                    continue
                ip, ts_raw, req, status = m.group(1), m.group(2), m.group(3), m.group(4)
                ua = None
                um = re.search(r'"([^"]*)"\s*$', line)
                if um:
                    ua = um.group(1)
                rm = re.match(r'^(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)', req)
                endpoint = rm.group(1) if rm else req[:100]
                try:
                    dt = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
                    ts = dt.astimezone(timezone.utc).isoformat(timespec="seconds")
                except Exception:
                    ts = None
            else:
                ip, ts_raw, method, uri, status, ua = m.groups()
                endpoint = uri[:200]
                try:
                    dt = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
                    ts = dt.astimezone(timezone.utc).isoformat(timespec="seconds")
                except Exception:
                    ts = None
            match_rules(f"{method or req} {endpoint or ''} {ua or ''}", ip, "nginx", endpoint, ts=ts, ua=ua, events=events)
    save_json(OFFSETS_FILE, offsets)


def scan_ssh_logs(events):
    offsets = load_json(OFFSETS_FILE, {})
    p = Path(SSH_LOG)
    if not p.exists():
        return
    key = f"ssh:{SSH_LOG}"
    offset = offsets.get(key)
    size = os.path.getsize(p)
    first_run = offset is None
    if offset is None or offset > size:
        offset = 0
    with open(p, "rb") as f:
        f.seek(offset)
        data = f.read()
        offsets[key] = size
    if first_run:
        save_json(OFFSETS_FILE, offsets)
        return
    for line in data.splitlines():
        line = line.decode("utf-8", errors="replace")
        m = re.search(r"Failed password for (\w+) from (\S+) port \d+", line)
        if m:
            user, ip = m.group(1), m.group(2)
            emit_event(events, "ssh", ip, "ssh_bruteforce", "high", f"user={user}",
                       f"failed password attempt for user '{user}'")
        m = re.search(r"Invalid user (\S+) from (\S+)", line)
        if m:
            user, ip = m.group(1), m.group(2)
            emit_event(events, "ssh", ip, "ssh_bruteforce", "high", f"user={user}",
                       f"invalid user '{user}' probe")
        m = re.search(r"Connection closed by authenticating user (\S+) (\S+)", line)
        if m:
            user, ip = m.group(1), m.group(2)
            emit_event(events, "ssh", ip, "ssh_bruteforce", "medium", f"user={user}",
                       "auth session closed")
    save_json(OFFSETS_FILE, offsets)


def scan_network(events):
    conns = get_connections()
    by_ip = defaultdict(int)
    for c in conns:
        by_ip[c["ip"]] += 1
    for ip, count in by_ip.items():
        if count >= 20:
            emit_event(events, "net", ip, "connection_flood", "high", f"established={count}",
                       f"{count} concurrent established connections from single IP")


# ---------------------------------------------------------------------------
# Strike tracking & snapshot
# ---------------------------------------------------------------------------
def update_strikes(events):
    strikes = load_json(STRIKES_FILE, {})
    now = time.time()
    for ip in list(strikes.keys()):
        strikes[ip] = [t for t in strikes[ip] if now - t < STRIKE_WINDOW]
        if not strikes[ip]:
            del strikes[ip]
    for ev in events:
        if SEV_ORDER.get(ev["severity"], 0) >= 2 and ev["ip"] not in (None, "?"):
            strikes.setdefault(ev["ip"], []).append(now)
            strikes[ev["ip"]] = strikes[ev["ip"]][-200:]
    save_json(STRIKES_FILE, strikes)
    return strikes


def check_docker():
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}:{{.Status}}"],
                             capture_output=True, text=True, timeout=10).stdout
        return [l for l in out.splitlines() if l.strip()]
    except Exception:
        return []


def build_snapshot(events, strikes):
    now = time.time()
    by_type = defaultdict(int)
    by_sev = defaultdict(int)
    by_ip = defaultdict(int)
    for ev in events:
        by_type[ev["type"]] += 1
        by_sev[ev["severity"]] += 1
        by_ip[ev["ip"]] += 1
    top_ips = sorted(strikes.items(), key=lambda kv: len(kv[1]), reverse=True)[:15]
    conns = get_connections()
    snap = {
        "ts": now_iso(),
        "counts": {"events": len(events), "by_type": dict(by_type), "by_severity": dict(by_sev)},
        "top_ips": [{"ip": ip, "strikes": len(t), "first": int(min(t)), "last": int(max(t))} for ip, t in top_ips],
        "top_event_ips": [{"ip": ip, "count": c} for ip, c in sorted(by_ip.items(), key=lambda kv: kv[1], reverse=True)[:10]],
        "active_connections": len(conns),
        "docker_healthy": check_docker(),
        "host": socket.gethostname(),
    }
    save_json(SNAPSHOT_FILE, snap)
    return snap


# ---------------------------------------------------------------------------
# Telegram send + auto-fix
# ---------------------------------------------------------------------------
def load_env():
    token = chat = None
    thread = None
    try:
        for line in open(ENV_FILE):
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k == "TELEGRAM_BOT_TOKEN" and v:
                token = v
            elif k == "TELEGRAM_HOME_CHANNEL" and v:
                chat = v
            elif k == "TELEGRAM_SENTINEL_CHAT" and v:
                chat = v
            elif k == "TELEGRAM_SENTINEL_THREAD" and v:
                thread = v
    except Exception as e:
        print(f"ERR load_env: {e}")
    return token, chat, thread


def tg_send(token, chat, text, thread_id=None):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {"chat_id": chat, "text": text, "parse_mode": "Markdown"}
    if thread_id:
        data["message_thread_id"] = int(thread_id)
    body = urllib.parse.urlencode(data).encode()
    try:
        req = urllib.request.Request(url, data=body)
        with urllib.request.urlopen(req, timeout=15) as resp:
            out = json.loads(resp.read().decode())
            return out.get("ok", False), ""
    except Exception as e:
        return False, str(e)


def already_banned(ip, jail):
    try:
        out = subprocess.run(["fail2ban-client", "status", jail], capture_output=True, text=True, timeout=10).stdout
        return ip in out
    except Exception:
        return False


def auto_fix(event):
    ip = event.get("ip", "")
    etype = event.get("type", "")
    sev = event.get("severity", "low")
    jail = AUTO_FIX_JAIL.get(etype)
    if not jail:
        return None
    if ip in IGNORE_IPS or not ip or ip == "?":
        return "SKIP (internal IP)"
    if already_banned(ip, jail):
        return f"ALREADY BANNED ({jail})"
    try:
        subprocess.run(["fail2ban-client", "set", jail, "banip", ip],
                       capture_output=True, text=True, timeout=15)
        if already_banned(ip, jail):
            return f"AUTO-BANNED via fail2ban ({jail})"
        return "BAN ATTEMPTED (verify)"
    except Exception:
        return "BAN FAILED"


def tg_escape(text):
    """Escape Markdown special chars biar Telegram ga 400. Hati-hati: '-' cuma
    perlu di-escape kalau di awal baris (bikin list). Di dalam backtick ga perlu."""
    return text.replace("\\", "\\\\").replace("_", "\\_").replace("*", "\\*").replace("[", "\\[").replace("]", "\\]").replace("(", "\\(").replace(")", "\\)").replace("~", "\\~").replace("`", "\\`").replace(">", "\\>").replace("#", "\\#").replace("+", "\\+").replace("!", "\\!")


def geo_lookup(ip):
    """Cari negara asal IP (offline, tanpa API — pake database kecil)."""
    # Fallback: resolve via ip-api.com (fast, no key) — cache 24h biar ga spam
    import os, time as _t
    cache_file = STATE_DIR / "geo_cache.json"
    cache = {}
    try:
        if cache_file.exists():
            cache = json.loads(open(cache_file).read())
    except Exception:
        pass
    if ip in cache and _t.time() - cache[ip].get("t", 0) < 86400:
        return cache[ip].get("country", "?")
    try:
        # pakai curl (terbukti jalan) — http, fields minimal
        out = subprocess.run(
            ["curl", "-s", "--max-time", "5", f"http://ip-api.com/json/{ip}?fields=country,countryCode,org,isp,as"],
            capture_output=True, text=True, timeout=8).stdout.strip()
        data = json.loads(out)
        if data.get("country"):
            country = f"{data.get('country','?')} ({data.get('countryCode','?')})"
            org = data.get("org", "") or data.get("isp", "") or ""
            cache[ip] = {"t": _t.time(), "country": country, "org": org}
            try:
                json.dump(cache, open(cache_file, "w"))
            except Exception:
                pass
            return country
    except Exception:
        pass
    return "?"


def geo_org(ip):
    """ISP/org dari IP (dari cache geo)."""
    import os, time as _t
    cache_file = STATE_DIR / "geo_cache.json"
    try:
        if cache_file.exists():
            cache = json.loads(open(cache_file).read())
            if ip in cache:
                return cache[ip].get("org", "")
    except Exception:
        pass
    return ""


def format_event(ev, fix=None):
    sev = ev.get("severity", "low")
    icon = SEV_ICON.get(sev, "⚪")
    etype = ev.get("type", "unknown").replace("_", " ").upper()
    cwe, name, cvss = CLASSIFICATION.get(ev.get("type", ""), ("CWE-000", ev.get("type", "?").replace("_", " ").title(), "0.0"))
    ip = ev.get("ip", "?")
    endpoint = (ev.get("endpoint") or "?").strip()[:100]
    ts_raw = ev.get("ts", "")
    try:
        ts = datetime.fromisoformat(ts_raw).astimezone(WIB).strftime("%d %b %Y %H:%M")
    except Exception:
        ts = "?"
    # enrich: negara + ISP
    country = geo_lookup(ip)
    org = geo_org(ip)
    src_line = f"• **Sumber:** `{country}`" if country and country != "?" else ""
    if org:
        src_line += f" — `{tg_escape(org[:60])}`"
    # strike count (jumlah percobaan dari IP ini)
    strikes = load_json(STRIKES_FILE, {})
    strike_n = len(strikes.get(ip, []))
    strike_line = f"• **Percobaan:** `{strike_n}x` dalam 15 menit" if strike_n else ""
    # port/vector dari src
    vector = ev.get("src", "?")
    vector_line = f"• **Vektor:** `{vector}` (SSH/web/network)"
    lines = [
        f"{icon} **SATPOL — {name}** ({cwe}, CVSS {cvss})",
        f"• **Tipe:** `{etype}`",
        f"• **IP:** `{ip}`",
    ]
    if src_line:
        lines.append(src_line)
    lines.append(f"• **Endpoint:** `{tg_escape(endpoint)}`")
    lines.append(vector_line)
    if strike_line:
        lines.append(strike_line)
    lines.append(f"• **Waktu:** {ts} WIB")
    lines.append(f"• **Detail:** {tg_escape(ev.get('detail','')[:140])}")
    if fix:
        lines.append(f"• **Aksi:** `{fix}`")
    lines.append("")
    lines.append("`SATPOL · {{VPS_IP}}`")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def tail_scan_once():
    """Satu pass scan (dipakai cron 1 menit sebagai backup + daemon tail)."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    events = []
    scan_docker_logs(events)
    scan_nginx_logs(events)
    scan_ssh_logs(events)
    scan_network(events)
    return events


def run_once():
    events = tail_scan_once()
    return send_events(events)


def daemon_tail():
    """Real-time mode: tail file terus-menerus, langsung eksekusi + kirim.
    Jalan sebagai background daemon (systemd/forever), bukan cron."""
    import time as _t
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    print("SENTINEL DAEMON — real-time tail active", flush=True)
    # seed baseline dulu (first-run scan, jangan emit history)
    tail_scan_once()
    # loop: scan tiap 5 detik (offset-based, cuma baca yang baru)
    while True:
        try:
            events = tail_scan_once()
            if events:
                send_events(events, quiet=True)
        except Exception as e:
            print(f"daemon error: {e}", flush=True)
        _t.sleep(5)


def send_events(events, quiet=False):
    """Append events, prune, update strikes/snapshot, kirim per-event ke Telegram."""
    # append events (prune old, cap)
    old_events = []
    if EVENTS_FILE.exists():
        try:
            with open(EVENTS_FILE) as f:
                old_events = [json.loads(l) for l in f if l.strip()]
        except Exception:
            pass
    cutoff = time.time() - EVENT_WINDOW
    old_events = [e for e in old_events if parse_ts(e.get("ts")) > cutoff]
    all_events = (old_events + events)[-MAX_EVENTS:]
    with open(EVENTS_FILE, "w") as f:
        for ev in all_events:
            f.write(json.dumps(ev) + "\n")

    strikes = update_strikes(events)
    build_snapshot(all_events, strikes)

    # --- send per-event ---
    token, chat, thread_id = load_env()
    if not token or not chat:
        print("ERR: TELEGRAM_BOT_TOKEN / TELEGRAM_HOME_CHANNEL tidak ditemukan di .env")
        return 2

    # single-instance lock ringan (claim event atomic via SENT_FILE, ga dobel kirim)
    LOCK_FILE.write_text(str(time.time()))

    seen = load_json(SENT_FILE, [])
    seen_set = set(seen)
    pending = [e for e in all_events if event_id(e) not in seen_set]
    pending.sort(key=lambda e: e.get("ts", ""))
    if not pending:
        try:
            LOCK_FILE.unlink()
        except Exception:
            pass
        if not quiet:
            print("")  # stdout kosong => silent tick
        return 0

    batch = pending[:MAX_SEND_PER_RUN]
    leftover = len(pending) - len(batch)
    sent = 0
    for i, ev in enumerate(batch):
        fix = auto_fix(ev)
        msg = format_event(ev, fix)
        if DRY_RUN:
            print(f"[DRY] would send {ev.get('type')} {ev.get('ip')}")
        else:
            ok, err = tg_send(token, chat, msg, thread_id)
            if ok:
                print(f"SENT {ev.get('type')} {ev.get('ip')}", flush=True)
            else:
                print(f"FAIL {ev.get('type')} {ev.get('ip')}: {err[:100]}", flush=True)
                continue
        seen.append(event_id(ev))
        sent += 1
        save_json(SENT_FILE, seen)
        if i < len(batch) - 1:
            time.sleep(DELAY_BETWEEN)

    try:
        LOCK_FILE.unlink()
    except Exception:
        pass
    extra = f" (+{leftover} menunggu tick berikutnya)" if leftover else ""
    print(f"done: {sent} chat terkirim (1 per event, delay {int(DELAY_BETWEEN)}s){extra}")

    # --- health check ---
    health_issues = []
    try:
        out = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", HEALTHZ_URL],
                             capture_output=True, text=True, timeout=10).stdout
        if out.strip() != "200":
            health_issues.append(f"healthz {HEALTHZ_URL} → {out.strip() or 'no response'}")
    except Exception as e:
        health_issues.append(f"healthz check error: {e}")
    containers = check_docker()
    down = [c for c in containers if "Up" not in c]
    if down:
        health_issues.append("container down: " + ", ".join(down))
    if health_issues and not DRY_RUN:
        msg = "🔴 **SATPOL CRITICAL — SERVICE DOWN**\n" + "\n".join(f"• {i}" for i in health_issues)
        tg_send(token, chat, msg, thread_id)
        print("CRITICAL: " + "; ".join(health_issues))
    return 0


def check_status():
    snap = load_json(SNAPSHOT_FILE, {})
    strikes = load_json(STRIKES_FILE, {})
    if not snap:
        print(json.dumps({"status": "no snapshot yet"}))
        return
    print(json.dumps({"status": "ok", "snapshot": snap, "active_strike_ips": len(strikes)}, indent=1))


def reset():
    for f in [EVENTS_FILE, OFFSETS_FILE, STRIKES_FILE, SNAPSHOT_FILE, SENT_FILE, LOCK_FILE]:
        try:
            f.unlink()
        except Exception:
            pass
    print("state reset (events, offsets, strikes, snapshot, sent, lock)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-once", action="store_true")
    ap.add_argument("--daemon", action="store_true", help="real-time tail mode (jalan terus)")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()
    if args.reset:
        reset()
    elif args.check:
        check_status()
    elif args.daemon:
        daemon_tail()
    else:
        sys.exit(run_once())
