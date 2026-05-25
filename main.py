#!/usr/bin/env python3
"""
ReconForge v2.0  —  Security Reconnaissance Orchestration Platform
Single-file: stdlib HTTP + sqlite3 + threading + psutil.

Usage:
    python3 main.py
    python3 main.py --port 8342 --https
    python3 main.py --cert server.crt --key server.key
    python3 main.py --skip-setup
"""

# ═══════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════
import argparse, base64, hashlib, hmac, json, logging, mimetypes
import os, queue, re, secrets, shutil, signal, socket, sqlite3, ssl
import subprocess, sys, tarfile, tempfile, threading, time, traceback
import urllib.parse, urllib.request, urllib.error
from collections import deque
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil as _psutil; HAS_PSUTIL = True
except ImportError:
    _psutil = None; HAS_PSUTIL = False

import scope_guard  # Phase 1: pure-logic gate, runs before every dispatch

# ═══════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════
VERSION      = "2.0.0"
APP_NAME     = "ReconForge"
DEFAULT_PORT = 8342
DEFAULT_HOST = "0.0.0.0"

_BASE            = os.path.dirname(os.path.abspath(__file__))
DATA_DIR         = os.environ.get("RECON_DATA_DIR", os.path.join(_BASE, "recon_data"))
DB_PATH          = os.path.join(DATA_DIR, "recon.db")
JOBS_DIR         = os.path.join(DATA_DIR, "jobs")
SCREENSHOTS_DIR  = os.path.join(DATA_DIR, "screenshots")
BACKUP_DIR       = os.path.join(DATA_DIR, "backups")
TEMP_DIR         = os.path.join(DATA_DIR, "tmp")

SESSION_TTL        = 86_400
PBKDF2_ITERS       = 100_000
SALT_BYTES         = 32
HARVEST_INTERVAL   = 30
FIRST_SUB_TIMEOUT  = 600  # wall-clock fallback; overridable via settings.json:first_sub_timeout
MIN_ENUM_TOOLS_REQUIRED = 2  # don't abort until at least N enum tools have completed-or-failed
RESOURCE_INTERVAL  = 5
RESOURCE_RETENTION = 3_600
DYNAMIC_INTERVAL   = 30
MONITOR_INTERVAL   = 10
BACKUP_INTERVAL    = 3_600
CLEANUP_INTERVAL   = 3_600
SESSION_CLEANUP    = 600
GALLERY_PAGE_SZ    = 20
MAX_BACKUPS        = 10
CLEANUP_TEMP_H     = 24
CLEANUP_DAYS       = 30
CPU_WARN  = 75; CPU_CRIT  = 90
MEM_WARN  = 80; MEM_CRIT  = 90
MAX_RATE_DELAY = 30
RATE_INCREMENT = 5
DEFAULT_TLDS     = ["com","net","org","io","co","app","dev","us","uk","in","de"]
DEFAULT_THREADS  = 50
DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

# ═══════════════════════════════════════════════════════════
#  GLOBAL STATE
# ═══════════════════════════════════════════════════════════
_lock          = threading.Lock()
_jobs: Dict[str, "Job"]               = {}
_pending: "queue.Queue[Job]"          = queue.Queue()
_tool_gates: Dict[str, "ToolGate"]    = {}
_rate_delay    = 0.0
_rate_lock     = threading.Lock()
_shutdown      = threading.Event()
_cfg_cache: Dict[str, Any]            = {}
_log_buf: deque                       = deque(maxlen=2_000)
_res_buf: deque                       = deque(maxlen=720)

# ═══════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%H:%M:%S")
_log = logging.getLogger(APP_NAME)

def emit(msg: str, level: str = "INFO", src: str = "system") -> None:
    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    _log_buf.append({"ts": ts, "level": level, "src": src, "msg": msg})
    getattr(_log, level.lower(), _log.info)(f"[{src}] {msg}")

# ═══════════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════════
_db_local = threading.local()

def get_db() -> sqlite3.Connection:
    if not hasattr(_db_local, "conn") or _db_local.conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA cache_size=-65536")
        conn.execute("PRAGMA mmap_size=268435456")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _db_local.conn = conn
    return _db_local.conn

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    flags TEXT DEFAULT '{}',
    options TEXT DEFAULT '{}',
    comments TEXT DEFAULT '',
    completed_steps TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    http_status INTEGER,
    http_title TEXT,
    http_technologies TEXT DEFAULT '[]',
    nuclei_findings TEXT DEFAULT '[]',
    nikto_results TEXT DEFAULT '[]',
    interesting INTEGER DEFAULT 0,
    screenshot_path TEXT,
    dns_resolved INTEGER DEFAULT 0,
    ip_addresses TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(domain, subdomain)
);
CREATE INDEX IF NOT EXISTS idx_sub_domain ON subdomains(domain);
CREATE TABLE IF NOT EXISTS completed_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    username TEXT,
    started_at TEXT,
    completed_at TEXT DEFAULT (datetime('now')),
    status TEXT DEFAULT 'completed',
    subdomain_count INTEGER DEFAULT 0,
    results TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_cjobs_domain ON completed_jobs(domain, completed_at);
CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    source TEXT DEFAULT 'system',
    text TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hist_domain ON history(domain, created_at);
CREATE TABLE IF NOT EXISTS monitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    last_checked TEXT,
    last_result TEXT DEFAULT '',
    last_count INTEGER DEFAULT 0,
    seen_entries TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS system_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cpu_percent REAL, memory_percent REAL, disk_percent REAL,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    applied_at TEXT DEFAULT (datetime('now'))
);
"""

def init_db() -> None:
    for d in (DATA_DIR, JOBS_DIR, SCREENSHOTS_DIR, BACKUP_DIR, TEMP_DIR):
        os.makedirs(d, exist_ok=True)
    get_db().executescript(_SCHEMA)
    get_db().commit()
    # Phase 2: forward-only migrations. Baseline (001) is a no-op against the
    # _SCHEMA we just ran; 002+ add agentic tables. No pre-migration backup
    # at startup — the schema was just rebuilt and is internally consistent.
    try:
        from db.migrations import runner as _mig
        applied = _mig.run_pending(get_db(), backup_fn=None)
        if applied:
            emit(f"Migrations applied: {', '.join(applied)}", "INFO", "migrate")
    except Exception as e:
        emit(f"Migration runner failed: {e}", "ERROR", "migrate")
    emit("Database ready")

def db_row(sql: str, params=()) -> Optional[sqlite3.Row]:
    return get_db().execute(sql, params).fetchone()

def db_rows(sql: str, params=()) -> List[sqlite3.Row]:
    return get_db().execute(sql, params).fetchall()

def db_exec(sql: str, params=(), commit: bool = True) -> sqlite3.Cursor:
    c = get_db().execute(sql, params)
    if commit:
        get_db().commit()
    return c

def get_config(key: str, default: Any = None) -> Any:
    if key in _cfg_cache:
        return _cfg_cache[key]
    row = db_row("SELECT value FROM config WHERE key=?", (key,))
    val = json.loads(row["value"]) if row else default
    _cfg_cache[key] = val
    return val

def set_config(key: str, value: Any) -> None:
    _cfg_cache[key] = value
    db_exec("INSERT OR REPLACE INTO config(key,value) VALUES(?,?)",
            (key, json.dumps(value)))


def _seed_config_from_settings() -> None:
    """Mirror keys from ~/.config/reconforge/settings.json into the DB
    config table so the web UI's Settings page is pre-populated. The
    local file remains the source of truth — re-running the wizard
    updates the file; running the server then re-seeds the DB."""
    try:
        from wizard.app import settings_path
        sp = settings_path()
        if not sp.exists():
            return
        doc = json.loads(sp.read_text(encoding="utf-8"))
    except Exception as e:
        emit(f"settings.json seed skipped: {e}", "WARNING", "setup")
        return
    for k, v in (doc.get("api_keys") or {}).items():
        if v:
            set_config(k, v)
    idents = doc.get("platform_identities") or {}
    if idents:
        set_config("platform_identities", idents)

def add_history(domain: Optional[str], source: str, text: str) -> None:
    db_exec("INSERT INTO history(domain,source,text) VALUES(?,?,?)",
            (domain, source, text))

def row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict]:
    return dict(row) if row else None

def rows_to_list(rows: List[sqlite3.Row]) -> List[Dict]:
    return [dict(r) for r in rows]

# ═══════════════════════════════════════════════════════════
#  AUTHENTICATION
# ═══════════════════════════════════════════════════════════
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(),
                              PBKDF2_ITERS, dklen=32)
    return dk.hex(), salt

def verify_password(password: str, stored: str, salt: str) -> bool:
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, stored)

def create_session(user_id: int, username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(seconds=SESSION_TTL)).strftime("%Y-%m-%dT%H:%M:%S")
    db_exec("INSERT OR REPLACE INTO sessions(token,user_id,username,role,expires_at) VALUES(?,?,?,?,?)",
            (token, user_id, username, role, expires))
    with _lock:
        # warm the in-memory cache
        pass
    return token

def get_session(token: str) -> Optional[Dict]:
    if not token:
        return None
    row = db_row("SELECT user_id,username,role,expires_at FROM sessions WHERE token=?", (token,))
    if not row:
        return None
    try:
        if datetime.strptime(row["expires_at"], "%Y-%m-%dT%H:%M:%S") > datetime.now():
            return dict(row)
    except ValueError:
        pass
    return None

def delete_session(token: str) -> None:
    db_exec("DELETE FROM sessions WHERE token=?", (token,))

def create_user(username: str, password: str, role: str = "user") -> int:
    ph, salt = hash_password(password)
    c = db_exec("INSERT INTO users(username,password_hash,salt,role) VALUES(?,?,?,?)",
                (username, ph, salt, role))
    return c.lastrowid

def ensure_admin() -> Optional[str]:
    count = db_row("SELECT COUNT(*) as c FROM users WHERE role='admin'")["c"]
    if count == 0:
        pw = secrets.token_urlsafe(12)
        create_user("admin", pw, "admin")
        print(f"\n{'='*52}")
        print(f"  {APP_NAME} first-run  —  admin account created")
        print(f"  Username : admin")
        print(f"  Password : {pw}")
        print(f"{'='*52}\n")
        return pw
    return None

def _get_token_from_request(handler: "BaseHTTPRequestHandler") -> Optional[str]:
    cookie_hdr = handler.headers.get("Cookie", "")
    if cookie_hdr:
        try:
            c = SimpleCookie(cookie_hdr)
            if "session" in c:
                return c["session"].value
        except Exception:
            pass
    return handler.headers.get("X-Session-Token")

# ═══════════════════════════════════════════════════════════
#  TOOL DEFINITIONS  (16 tools)
# ═══════════════════════════════════════════════════════════
_DEFAULT_TOOLS: Dict[str, Dict] = {
    "amass": {
        "name": "Amass", "type": "enum", "step": 1,
        "cmd": "amass enum -passive -d $DOMAIN$ -o $OUTPUT$",
        "enabled": True, "max_concurrent": 2, "parse_mode": "lines",
        "description": "OWASP Amass subdomain enumeration",
    },
    "subfinder": {
        "name": "Subfinder", "type": "enum", "step": 1,
        "cmd": "subfinder -d $DOMAIN$ -o $OUTPUT$ -silent",
        "enabled": True, "max_concurrent": 3, "parse_mode": "lines",
        "description": "Fast passive subdomain enumeration",
    },
    "assetfinder": {
        "name": "Assetfinder", "type": "enum", "step": 1,
        "cmd": "assetfinder --subs-only $DOMAIN$",
        "enabled": True, "max_concurrent": 3, "parse_mode": "stdout",
        "description": "Find domains and subdomains related to a domain",
    },
    "findomain": {
        "name": "Findomain", "type": "enum", "step": 1,
        "cmd": "findomain -t $DOMAIN$ -q",
        "enabled": True, "max_concurrent": 3, "parse_mode": "stdout",
        "description": "Cross-platform subdomain enumerator",
    },
    "sublist3r": {
        "name": "Sublist3r", "type": "enum", "step": 1,
        "cmd": "sublist3r -d $DOMAIN$ -o $OUTPUT$ -n",
        "enabled": True, "max_concurrent": 2, "parse_mode": "lines",
        "description": "Sublist3r OSINT subdomain enumeration",
    },
    "crtsh": {
        "name": "crt.sh", "type": "enum", "step": 1,
        "cmd": "",  # HTTP API — no binary
        "enabled": True, "max_concurrent": 5, "parse_mode": "api",
        "description": "Certificate Transparency log search (crt.sh API)",
    },
    "github_subdomains": {
        "name": "GitHub-Subdomains", "type": "enum", "step": 1,
        "cmd": "github-subdomains -d $DOMAIN$ -t $GITHUB_TOKEN$ -o $OUTPUT$",
        "enabled": True, "max_concurrent": 2, "parse_mode": "lines",
        "description": "GitHub code search for subdomain discovery",
    },
    "theharvester": {
        "name": "theHarvester", "type": "enum", "step": 1,
        "cmd": "theHarvester -d $DOMAIN$ -b all -f $OUTPUT$",
        "enabled": True, "max_concurrent": 2, "parse_mode": "lines",
        "description": "OSINT email and subdomain harvesting",
    },
    "dnsx": {
        "name": "DNSx", "type": "dns", "step": 2,
        "cmd": "dnsx -l $INPUT_FILE$ -resp -o $OUTPUT$ -t $THREADS$",
        "enabled": True, "max_concurrent": 2, "parse_mode": "dnsx",
        "description": "Fast DNS resolver and validation",
    },
    "httpx": {
        "name": "HTTPx", "type": "http", "step": 3,
        "cmd": "httpx -l $INPUT_FILE$ -o $OUTPUT$ -title -tech-detect -status-code -threads $THREADS$ -silent -json",
        "enabled": True, "max_concurrent": 2, "parse_mode": "jsonl",
        "description": "HTTP probing, fingerprinting, and status check",
    },
    "gowitness": {
        "name": "Gowitness", "type": "screenshot", "step": 4,
        "cmd": "gowitness file -f $INPUT_FILE$ -P $OUTPUT$ --threads $THREADS$",
        "enabled": True, "max_concurrent": 1, "parse_mode": "files",
        "description": "Web screenshot capture",
    },
    "nuclei": {
        "name": "Nuclei", "type": "vuln", "step": 5,
        "cmd": "nuclei -l $INPUT_FILE$ -o $OUTPUT$ -c $THREADS$ -silent -severity medium,high,critical -json",
        "enabled": True, "max_concurrent": 1, "parse_mode": "jsonl",
        "description": "Template-based vulnerability scanner",
    },
    "nikto": {
        "name": "Nikto", "type": "vuln", "step": 6,
        "cmd": "nikto -h $SUBDOMAIN$ -o $OUTPUT$ -Format json -nointeractive",
        "enabled": True, "max_concurrent": 2, "parse_mode": "nikto",
        "description": "Web server vulnerability scanner",
    },
    "wafw00f": {
        "name": "WafW00f", "type": "recon", "step": 7,
        "cmd": "wafw00f $SUBDOMAIN$ -o $OUTPUT$ -f json",
        "enabled": True, "max_concurrent": 3, "parse_mode": "json",
        "description": "WAF detection and fingerprinting",
    },
    "ffuf": {
        "name": "ffuf", "type": "fuzz", "step": 8,
        "cmd": "ffuf -w $WORDLIST$ -u https://$SUBDOMAIN$/FUZZ -o $OUTPUT$ -of json -t $THREADS$ -mc 200,204,301,302,307",
        "enabled": True, "max_concurrent": 2, "parse_mode": "json",
        "description": "Fast web content discovery fuzzer",
    },
    "nmap": {
        "name": "Nmap", "type": "port_scan", "step": 9,
        "cmd": "nmap -sV -T4 --open -oJ $OUTPUT$ $SUBDOMAIN$",
        "enabled": True, "max_concurrent": 2, "parse_mode": "json",
        "description": "Network port scanner and service detection",
    },
    # ── Phase C Batch 1: subdomain spine ──────────────────────────
    "bbot": {
        "name": "BBOT", "type": "enum", "step": 1,
        "cmd": "bbot -t $DOMAIN$ -f subdomain-enum -o $OUTPUT$ -y --silent",
        "enabled": True, "max_concurrent": 1, "parse_mode": "bbot",
        "description": "Recursive multi-source subdomain enumeration (BBOT)",
    },
    "puredns": {
        "name": "PureDNS", "type": "dns", "step": 2,
        "cmd": "puredns resolve $INPUT_FILE$ -r $RESOLVERS_FILE$ -w $OUTPUT$ --skip-wildcard-filter",
        "enabled": True, "max_concurrent": 2, "parse_mode": "lines",
        "description": "Wildcard-DNS filter + bulk resolver (runs between enum and dnsx)",
    },
    "cdncheck": {
        "name": "CDNcheck", "type": "dns", "step": 2,
        "cmd": "cdncheck -i $INPUT_FILE$ -o $OUTPUT$ -resp",
        "enabled": True, "max_concurrent": 3, "parse_mode": "lines",
        "description": "Tag CDN/WAF-fronted IPs so downstream scans skip shared infra",
    },
    # ── Phase C Batch 2: HTTP exploration ─────────────────────────
    "katana": {
        "name": "Katana", "type": "crawl", "step": 4,
        "cmd": "katana -u $TARGET$ -o $OUTPUT$ -d 3 -jc -silent",
        "enabled": True, "max_concurrent": 2, "parse_mode": "lines",
        "description": "Headless SPA-aware crawler with JS extraction (depth-3 default)",
    },
    "feroxbuster": {
        "name": "Feroxbuster", "type": "content", "step": 8,
        "cmd": "feroxbuster -u https://$TARGET$ -w $WORDLIST$ -o $OUTPUT$ --silent --no-state",
        "enabled": True, "max_concurrent": 2, "parse_mode": "lines",
        "description": "Recursive content discovery (Rust ffuf cousin)",
    },
    "x8": {
        "name": "x8", "type": "fuzz", "step": 8,
        "cmd": "x8 -u https://$TARGET$ -w $WORDLIST$ -o $OUTPUT$ --output-format url",
        "enabled": True, "max_concurrent": 2, "parse_mode": "lines",
        "description": "Hidden HTTP parameter discovery",
    },
    "kiterunner": {
        "name": "Kiterunner", "type": "api", "step": 8,
        "cmd": "kr scan https://$TARGET$ -w $WORDLIST_DIR$/routes-large.kite -o $OUTPUT$",
        "enabled": True, "max_concurrent": 2, "parse_mode": "lines",
        "description": "Swagger/OpenAPI corpus brute (67k+ spec routes)",
    },
    # ── Phase C Batch 3: JS analysis ──────────────────────────────
    "jsluice": {
        "name": "jsluice", "type": "js", "step": 5,
        "cmd": "jsluice urls $INPUT_FILE$",
        "enabled": True, "max_concurrent": 3, "parse_mode": "stdout",
        "description": "AST-based URL + secret extraction from JS files",
    },
    "mantra": {
        "name": "Mantra", "type": "js", "step": 5,
        "cmd": "mantra -ua ReconForge -p $TARGET$",
        "enabled": True, "max_concurrent": 3, "parse_mode": "stdout",
        "description": "Regex-based API-key / secret hunter for live JS responses",
    },
    "trufflehog": {
        "name": "TruffleHog", "type": "js", "step": 5,
        "cmd": "trufflehog filesystem $INPUT_FILE$ --json --no-update",
        "enabled": True, "max_concurrent": 2, "parse_mode": "jsonl",
        "description": "High-entropy + regex secret scanner (filesystem mode)",
    },
}

def get_tools_config() -> Dict[str, Dict]:
    stored = get_config("tools", {})
    result = {}
    for k, defaults in _DEFAULT_TOOLS.items():
        result[k] = {**defaults, **stored.get(k, {})}
    return result

def get_tool(key: str) -> Dict:
    return get_tools_config().get(key, _DEFAULT_TOOLS.get(key, {}))

def is_tool_available(key: str) -> bool:
    t = get_tool(key)
    if t.get("parse_mode") == "api":
        return True
    cmd = t.get("cmd", "")
    if not cmd:
        return False
    binary = cmd.split()[0]
    return shutil.which(binary) is not None

def expand_domain(domain: str) -> List[str]:
    tlds = get_config("tld_list", DEFAULT_TLDS)
    if domain.endswith(".*"):
        base = domain[:-2]
        return [f"{base}.{tld}" for tld in tlds]
    if domain.startswith("*."):
        return [domain[2:]]
    return [domain]

def build_cmd(template: str, vars_: Dict[str, str]) -> List[str]:
    cmd = template
    for k, v in vars_.items():
        cmd = cmd.replace(k, v)
    return cmd.split()


def _standard_vars(domain: str = "", output: str = "", input_file: str = "",
                   target: str = "") -> Dict[str, str]:
    """Standard variable substitutions for tool cmd templates. Centralizes
    every placeholder we resolve from settings.json so adding a new
    tool/var is a one-line change here, not a per-runner refactor.

    Per-call placeholders (domain/output/input_file/target) are passed
    explicitly; config-driven ones (threads/wordlist/API keys/etc.) are
    read from `get_config`. Any tool's cmd_template can reference any
    placeholder — unused ones are simply not substituted.
    """
    return {
        "$DOMAIN$":             domain,
        "$TARGET$":             target or domain,
        "$SUBDOMAIN$":          target or domain,
        "$OUTPUT$":             output,
        "$INPUT_FILE$":         input_file,
        "$THREADS$":            str(get_config("threads", DEFAULT_THREADS)),
        "$WORDLIST$":           get_config("wordlist", DEFAULT_WORDLIST),
        "$WORDLIST_DIR$":       get_config("wordlist_dir", "/usr/share/seclists"),
        "$RESOLVERS_FILE$":     get_config("resolvers_file", ""),
        "$GITHUB_TOKEN$":       get_config("github_token", ""),
        "$SHODAN_KEY$":         get_config("shodan_key", ""),
        "$SECURITYTRAILS_KEY$": get_config("securitytrails_key", ""),
        "$INTERACTSH_URL$":     get_config("interactsh_url", ""),
    }

def _handle_rate_limit() -> None:
    global _rate_delay
    with _rate_lock:
        _rate_delay = min(_rate_delay + RATE_INCREMENT, MAX_RATE_DELAY)
    emit(f"Rate limit hit — delay now {_rate_delay}s", "WARNING", "ratelimit")

def _reset_rate_limit() -> None:
    global _rate_delay
    with _rate_lock:
        _rate_delay = 0.0

# ═══════════════════════════════════════════════════════════
#  TOOL GATE  (per-tool concurrency limiter)
# ═══════════════════════════════════════════════════════════
class ToolGate:
    def __init__(self, name: str, max_concurrent: int = 3):
        self.name         = name
        self.max_concurrent = max_concurrent
        self._sem         = threading.Semaphore(max_concurrent)
        self._lock        = threading.Lock()
        self.running      = 0
        self.waiting      = 0

    def acquire(self) -> None:
        with self._lock:
            self.waiting += 1
        self._sem.acquire()
        with self._lock:
            self.waiting -= 1
            self.running += 1

    def release(self) -> None:
        with self._lock:
            self.running = max(0, self.running - 1)
        self._sem.release()

    def status(self) -> Dict:
        with self._lock:
            return {"name": self.name, "running": self.running,
                    "waiting": self.waiting, "max": self.max_concurrent}

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_):
        self.release()

def init_tool_gates() -> None:
    global _tool_gates
    tools = get_tools_config()
    with _lock:
        for k, t in tools.items():
            mc = t.get("max_concurrent", 3)
            if k in _tool_gates:
                _tool_gates[k].max_concurrent = mc
            else:
                _tool_gates[k] = ToolGate(k, mc)

def _gate(key: str) -> ToolGate:
    with _lock:
        if key not in _tool_gates:
            _tool_gates[key] = ToolGate(key, 3)
        return _tool_gates[key]

# ═══════════════════════════════════════════════════════════
#  JOB  (one domain scan)
# ═══════════════════════════════════════════════════════════
_PIPELINE_STEPS = [
    "amass","subfinder","assetfinder","findomain","sublist3r",
    "crtsh","github_subdomains","theharvester",
    "dnsx","httpx","gowitness","nuclei","nikto",
]

class Job:
    def __init__(self, domain: str, username: str = "admin",
                 options: Optional[Dict] = None):
        self.id          = secrets.token_hex(8)
        self.domain      = domain
        self.username    = username
        self.options     = options or {}
        self.status      = "pending"
        self.current_step: Optional[str] = None
        self.steps_done  = 0
        self.started_at: Optional[str]   = None
        self.completed_at: Optional[str] = None
        self.error: Optional[str]        = None
        self.queued_at   = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        self.cancel_event = threading.Event()
        self.pause_event  = threading.Event()
        self.first_sub_event = threading.Event()
        self.skipped_steps: Set[str] = set()
        self._discovered: Set[str]   = set()
        self._disc_lock  = threading.Lock()
        self._logs: deque             = deque(maxlen=500)
        self._log_lock   = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        # Per-tool outcome tracking. Each entry: {status, subs, error?}.
        # status ∈ {ok, disabled, missing, rate-limited, timeout, error, skipped}.
        self.tool_results: Dict[str, Dict] = {}
        self._tr_lock     = threading.Lock()

    # — subdomain tracking ——————————————————————————
    def add_subs(self, subs: Set[str]) -> int:
        with self._disc_lock:
            before = len(self._discovered)
            for s in subs:
                s = s.strip().lower()
                if s and (s.endswith("." + self.domain) or s == self.domain):
                    self._discovered.add(s)
            added = len(self._discovered) - before
        if added > 0 and not self.first_sub_event.is_set():
            self.first_sub_event.set()
        return added

    def get_subs(self) -> Set[str]:
        with self._disc_lock:
            return set(self._discovered)

    # — logging ——————————————————————————————————————
    def log(self, msg: str, src: str = "pipeline", level: str = "INFO") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}][{src}] {msg}"
        with self._log_lock:
            self._logs.append(entry)
        add_history(self.domain, src, msg)
        emit(f"[{self.domain}] {msg}", level, src)

    def get_logs(self) -> List[str]:
        with self._log_lock:
            return list(self._logs)

    # — step tracking ————————————————————————————————
    def mark_step(self, step: str) -> None:
        self.steps_done += 1
        self.current_step = step
        row = db_row("SELECT completed_steps FROM targets WHERE domain=?", (self.domain,))
        if row:
            cs = json.loads(row["completed_steps"] or "{}")
            cs[step] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            db_exec("UPDATE targets SET completed_steps=? WHERE domain=?",
                    (json.dumps(cs), self.domain))

    def is_done(self, step: str) -> bool:
        row = db_row("SELECT completed_steps FROM targets WHERE domain=?", (self.domain,))
        if not row:
            return False
        cs = json.loads(row["completed_steps"] or "{}")
        return step in cs

    def skip(self, step: str) -> None:
        self.skipped_steps.add(step)

    # — per-tool outcome ————————————————————————————
    def record_tool_result(self, key: str, status: str,
                           subs: int = 0, error: Optional[str] = None) -> None:
        with self._tr_lock:
            self.tool_results[key] = {"status": status, "subs": subs}
            if error:
                self.tool_results[key]["error"] = error

    def enum_completed_count(self, enum_keys: List[str]) -> int:
        with self._tr_lock:
            return sum(1 for k in enum_keys if k in self.tool_results)

    def enum_summary(self, enum_keys: List[str]) -> str:
        """One-line summary: 'subfinder→47, crtsh→0 (rate-limited), amass→pending'."""
        with self._tr_lock:
            parts = []
            for k in enum_keys:
                r = self.tool_results.get(k)
                if r is None:
                    parts.append(f"{k}→pending")
                elif r["status"] == "ok":
                    parts.append(f"{k}→{r['subs']}")
                else:
                    parts.append(f"{k}→0 ({r['status']})")
            return ", ".join(parts)

    def should_skip(self, step: str) -> bool:
        return step in self.skipped_steps

    def to_dict(self) -> Dict:
        with self._tr_lock:
            tr_snapshot = dict(self.tool_results)
        return {
            "id": self.id,
            "domain": self.domain,
            "username": self.username,
            "status": self.status,
            "current_step": self.current_step,
            "steps_done": self.steps_done,
            "steps_total": len(_PIPELINE_STEPS),
            "subdomain_count": len(self._discovered),
            "queued_at": self.queued_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "tool_results": tr_snapshot,
            "logs": self.get_logs()[-20:],
        }

def get_job_dir(domain: str) -> str:
    d = os.path.join(JOBS_DIR, re.sub(r"[^\w\-.]", "_", domain))
    os.makedirs(d, exist_ok=True)
    return d

def _complete_job(job: Job, status: str = "completed") -> None:
    job.status = status
    job.completed_at = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    subs = db_rows("SELECT COUNT(*) as c FROM subdomains WHERE domain=?", (job.domain,))
    n = subs[0]["c"] if subs else 0
    db_exec(
        "INSERT INTO completed_jobs(job_id,domain,username,started_at,completed_at,status,subdomain_count) VALUES(?,?,?,?,?,?,?)",
        (job.id, job.domain, job.username, job.started_at, job.completed_at, status, n)
    )
    with _lock:
        _jobs.pop(job.id, None)
    emit(f"{job.domain} → {status} ({n} subdomains)", "INFO", "pipeline")

# ═══════════════════════════════════════════════════════════
#  SUBPROCESS HELPER
# ═══════════════════════════════════════════════════════════
def run_proc(cmd: List[str], job: Job, tool_key: str,
             timeout: int = 3600) -> Tuple[int, str, str]:
    """Run a subprocess with cancellation/pause support. Returns (rc, stdout, stderr)."""
    out_buf: List[str] = []
    err_buf: List[str] = []

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        return -1, "", f"{cmd[0]}: command not found"
    except Exception as e:
        return -1, "", str(e)

    def _read(stream, buf):
        try:
            for line in stream:
                buf.append(line)
        except Exception:
            pass

    t_o = threading.Thread(target=_read, args=(proc.stdout, out_buf), daemon=True)
    t_e = threading.Thread(target=_read, args=(proc.stderr, err_buf), daemon=True)
    t_o.start(); t_e.start()

    deadline = time.time() + timeout
    while proc.poll() is None:
        if job.cancel_event.is_set():
            proc.kill()
            break
        while job.pause_event.is_set():
            if job.cancel_event.is_set():
                proc.kill()
                break
            time.sleep(0.5)
        if time.time() > deadline:
            proc.kill()
            job.log(f"{tool_key}: timeout after {timeout}s", tool_key, "WARNING")
            break
        time.sleep(0.3)

    t_o.join(timeout=5); t_e.join(timeout=5)
    return (proc.returncode or 0), "".join(out_buf), "".join(err_buf)

# ═══════════════════════════════════════════════════════════
#  PIPELINE STEPS
# ═══════════════════════════════════════════════════════════

# ── helpers ─────────────────────────────────────────────────
def _sleep_rate(job: Job) -> bool:
    """Sleep for the current rate-limit delay. Returns False if cancelled."""
    d = _rate_delay
    if d > 0:
        end = time.time() + d
        while time.time() < end:
            if job.cancel_event.is_set():
                return False
            time.sleep(0.5)
    return True

def _flush_subs_to_db(job: Job) -> int:
    """Write in-memory discovered subdomains to SQLite. Returns count inserted."""
    subs = job.get_subs()
    if not subs:
        return 0
    db = get_db()
    added = 0
    for s in subs:
        try:
            db.execute(
                "INSERT OR IGNORE INTO subdomains(domain,subdomain) VALUES(?,?)",
                (job.domain, s)
            )
            added += db.execute("SELECT changes()").fetchone()[0]
        except Exception:
            pass
    db.commit()
    return added

def _write_sub_list(job: Job, path: str) -> int:
    """Write current discovered subdomains to a file. Returns count."""
    subs = sorted(job.get_subs())
    if not subs:
        return 0
    with open(path, "w") as f:
        f.write("\n".join(subs) + "\n")
    return len(subs)

# ── harvest loop ────────────────────────────────────────────
def _harvest_loop(job: Job) -> None:
    while not job.cancel_event.is_set():
        _flush_subs_to_db(job)
        # Check output files from disk-writing tools
        jd = get_job_dir(job.domain)
        for key in ["amass","subfinder","sublist3r","github_subdomains","theharvester"]:
            out = os.path.join(jd, f"enum_{key}.txt")
            if os.path.exists(out):
                with open(out) as f:
                    lines = {l.strip() for l in f if l.strip()}
                if lines:
                    job.add_subs(lines)
        _flush_subs_to_db(job)
        for _ in range(HARVEST_INTERVAL * 2):
            if job.cancel_event.is_set():
                return
            time.sleep(0.5)

# ── enumeration tools ────────────────────────────────────────
def _run_enum_cli(job: Job, tool_key: str) -> None:
    """Run an enumeration tool that writes to a file or stdout."""
    t = get_tool(tool_key)
    if not t.get("enabled"):
        job.record_tool_result(tool_key, "disabled")
        return
    if not is_tool_available(tool_key):
        job.record_tool_result(tool_key, "missing")
        return
    if job.should_skip(tool_key) or job.is_done(tool_key):
        job.record_tool_result(tool_key, "skipped")
        return
    if job.cancel_event.is_set():
        return

    gate = _gate(tool_key)
    with gate:
        jd   = get_job_dir(job.domain)
        # BBOT writes a directory tree, not a single file. All other enum
        # tools land at enum_<key>.txt as either stdout-parsed or file-parsed.
        mode = t.get("parse_mode", "lines")
        if mode == "bbot":
            out = os.path.join(jd, f"bbot_{tool_key}")
        else:
            out = os.path.join(jd, f"enum_{tool_key}.txt")
        cmd  = build_cmd(t["cmd"], _standard_vars(domain=job.domain, output=out))
        job.log(f"[{tool_key}] starting", tool_key)
        try:
            rc, stdout, stderr = run_proc(cmd, job, tool_key)
        except Exception as e:
            job.log(f"[{tool_key}] error: {e}", tool_key, "WARNING")
            job.record_tool_result(tool_key, "error", error=str(e))
            return

        subs: Set[str] = set()
        if mode == "stdout":
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    subs.add(line)
        elif mode == "lines" and os.path.exists(out):
            with open(out) as f:
                subs = {l.strip() for l in f if l.strip()}
        elif mode == "lines" and stdout:
            subs = {l.strip() for l in stdout.splitlines() if l.strip()}
        elif mode == "bbot" and os.path.isdir(out):
            # BBOT writes subdomains.txt under its output dir; recurse so
            # we don't depend on the exact subdir naming (varies by version).
            for root_dir, _dirs, files in os.walk(out):
                for fn in files:
                    if fn == "subdomains.txt":
                        try:
                            with open(os.path.join(root_dir, fn)) as f:
                                subs.update(l.strip() for l in f if l.strip())
                        except Exception:
                            continue

        added = job.add_subs(subs)
        job.log(f"[{tool_key}] done — {added} new subdomains", tool_key)
        job.record_tool_result(tool_key, "ok", subs=added)
        job.mark_step(tool_key)

def _run_crtsh(job: Job) -> None:
    """Query crt.sh certificate transparency API."""
    if job.should_skip("crtsh") or job.is_done("crtsh"):
        job.record_tool_result("crtsh", "skipped")
        return
    if not get_tool("crtsh").get("enabled", True):
        job.record_tool_result("crtsh", "disabled")
        return

    gate = _gate("crtsh")
    with gate:
        if not _sleep_rate(job):
            job.record_tool_result("crtsh", "rate-limited")
            return
        job.log("[crtsh] querying crt.sh", "crtsh")
        url = f"https://crt.sh/?q=%.{job.domain}&output=json"
        subs: Set[str] = set()
        status = "ok"
        err: Optional[str] = None
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and (name.endswith("." + job.domain) or name == job.domain):
                        subs.add(name)
            _reset_rate_limit()
        except urllib.error.HTTPError as e:
            if e.code == 429:
                _handle_rate_limit()
                status = "rate-limited"
            else:
                status = "error"
            err = f"HTTP {e.code}"
            job.log(f"[crtsh] HTTP {e.code}", "crtsh", "WARNING")
        except Exception as e:
            status = "error"
            err = str(e)
            job.log(f"[crtsh] error: {e}", "crtsh", "WARNING")

        added = job.add_subs(subs)
        job.log(f"[crtsh] done — {added} subdomains", "crtsh")
        job.record_tool_result("crtsh", status, subs=added, error=err)
        job.mark_step("crtsh")

# ── DNS resolution (step 2) ─────────────────────────────────
def _run_dnsx(job: Job) -> None:
    if job.should_skip("dnsx") or job.is_done("dnsx"):
        return
    t = get_tool("dnsx")
    if not t.get("enabled") or not is_tool_available("dnsx"):
        job.log("[dnsx] not available, skipping", "dnsx", "WARNING")
        return

    gate = _gate("dnsx")
    with gate:
        jd  = get_job_dir(job.domain)
        inp = os.path.join(jd, "dnsx_input.txt")
        out = os.path.join(jd, "dnsx_output.txt")
        n   = _write_sub_list(job, inp)
        if n == 0:
            return
        cmd = build_cmd(t["cmd"], {
            "$INPUT_FILE$": inp,
            "$OUTPUT$": out,
            "$THREADS$": str(get_config("threads", DEFAULT_THREADS)),
        })
        job.log(f"[dnsx] resolving {n} hosts", "dnsx")
        rc, stdout, _ = run_proc(cmd, job, "dnsx")

        # Parse: "sub.example.com [1.2.3.4]"
        db = get_db()
        if os.path.exists(out):
            with open(out) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    m = re.match(r"^(\S+)\s*\[([^\]]+)\]", line)
                    if m:
                        sub, ip = m.group(1), m.group(2)
                    else:
                        sub, ip = line, ""
                    ips_json = json.dumps([ip] if ip else [])
                    db.execute(
                        "INSERT OR IGNORE INTO subdomains(domain,subdomain) VALUES(?,?)",
                        (job.domain, sub))
                    db.execute(
                        "UPDATE subdomains SET dns_resolved=1, ip_addresses=?, updated_at=datetime('now')"
                        " WHERE domain=? AND subdomain=?",
                        (ips_json, job.domain, sub))
        db.commit()
        job.log("[dnsx] done", "dnsx")
        job.mark_step("dnsx")

# ── HTTP probing (step 3) ────────────────────────────────────
def _run_httpx(job: Job) -> None:
    if job.should_skip("httpx") or job.is_done("httpx"):
        return
    t = get_tool("httpx")
    if not t.get("enabled") or not is_tool_available("httpx"):
        job.log("[httpx] not available, skipping", "httpx", "WARNING")
        return

    gate = _gate("httpx")
    with gate:
        jd  = get_job_dir(job.domain)
        inp = os.path.join(jd, "httpx_input.txt")
        out = os.path.join(jd, "httpx_output.jsonl")
        n   = _write_sub_list(job, inp)
        if n == 0:
            return
        cmd = build_cmd(t["cmd"], {
            "$INPUT_FILE$": inp,
            "$OUTPUT$": out,
            "$THREADS$": str(get_config("threads", DEFAULT_THREADS)),
        })
        job.log(f"[httpx] probing {n} hosts", "httpx")
        run_proc(cmd, job, "httpx")

        db = get_db()
        if os.path.exists(out):
            with open(out) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    url  = e.get("url", e.get("input", ""))
                    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
                    status = e.get("status_code", e.get("status", None))
                    title  = e.get("title", "")
                    tech   = json.dumps(e.get("tech", e.get("technologies", [])))
                    db.execute(
                        "INSERT OR IGNORE INTO subdomains(domain,subdomain) VALUES(?,?)",
                        (job.domain, host))
                    db.execute(
                        "UPDATE subdomains SET http_status=?, http_title=?, http_technologies=?,"
                        " updated_at=datetime('now') WHERE domain=? AND subdomain=?",
                        (status, title, tech, job.domain, host))
        db.commit()
        job.log("[httpx] done", "httpx")
        job.mark_step("httpx")

# ── screenshots (step 4) ─────────────────────────────────────
def _run_gowitness(job: Job) -> None:
    if job.should_skip("gowitness") or job.is_done("gowitness"):
        return
    t = get_tool("gowitness")
    if not t.get("enabled") or not is_tool_available("gowitness"):
        job.log("[gowitness] not available, skipping", "gowitness", "WARNING")
        return

    gate = _gate("gowitness")
    with gate:
        jd  = get_job_dir(job.domain)
        # Build URL list from http-probed hosts
        rows = db_rows(
            "SELECT subdomain, http_status FROM subdomains WHERE domain=? AND http_status IS NOT NULL",
            (job.domain,))
        if not rows:
            job.log("[gowitness] no live hosts, skipping", "gowitness")
            return
        inp = os.path.join(jd, "gowitness_urls.txt")
        with open(inp, "w") as f:
            for r in rows:
                scheme = "https" if r["http_status"] in (443,) else "http"
                f.write(f"{scheme}://{r['subdomain']}\n")

        out_dir = os.path.join(SCREENSHOTS_DIR, re.sub(r"[^\w\-.]", "_", job.domain))
        os.makedirs(out_dir, exist_ok=True)
        cmd = build_cmd(t["cmd"], {
            "$INPUT_FILE$": inp,
            "$OUTPUT$": out_dir,
            "$THREADS$": str(get_config("threads", 5)),
        })
        job.log(f"[gowitness] capturing {len(rows)} screenshots", "gowitness")
        run_proc(cmd, job, "gowitness", timeout=1800)

        # Update screenshot paths in DB
        db = get_db()
        for fname in os.listdir(out_dir):
            if fname.endswith(".png"):
                host = fname.replace("http-", "").replace("https-", "").rstrip(".png")
                db.execute(
                    "UPDATE subdomains SET screenshot_path=? WHERE domain=? AND subdomain LIKE ?",
                    (os.path.join(out_dir, fname), job.domain, f"%{host}%"))
        db.commit()
        job.log("[gowitness] done", "gowitness")
        job.mark_step("gowitness")

# ── nuclei (step 5) ─────────────────────────────────────────
def _run_nuclei(job: Job) -> None:
    if job.should_skip("nuclei") or job.is_done("nuclei"):
        return
    t = get_tool("nuclei")
    if not t.get("enabled") or not is_tool_available("nuclei"):
        job.log("[nuclei] not available, skipping", "nuclei", "WARNING")
        return

    gate = _gate("nuclei")
    with gate:
        jd  = get_job_dir(job.domain)
        inp = os.path.join(jd, "nuclei_input.txt")
        out = os.path.join(jd, "nuclei_output.jsonl")
        rows = db_rows(
            "SELECT subdomain,http_status FROM subdomains WHERE domain=? AND http_status IS NOT NULL",
            (job.domain,))
        if not rows:
            return
        with open(inp, "w") as f:
            for r in rows:
                f.write(r["subdomain"] + "\n")
        cmd = build_cmd(t["cmd"], {
            "$INPUT_FILE$": inp,
            "$OUTPUT$": out,
            "$THREADS$": str(get_config("threads", DEFAULT_THREADS)),
        })
        job.log(f"[nuclei] scanning {len(rows)} targets", "nuclei")
        run_proc(cmd, job, "nuclei", timeout=7200)

        db = get_db()
        if os.path.exists(out):
            findings: Dict[str, List] = {}
            with open(out) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    host = e.get("host", "")
                    h = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
                    findings.setdefault(h, []).append({
                        "template": e.get("template-id", ""),
                        "name": e.get("info", {}).get("name", ""),
                        "severity": e.get("info", {}).get("severity", ""),
                        "matched": e.get("matched-at", ""),
                    })
            for host, flist in findings.items():
                db.execute(
                    "UPDATE subdomains SET nuclei_findings=?, interesting=1,"
                    " updated_at=datetime('now') WHERE domain=? AND subdomain=?",
                    (json.dumps(flist), job.domain, host))
        db.commit()
        job.log("[nuclei] done", "nuclei")
        job.mark_step("nuclei")

# ── nikto (step 6) ──────────────────────────────────────────
def _run_nikto(job: Job) -> None:
    if job.should_skip("nikto") or job.is_done("nikto"):
        return
    t = get_tool("nikto")
    if not t.get("enabled") or not is_tool_available("nikto"):
        job.log("[nikto] not available, skipping", "nikto", "WARNING")
        return

    gate = _gate("nikto")
    rows = db_rows(
        "SELECT subdomain FROM subdomains WHERE domain=? AND http_status IS NOT NULL",
        (job.domain,))
    if not rows:
        return

    jd = get_job_dir(job.domain)
    nikto_dir = os.path.join(jd, "nikto")
    os.makedirs(nikto_dir, exist_ok=True)

    for row in rows:
        if job.cancel_event.is_set():
            break
        while job.pause_event.is_set():
            if job.cancel_event.is_set():
                break
            time.sleep(1)

        sub = row["subdomain"]
        out = os.path.join(nikto_dir, re.sub(r"[^\w\-.]", "_", sub) + ".json")
        cmd = build_cmd(t["cmd"], {
            "$SUBDOMAIN$": sub,
            "$OUTPUT$": out,
        })
        with gate:
            job.log(f"[nikto] scanning {sub}", "nikto")
            run_proc(cmd, job, "nikto", timeout=600)
            if os.path.exists(out):
                try:
                    data = json.load(open(out))
                    vulns = data.get("vulnerabilities", data if isinstance(data, list) else [])
                    if vulns:
                        db_exec(
                            "UPDATE subdomains SET nikto_results=?, interesting=1,"
                            " updated_at=datetime('now') WHERE domain=? AND subdomain=?",
                            (json.dumps(vulns), job.domain, sub))
                except Exception:
                    pass

    job.log("[nikto] done", "nikto")
    job.mark_step("nikto")

# ── main orchestrator ────────────────────────────────────────
def run_pipeline(job: Job) -> None:
    try:
        job.status = "running"
        job.started_at = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        # Ensure target row exists
        db_exec("INSERT OR IGNORE INTO targets(domain) VALUES(?)", (job.domain,))

        # ── Phase 1: enumeration (all 8 tools in parallel) ──
        job.current_step = "enumeration"
        job.log("Starting enumeration phase", "pipeline")

        enum_keys = ["amass","subfinder","assetfinder","findomain",
                     "sublist3r","crtsh","github_subdomains","theharvester"]

        # Pre-flight tool availability audit. Surface missing-binary problems
        # up front so the user sees one banner instead of a silent abort.
        avail: List[str] = []
        unavail: List[str] = []
        skip_set: Set[str] = set()
        for key in enum_keys:
            t = get_tool(key)
            if not t.get("enabled"):
                unavail.append(f"{key} (disabled)")
                skip_set.add(key)
                job.record_tool_result(key, "disabled")
                continue
            if not is_tool_available(key):
                unavail.append(f"{key} (not installed)")
                skip_set.add(key)
                job.record_tool_result(key, "missing")
                job.log(f"MISSING TOOL: {key} — binary not on PATH", "pipeline", "WARNING")
                continue
            avail.append(key)
        if unavail:
            job.log(
                f"Enum tools: {len(avail)} available ({', '.join(avail) or 'none'}), "
                f"{len(unavail)} unavailable ({', '.join(unavail)}). "
                f"Run installer/install.sh to fix missing binaries.",
                "pipeline", "WARNING")
        else:
            job.log(f"Enum tools: all {len(avail)} available", "pipeline")

        enum_threads = []
        for key in enum_keys:
            if job.cancel_event.is_set():
                break
            if key in skip_set:
                continue
            t = threading.Thread(
                target=(_run_crtsh if key == "crtsh" else _run_enum_cli),
                args=(job,) if key == "crtsh" else (job, key),
                daemon=True,
                name=f"enum-{key}-{job.id}"
            )
            t.start()
            enum_threads.append(t)

        # Start harvest loop
        harvest_t = threading.Thread(target=_harvest_loop, args=(job,),
                                     daemon=True, name=f"harvest-{job.id}")
        harvest_t.start()

        # Wait for first subdomain. Don't abort on wall-clock alone — give the
        # tools a chance to finish-or-fail (at least min_enum_tools_required of
        # them). Hardened targets like Rivian can take >5 minutes for amass
        # passive mode to return anything useful.
        timeout = int(get_config("first_sub_timeout", FIRST_SUB_TIMEOUT))
        min_req = int(get_config("min_enum_tools_required", MIN_ENUM_TOOLS_REQUIRED))
        deadline = time.time() + timeout
        triggered = False
        while True:
            if job.first_sub_event.wait(timeout=5):
                triggered = True
                break
            if job.cancel_event.is_set():
                break
            past_deadline = time.time() >= deadline
            completed = job.enum_completed_count(enum_keys)
            if past_deadline and completed >= min_req:
                break
            # If every launched enum thread has finished and still no subs,
            # there is nothing more to wait for — abort early instead of
            # burning the rest of the wall-clock timeout.
            if all(not t.is_alive() for t in enum_threads):
                break
        if not triggered:
            summary = job.enum_summary(enum_keys)
            job.log(
                f"No subdomains discovered. Enum results: {summary}. "
                f"Common causes: enum binaries not installed, crt.sh rate-limit, "
                f"WAF blocking, or target has no public subdomains.",
                "pipeline", "WARNING")
            job.cancel_event.set()
            for t in enum_threads:
                t.join(timeout=5)
            _complete_job(job, "failed")
            job.error = "No subdomains discovered"
            return

        # Got at least one subdomain — log the partial result tally so the
        # operator can see which tools contributed.
        job.log(f"Enum partial results: {job.enum_summary(enum_keys)}", "pipeline")

        if job.cancel_event.is_set():
            _complete_job(job, "cancelled")
            return

        # Flush immediately
        _flush_subs_to_db(job)

        # ── Phase 2: DNS resolution ──────────────────────────
        _run_dnsx(job)
        if job.cancel_event.is_set():
            _complete_job(job, "cancelled"); return

        # ── Phase 3: HTTP probing ────────────────────────────
        _run_httpx(job)
        if job.cancel_event.is_set():
            _complete_job(job, "cancelled"); return

        # ── Phase 4+5: screenshots + nuclei (parallel) ───────
        t_shot = threading.Thread(target=_run_gowitness, args=(job,),
                                  daemon=True, name=f"gowitness-{job.id}")
        t_nuc  = threading.Thread(target=_run_nuclei, args=(job,),
                                  daemon=True, name=f"nuclei-{job.id}")
        t_shot.start(); t_nuc.start()
        t_shot.join(); t_nuc.join()

        if job.cancel_event.is_set():
            _complete_job(job, "cancelled"); return

        # Wait for all enumeration to complete before nikto
        for t in enum_threads:
            t.join(timeout=600)
        _flush_subs_to_db(job)

        # ── Phase 6: Nikto ───────────────────────────────────
        _run_nikto(job)

        # Final flush
        _flush_subs_to_db(job)
        _complete_job(job, "completed")

    except Exception as e:
        job.error = str(e)
        job.log(f"Pipeline error: {traceback.format_exc()}", "pipeline", "ERROR")
        _complete_job(job, "failed")

# ═══════════════════════════════════════════════════════════
#  JOB DISPATCH
# ═══════════════════════════════════════════════════════════
def _active_program() -> Optional[Dict[str, Any]]:
    """Load the active program scope from config. None = guard bypassed.

    Set via config["active_program"] = "scopes/<name>.json" (relative to repo
    root, or absolute). Wizard will write this in Phase 11; for now, set with
    set_config("active_program", "scopes/rivian.json") from a Python shell.
    """
    path = get_config("active_program")
    if not path:
        return None
    full = path if os.path.isabs(path) else os.path.join(_BASE, path)
    try:
        with open(full, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        emit(f"Could not load active program {path}: {e}", "ERROR", "scope_guard")
        return None


def submit_domain(raw_domain: str, username: str,
                  options: Optional[Dict] = None) -> List["Job"]:
    """Expand wildcards then enqueue jobs. Returns list of Job objects.

    Scope Guard (Phase 1) gates every expanded target. Rejected domains are
    logged to history and skipped — they never become Job objects.
    """
    jobs = []
    prog = _active_program()
    for domain in expand_domain(raw_domain.strip().lower()):
        if prog is not None:
            result = scope_guard.check(domain, prog)
            if not result["allowed"]:
                add_history(domain, "scope_guard",
                            f"REJECTED ({username}): {result['reason']}")
                emit(f"Scope Guard rejected {domain}: {result['reason']}",
                     "WARNING", "scope_guard")
                continue
        job = Job(domain, username, options)
        with _lock:
            _jobs[job.id] = job
        _pending.put(job)
        jobs.append(job)
        add_history(domain, "dispatch", f"Job {job.id} queued by {username}")
    return jobs

def _max_jobs() -> int:
    return int(get_config("max_running_jobs", 5))

def _running_count() -> int:
    with _lock:
        return sum(1 for j in _jobs.values() if j.status == "running")

def _dispatcher_worker() -> None:
    while not _shutdown.is_set():
        try:
            if _running_count() < _max_jobs():
                try:
                    job = _pending.get(timeout=1)
                except queue.Empty:
                    continue
                if job.cancel_event.is_set():
                    with _lock:
                        _jobs.pop(job.id, None)
                    continue
                job._thread = threading.Thread(
                    target=run_pipeline, args=(job,),
                    daemon=True, name=f"pipeline-{job.id}")
                job._thread.start()
            else:
                time.sleep(1)
        except Exception as e:
            emit(f"Dispatcher error: {e}", "ERROR", "dispatcher")

# ═══════════════════════════════════════════════════════════
#  BACKUP / RESTORE
# ═══════════════════════════════════════════════════════════
def create_backup(label: Optional[str] = None) -> str:
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"backup_{label or ts}.tar.gz"
    path = os.path.join(BACKUP_DIR, name)

    snap = os.path.join(TEMP_DIR, f"snap_{ts}.db")
    try:
        src = get_db()
        dst = sqlite3.connect(snap)
        src.backup(dst)
        dst.close()

        with tarfile.open(path, "w:gz") as tar:
            tar.add(snap, arcname="recon.db")
            if os.path.isdir(SCREENSHOTS_DIR):
                tar.add(SCREENSHOTS_DIR, arcname="screenshots")
    finally:
        if os.path.exists(snap):
            os.unlink(snap)

    # Prune old backups
    _prune_backups()
    emit(f"Backup created: {name}", "INFO", "backup")
    return name

def list_backups() -> List[Dict]:
    result = []
    for f in sorted(Path(BACKUP_DIR).glob("backup_*.tar.gz"), reverse=True):
        stat = f.stat()
        result.append({
            "name": f.name,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%dT%H:%M:%S"),
        })
    return result

def _prune_backups() -> None:
    backups = sorted(Path(BACKUP_DIR).glob("backup_*.tar.gz"),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[MAX_BACKUPS:]:
        old.unlink(missing_ok=True)

def restore_backup(name: str) -> None:
    path = os.path.join(BACKUP_DIR, name)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Backup not found: {name}")
    running = _running_count()
    if running > 0:
        raise RuntimeError(f"Cannot restore while {running} job(s) are running")

    with tarfile.open(path, "r:gz") as tar:
        tar.extractall(DATA_DIR)
    # Force DB reconnect
    _db_local.conn = None
    _cfg_cache.clear()
    emit(f"Restored from {name}", "INFO", "backup")

# ═══════════════════════════════════════════════════════════
#  BACKGROUND WORKERS
# ═══════════════════════════════════════════════════════════
def _resource_worker() -> None:
    while not _shutdown.is_set():
        try:
            if HAS_PSUTIL:
                cpu = _psutil.cpu_percent(interval=1)
                mem = _psutil.virtual_memory().percent
                dsk = _psutil.disk_usage(DATA_DIR).percent
            else:
                cpu = mem = dsk = 0.0
            entry = {"ts": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                     "cpu": cpu, "mem": mem, "disk": dsk}
            _res_buf.append(entry)
            db_exec(
                "INSERT INTO system_resources(cpu_percent,memory_percent,disk_percent) VALUES(?,?,?)",
                (cpu, mem, dsk))
            # Trim old rows. Commit each statement: WAL allows concurrent
            # readers but only ONE writer, and an uncommitted write
            # transaction holds the write lock — leaving it open for ~60s
            # was blocking session INSERTs during login.
            cutoff = (datetime.now() - timedelta(seconds=RESOURCE_RETENTION)).strftime("%Y-%m-%dT%H:%M:%S")
            db_exec("DELETE FROM system_resources WHERE created_at < ?", (cutoff,))
        except Exception as e:
            pass
        _shutdown.wait(RESOURCE_INTERVAL)

def _dynamic_worker() -> None:
    while not _shutdown.is_set():
        if HAS_PSUTIL:
            try:
                cpu = _psutil.cpu_percent(interval=0.5)
                mem = _psutil.virtual_memory().percent
                current = _max_jobs()
                lo = int(get_config("dyn_min_jobs", 1))
                hi = int(get_config("dyn_max_jobs", 10))
                if cpu >= CPU_CRIT or mem >= MEM_CRIT:
                    new = max(lo, current - 1)
                elif cpu >= CPU_WARN or mem >= MEM_WARN:
                    new = current  # hold
                else:
                    new = min(hi, current + 1)
                if new != current and get_config("dynamic_mode", False):
                    set_config("max_running_jobs", new)
                    emit(f"Dynamic: max_jobs → {new} (cpu={cpu:.0f}% mem={mem:.0f}%)",
                         "INFO", "dynamic")
            except Exception:
                pass
        _shutdown.wait(DYNAMIC_INTERVAL)

def _monitor_worker() -> None:
    while not _shutdown.is_set():
        try:
            mons = db_rows("SELECT * FROM monitors WHERE enabled=1")
            for m in mons:
                _check_monitor(m)
        except Exception as e:
            emit(f"Monitor error: {e}", "ERROR", "monitor")
        _shutdown.wait(MONITOR_INTERVAL)

def _check_monitor(mon: sqlite3.Row) -> None:
    try:
        url = mon["url"]
        if url.startswith("file://"):
            with open(url[7:]) as f:
                content = f.read()
        else:
            req = urllib.request.Request(
                url, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
            with urllib.request.urlopen(req, timeout=10) as r:
                if r.status == 429:
                    _handle_rate_limit(); return
                content = r.read().decode()
        seen = set(json.loads(mon["seen_entries"] or "[]"))
        new_domains = [
            line.strip() for line in content.splitlines()
            if line.strip() and line.strip() not in seen
        ]
        if new_domains:
            for d in new_domains:
                seen.add(d)
                submit_domain(d, "monitor")
                add_history(d, "monitor", f"Auto from monitor '{mon['name']}'")
        db_exec(
            "UPDATE monitors SET last_checked=?,last_result=?,last_count=?,seen_entries=? WHERE id=?",
            (datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
             f"{len(new_domains)} new" if new_domains else "no change",
             len(new_domains), json.dumps(list(seen)), mon["id"]))
    except Exception as e:
        emit(f"Monitor '{mon['name']}' error: {e}", "WARNING", "monitor")

def _backup_worker() -> None:
    while not _shutdown.is_set():
        interval = int(get_config("backup_interval", BACKUP_INTERVAL))
        _shutdown.wait(interval)
        if _shutdown.is_set():
            break
        if get_config("auto_backup", True):
            try:
                create_backup()
            except Exception as e:
                emit(f"Auto-backup failed: {e}", "ERROR", "backup")

def _cleanup_worker() -> None:
    while not _shutdown.is_set():
        _shutdown.wait(CLEANUP_INTERVAL)
        if _shutdown.is_set():
            break
        try:
            # Temp files
            cutoff = time.time() - CLEANUP_TEMP_H * 3600
            for p in Path(TEMP_DIR).iterdir():
                if p.stat().st_mtime < cutoff:
                    p.unlink(missing_ok=True)
            # Old scan directories
            cutoff_dt = datetime.now() - timedelta(days=CLEANUP_DAYS)
            for p in Path(JOBS_DIR).iterdir():
                if p.is_dir():
                    mtime = datetime.fromtimestamp(p.stat().st_mtime)
                    if mtime < cutoff_dt:
                        shutil.rmtree(p, ignore_errors=True)
            emit("Cleanup complete", "INFO", "cleanup")
        except Exception as e:
            emit(f"Cleanup error: {e}", "ERROR", "cleanup")

def _session_cleanup_worker() -> None:
    while not _shutdown.is_set():
        _shutdown.wait(SESSION_CLEANUP)
        if _shutdown.is_set():
            break
        try:
            db_exec("DELETE FROM sessions WHERE expires_at < datetime('now')")
        except Exception:
            pass

def start_workers() -> None:
    for target, name in [
        (_dispatcher_worker,       "dispatcher"),
        (_resource_worker,         "resources"),
        (_dynamic_worker,          "dynamic"),
        (_monitor_worker,          "monitors"),
        (_backup_worker,           "autobackup"),
        (_cleanup_worker,          "cleanup"),
        (_session_cleanup_worker,  "session-gc"),
    ]:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
    emit("All background workers started", "INFO", "system")

# ═══════════════════════════════════════════════════════════
#  HTTP SERVER  (request handler)
# ═══════════════════════════════════════════════════════════
class ReconHandler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}/{VERSION}"

    def log_message(self, fmt, *args):
        # Route access log through emit() so it shows up alongside other server
        # output. Set RECONFORGE_QUIET_ACCESS_LOG=1 to suppress.
        if os.environ.get("RECONFORGE_QUIET_ACCESS_LOG"):
            return
        try:
            emit(fmt % args, "INFO", "http")
        except Exception:
            pass

    # ── routing ─────────────────────────────────────────────
    def do_GET(self):    self._dispatch("GET")
    def do_POST(self):   self._dispatch("POST")
    def do_PUT(self):    self._dispatch("PUT")
    def do_DELETE(self): self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        try:
            parsed = urllib.parse.urlparse(self.path)
            path   = parsed.path.rstrip("/") or "/"
            qs     = urllib.parse.parse_qs(parsed.query)

            # ── public endpoints ──────────────────────────────
            if path in ("/login", "/") and method == "GET":
                return self._serve_frontend()
            if path == "/api/login" and method == "POST":
                return self._api_login()

            # ── require session for everything else ───────────
            session = self._require_session()
            if session is None:
                if path.startswith("/api/"):
                    return self._err("Authentication required", 401)
                return self._redirect("/login")

            # ── v2 router (Phase 13+) ────────────────────────
            if path.startswith("/api/v2/"):
                from api.server import dispatch as _v2_dispatch
                body = self._body_json() if method in ("POST", "PUT") else None
                status, payload = _v2_dispatch(method, path, qs, body, get_db())
                return self._json(payload, status)

            if method == "GET":
                self._route_get(path, qs, session)
            elif method == "POST":
                self._route_post(path, qs, session)
            elif method == "PUT":
                self._route_put(path, qs, session)
            elif method == "DELETE":
                self._route_delete(path, qs, session)
            else:
                self._err("Method not allowed", 405)
        except BrokenPipeError:
            pass
        except Exception:
            emit(f"Handler error\n{traceback.format_exc()}", "ERROR", "http")
            try:
                self._err("Internal server error", 500)
            except Exception:
                pass

    def _route_get(self, path: str, qs: Dict, session: Dict) -> None:
        # state
        if path == "/api/state":
            return self._api_state(session)
        # jobs
        if path == "/api/jobs":
            return self._api_jobs_list()
        m = re.match(r"^/api/jobs/([a-f0-9]+)/logs$", path)
        if m:
            return self._api_job_logs(m.group(1))
        m = re.match(r"^/api/jobs/([a-f0-9]+)$", path)
        if m:
            return self._api_job_detail(m.group(1))
        # targets / subdomains / reports
        if path == "/api/targets":
            return self._api_targets_list()
        m = re.match(r"^/api/targets/([^/]+)$", path)
        if m:
            return self._api_target_detail(urllib.parse.unquote(m.group(1)))
        m = re.match(r"^/api/subdomains/([^/]+)$", path)
        if m:
            return self._api_subdomains(urllib.parse.unquote(m.group(1)), qs)
        m = re.match(r"^/api/reports/([^/]+)$", path)
        if m:
            return self._api_report(urllib.parse.unquote(m.group(1)), qs)
        # config / history / logs
        if path == "/api/config":
            return self._api_config_get()
        if path == "/api/history":
            return self._api_history(qs)
        if path == "/api/logs":
            return self._api_logs(qs)
        # monitors
        if path == "/api/monitors":
            return self._api_monitors_list()
        # resources / workers
        if path == "/api/resources":
            return self._api_resources()
        if path == "/api/workers":
            return self._api_workers()
        # users (admin only)
        if path == "/api/users":
            if session.get("role") != "admin":
                return self._err("Forbidden", 403)
            return self._api_users_list()
        # backups (admin only)
        if path == "/api/backups":
            if session.get("role") != "admin":
                return self._err("Forbidden", 403)
            return self._ok(list_backups())
        # gallery
        m = re.match(r"^/gallery/([^/]+)$", path)
        if m:
            return self._serve_gallery(urllib.parse.unquote(m.group(1)), qs)
        m = re.match(r"^/api/gallery/([^/]+)$", path)
        if m:
            return self._api_gallery(urllib.parse.unquote(m.group(1)), qs)
        # screenshots
        m = re.match(r"^/screenshots/(.+)$", path)
        if m:
            return self._serve_file(os.path.join(DATA_DIR, "screenshots", m.group(1)))

        self._err("Not found", 404)

    def _route_post(self, path: str, qs: Dict, session: Dict) -> None:
        if path == "/api/logout":
            return self._api_logout(session)
        if path == "/api/jobs":
            return self._api_jobs_create(session)
        m = re.match(r"^/api/jobs/([a-f0-9]+)/(pause|resume|cancel|skip-step)$", path)
        if m:
            return self._api_job_action(m.group(1), m.group(2), session)
        if path == "/api/monitors":
            return self._api_monitors_create()
        if path == "/api/users":
            if session.get("role") != "admin":
                return self._err("Forbidden", 403)
            return self._api_users_create(session)
        if path == "/api/backups":
            if session.get("role") != "admin":
                return self._err("Forbidden", 403)
            return self._api_backup_create()
        m = re.match(r"^/api/backups/restore/(.+)$", path)
        if m:
            if session.get("role") != "admin":
                return self._err("Forbidden", 403)
            return self._api_backup_restore(m.group(1))
        self._err("Not found", 404)

    def _route_put(self, path: str, qs: Dict, session: Dict) -> None:
        if path == "/api/config":
            if session.get("role") != "admin":
                return self._err("Forbidden", 403)
            return self._api_config_put()
        m = re.match(r"^/api/monitors/(\d+)$", path)
        if m:
            return self._api_monitors_update(int(m.group(1)))
        m = re.match(r"^/api/targets/([^/]+)$", path)
        if m:
            return self._api_target_update(urllib.parse.unquote(m.group(1)))
        m = re.match(r"^/api/users/(\d+)$", path)
        if m:
            if session.get("role") != "admin":
                return self._err("Forbidden", 403)
            return self._api_users_update(int(m.group(1)))
        self._err("Not found", 404)

    def _route_delete(self, path: str, qs: Dict, session: Dict) -> None:
        m = re.match(r"^/api/monitors/(\d+)$", path)
        if m:
            return self._api_monitors_delete(int(m.group(1)))
        m = re.match(r"^/api/targets/([^/]+)$", path)
        if m:
            return self._api_target_delete(urllib.parse.unquote(m.group(1)))
        m = re.match(r"^/api/users/(\d+)$", path)
        if m:
            if session.get("role") != "admin":
                return self._err("Forbidden", 403)
            return self._api_users_delete(int(m.group(1)), session)
        self._err("Not found", 404)

    # ── response helpers ─────────────────────────────────────
    def _ok(self, data: Any = None, msg: str = "OK") -> None:
        self._json({"success": True, "message": msg, "data": data})

    def _err(self, msg: str, status: int = 400) -> None:
        self._json({"success": False, "message": msg}, status)

    def _json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _serve_frontend(self) -> None:
        body = FRONTEND_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, path: str) -> None:
        if not os.path.exists(path):
            return self._err("Not found", 404)
        mt, _ = mimetypes.guess_type(path)
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", mt or "application/octet-stream")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _require_session(self) -> Optional[Dict]:
        token = _get_token_from_request(self)
        return get_session(token) if token else None

    def _body_json(self) -> Optional[Dict]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            return json.loads(raw)
        except Exception:
            return None

    # ── API: auth ────────────────────────────────────────────
    def _api_login(self) -> None:
        body = self._body_json()
        if not body:
            return self._err("Invalid JSON")
        username = body.get("username", "").strip()
        password = body.get("password", "")
        row = db_row("SELECT id,password_hash,salt,role FROM users WHERE username=?",
                     (username,))
        if not row or not verify_password(password, row["password_hash"], row["salt"]):
            return self._err("Invalid credentials", 401)
        token = create_session(row["id"], username, row["role"])
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        # Max-Age is relative seconds — immune to client/server clock skew,
        # which bit us on VMs whose RTC drifted from real UTC.
        self.send_header("Set-Cookie",
                         f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}")
        body_b = json.dumps({"success": True, "message": "OK",
                             "data": {"role": row["role"], "username": username}}).encode()
        self.send_header("Content-Length", len(body_b))
        self.end_headers()
        self.wfile.write(body_b)

    def _api_logout(self, session: Dict) -> None:
        token = _get_token_from_request(self)
        if token:
            delete_session(token)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie",
                         "session=; Path=/; HttpOnly; Max-Age=0")
        body_b = json.dumps({"success": True, "message": "Logged out"}).encode()
        self.send_header("Content-Length", len(body_b))
        self.end_headers()
        self.wfile.write(body_b)

    # ── API: state ───────────────────────────────────────────
    def _api_state(self, session: Dict) -> None:
        with _lock:
            jobs_snap = list(_jobs.values())
        running = [j.to_dict() for j in jobs_snap if j.status == "running"]
        pending_jobs = [j.to_dict() for j in jobs_snap if j.status == "pending"]
        completed = rows_to_list(db_rows(
            "SELECT * FROM completed_jobs ORDER BY completed_at DESC LIMIT 20"))
        stats = {
            "total_domains":    (db_row("SELECT COUNT(*) as c FROM targets") or {"c":0})["c"],
            "total_subdomains": (db_row("SELECT COUNT(*) as c FROM subdomains") or {"c":0})["c"],
            "total_findings":   (db_row("SELECT COUNT(*) as c FROM subdomains WHERE interesting=1") or {"c":0})["c"],
            "running_count":    len(running),
            "queued_count":     len(pending_jobs),
        }
        with _lock:
            workers = {k: g.status() for k, g in _tool_gates.items()}
        res_list = list(_res_buf)
        resources = {
            "cpu":          res_list[-1]["cpu"]  if res_list else 0,
            "memory":       res_list[-1]["mem"]  if res_list else 0,
            "disk":         res_list[-1]["disk"] if res_list else 0,
            "cpu_history":  [r["cpu"]  for r in res_list[-60:]],
            "mem_history":  [r["mem"]  for r in res_list[-60:]],
            "disk_history": [r["disk"] for r in res_list[-60:]],
        }
        self._ok({
            "running_jobs":   running,
            "queued_jobs":    pending_jobs,
            "completed_jobs": completed,
            "stats":          stats,
            "workers":        workers,
            "resources":      resources,
            "max_jobs":       _max_jobs(),
            "dynamic_mode":   get_config("dynamic_mode", False),
            "rate_delay":     _rate_delay,
            "session":        {"username": session["username"], "role": session["role"]},
        })

    # ── API: jobs ────────────────────────────────────────────
    def _api_jobs_list(self) -> None:
        with _lock:
            snap = [j.to_dict() for j in _jobs.values()]
        hist = rows_to_list(db_rows(
            "SELECT * FROM completed_jobs ORDER BY completed_at DESC LIMIT 50"))
        self._ok({"active": snap, "history": hist})

    def _api_job_detail(self, job_id: str) -> None:
        with _lock:
            job = _jobs.get(job_id)
        if job:
            return self._ok(job.to_dict())
        row = db_row("SELECT * FROM completed_jobs WHERE job_id=?", (job_id,))
        if row:
            return self._ok(dict(row))
        self._err("Job not found", 404)

    def _api_job_logs(self, job_id: str) -> None:
        with _lock:
            job = _jobs.get(job_id)
        if not job:
            return self._err("Job not found", 404)
        self._ok(job.get_logs())

    def _api_jobs_create(self, session: Dict) -> None:
        body = self._body_json()
        if not body:
            return self._err("Invalid JSON")
        domain = body.get("domain", "").strip()
        if not domain:
            return self._err("domain is required")
        opts = body.get("options", {})
        jobs = submit_domain(domain, session["username"], opts)
        self._ok([j.to_dict() for j in jobs], f"{len(jobs)} job(s) queued")

    def _api_job_action(self, job_id: str, action: str, session: Dict) -> None:
        with _lock:
            job = _jobs.get(job_id)
        if not job:
            return self._err("Job not found", 404)
        if session.get("role") != "admin" and job.username != session["username"]:
            return self._err("Forbidden", 403)
        if action == "pause":
            job.pause_event.set()
            job.status = "paused"
        elif action == "resume":
            job.pause_event.clear()
            job.status = "running"
        elif action == "cancel":
            job.cancel_event.set()
            job.status = "cancelled"
        elif action == "skip-step":
            if job.current_step:
                job.skip(job.current_step)
        self._ok(job.to_dict(), f"Action '{action}' applied")

    # ── API: targets ─────────────────────────────────────────
    def _api_targets_list(self) -> None:
        rows = db_rows("""
            SELECT t.*,
                   (SELECT COUNT(*) FROM subdomains s WHERE s.domain=t.domain) as sub_count,
                   (SELECT COUNT(*) FROM subdomains s WHERE s.domain=t.domain AND s.interesting=1) as findings
            FROM targets t ORDER BY t.created_at DESC
        """)
        self._ok(rows_to_list(rows))

    def _api_target_detail(self, domain: str) -> None:
        row = db_row("SELECT * FROM targets WHERE domain=?", (domain,))
        if not row:
            return self._err("Not found", 404)
        self._ok(dict(row))

    def _api_target_update(self, domain: str) -> None:
        body = self._body_json() or {}
        comments = body.get("comments", "")
        flags    = json.dumps(body.get("flags", {}))
        db_exec("UPDATE targets SET comments=?, flags=? WHERE domain=?",
                (comments, flags, domain))
        self._ok(msg="Updated")

    def _api_target_delete(self, domain: str) -> None:
        db_exec("DELETE FROM subdomains WHERE domain=?", (domain,))
        db_exec("DELETE FROM targets WHERE domain=?", (domain,))
        db_exec("DELETE FROM history WHERE domain=?", (domain,))
        self._ok(msg="Deleted")

    # ── API: subdomains / reports ─────────────────────────────
    def _api_subdomains(self, domain: str, qs: Dict) -> None:
        clauses = ["domain=?"]
        params: List[Any] = [domain]
        if "status" in qs:
            clauses.append("http_status=?"); params.append(int(qs["status"][0]))
        if qs.get("interesting", [""])[0] == "1":
            clauses.append("interesting=1")
        if "q" in qs:
            clauses.append("subdomain LIKE ?"); params.append(f"%{qs['q'][0]}%")
        sql = f"SELECT * FROM subdomains WHERE {' AND '.join(clauses)} ORDER BY subdomain"
        self._ok(rows_to_list(db_rows(sql, params)))

    def _api_report(self, domain: str, qs: Dict) -> None:
        clauses = ["domain=?"]
        params: List[Any] = [domain]
        if qs.get("has_findings", [""])[0] == "1":
            clauses.append("interesting=1")
        if qs.get("has_screenshots", [""])[0] == "1":
            clauses.append("screenshot_path IS NOT NULL")
        if "status" in qs:
            clauses.append("http_status=?"); params.append(int(qs["status"][0]))
        sql = f"SELECT * FROM subdomains WHERE {' AND '.join(clauses)} ORDER BY interesting DESC, subdomain"
        rows = rows_to_list(db_rows(sql, params))
        # Decode JSON fields
        for r in rows:
            for f in ("http_technologies","nuclei_findings","nikto_results","ip_addresses"):
                if isinstance(r.get(f), str):
                    try:
                        r[f] = json.loads(r[f])
                    except Exception:
                        r[f] = []
        self._ok(rows)

    # ── API: config ──────────────────────────────────────────
    def _api_config_get(self) -> None:
        tools  = get_tools_config()
        fields = [
            "max_running_jobs","dynamic_mode","dyn_min_jobs","dyn_max_jobs",
            "threads","wordlist","tld_list","github_token","auto_backup",
            "backup_interval","cleanup_temp_h","cleanup_days","https_enabled",
        ]
        cfg = {f: get_config(f) for f in fields}
        cfg["tools"] = tools
        self._ok(cfg)

    def _api_config_put(self) -> None:
        body = self._body_json() or {}
        _cfg_cache.clear()
        safe_keys = {
            "max_running_jobs","dynamic_mode","dyn_min_jobs","dyn_max_jobs",
            "threads","wordlist","tld_list","github_token","auto_backup",
            "backup_interval","cleanup_temp_h","cleanup_days",
        }
        for k, v in body.items():
            if k in safe_keys:
                set_config(k, v)
            elif k == "tools":
                set_config("tools", v)
        init_tool_gates()
        self._ok(msg="Config saved")

    # ── API: history / logs ──────────────────────────────────
    def _api_history(self, qs: Dict) -> None:
        domain = qs.get("domain", [None])[0]
        if domain:
            rows = db_rows(
                "SELECT * FROM history WHERE domain=? ORDER BY created_at DESC LIMIT 200",
                (domain,))
        else:
            rows = db_rows("SELECT * FROM history ORDER BY created_at DESC LIMIT 200")
        self._ok(rows_to_list(rows))

    def _api_logs(self, qs: Dict) -> None:
        src_filter = qs.get("src", [None])[0]
        lvl_filter = qs.get("level", [None])[0]
        q_filter   = qs.get("q", [None])[0]
        logs = list(_log_buf)
        if src_filter:
            logs = [l for l in logs if l.get("src") == src_filter]
        if lvl_filter:
            logs = [l for l in logs if l.get("level") == lvl_filter]
        if q_filter:
            logs = [l for l in logs if q_filter.lower() in l.get("msg","").lower()]
        self._ok(logs[-500:])

    # ── API: monitors ────────────────────────────────────────
    def _api_monitors_list(self) -> None:
        self._ok(rows_to_list(db_rows("SELECT * FROM monitors ORDER BY id")))

    def _api_monitors_create(self) -> None:
        body = self._body_json() or {}
        name = body.get("name", "").strip()
        url  = body.get("url", "").strip()
        if not name or not url:
            return self._err("name and url are required")
        c = db_exec("INSERT INTO monitors(name,url,enabled) VALUES(?,?,1)", (name, url))
        self._ok({"id": c.lastrowid}, "Monitor created")

    def _api_monitors_update(self, mon_id: int) -> None:
        body = self._body_json() or {}
        name    = body.get("name")
        url     = body.get("url")
        enabled = body.get("enabled")
        if name is not None:
            db_exec("UPDATE monitors SET name=? WHERE id=?", (name, mon_id))
        if url is not None:
            db_exec("UPDATE monitors SET url=? WHERE id=?", (url, mon_id))
        if enabled is not None:
            db_exec("UPDATE monitors SET enabled=? WHERE id=?", (1 if enabled else 0, mon_id))
        self._ok(msg="Updated")

    def _api_monitors_delete(self, mon_id: int) -> None:
        db_exec("DELETE FROM monitors WHERE id=?", (mon_id,))
        self._ok(msg="Deleted")

    # ── API: resources / workers ─────────────────────────────
    def _api_resources(self) -> None:
        rows = rows_to_list(db_rows(
            "SELECT * FROM system_resources ORDER BY created_at DESC LIMIT 720"))
        self._ok(rows)

    def _api_workers(self) -> None:
        with _lock:
            snap = {k: g.status() for k, g in _tool_gates.items()}
        self._ok(snap)

    # ── API: users ───────────────────────────────────────────
    def _api_users_list(self) -> None:
        rows = rows_to_list(db_rows(
            "SELECT id,username,role,created_at FROM users ORDER BY id"))
        self._ok(rows)

    def _api_users_create(self, session: Dict) -> None:
        body = self._body_json() or {}
        username = body.get("username", "").strip()
        password = body.get("password", "")
        role     = body.get("role", "user")
        if not username or not password:
            return self._err("username and password required")
        if role not in ("admin", "user"):
            role = "user"
        try:
            uid = create_user(username, password, role)
            self._ok({"id": uid}, "User created")
        except sqlite3.IntegrityError:
            self._err("Username already exists")

    def _api_users_update(self, user_id: int) -> None:
        body = self._body_json() or {}
        if "password" in body and body["password"]:
            ph, salt = hash_password(body["password"])
            db_exec("UPDATE users SET password_hash=?, salt=? WHERE id=?",
                    (ph, salt, user_id))
        if "role" in body and body["role"] in ("admin","user"):
            db_exec("UPDATE users SET role=? WHERE id=?", (body["role"], user_id))
        self._ok(msg="Updated")

    def _api_users_delete(self, user_id: int, session: Dict) -> None:
        if user_id == session.get("user_id"):
            return self._err("Cannot delete yourself")
        db_exec("DELETE FROM users WHERE id=?", (user_id,))
        self._ok(msg="Deleted")

    # ── API: backups ─────────────────────────────────────────
    def _api_backup_create(self) -> None:
        try:
            name = create_backup()
            self._ok({"name": name}, "Backup created")
        except Exception as e:
            self._err(str(e))

    def _api_backup_restore(self, name: str) -> None:
        try:
            restore_backup(name)
            self._ok(msg=f"Restored from {name}")
        except Exception as e:
            self._err(str(e))

    # ── gallery ──────────────────────────────────────────────
    def _serve_gallery(self, domain: str, qs: Dict) -> None:
        page = int(qs.get("page", ["1"])[0])
        body = GALLERY_HTML.replace("__DOMAIN__", domain).replace("__PAGE__", str(page)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _api_gallery(self, domain: str, qs: Dict) -> None:
        page  = int(qs.get("page", ["1"])[0])
        offset = (page - 1) * GALLERY_PAGE_SZ
        rows = rows_to_list(db_rows(
            "SELECT subdomain,screenshot_path FROM subdomains"
            " WHERE domain=? AND screenshot_path IS NOT NULL"
            " ORDER BY subdomain LIMIT ? OFFSET ?",
            (domain, GALLERY_PAGE_SZ, offset)))
        total = (db_row(
            "SELECT COUNT(*) as c FROM subdomains WHERE domain=? AND screenshot_path IS NOT NULL",
            (domain,)) or {"c": 0})["c"]
        self._ok({"items": rows, "total": total, "page": page,
                  "pages": max(1, (total + GALLERY_PAGE_SZ - 1) // GALLERY_PAGE_SZ)})

# ═══════════════════════════════════════════════════════════
#  GALLERY HTML  (lightweight, not the full SPA)
# ═══════════════════════════════════════════════════════════
GALLERY_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Gallery — __DOMAIN__</title>
<style>
  body{background:#0a0a0f;color:#e2e8f0;font-family:monospace;margin:0;padding:20px}
  h1{color:#00ff88;margin-bottom:16px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
  .thumb{border:1px solid rgba(0,255,136,.15);border-radius:6px;overflow:hidden;cursor:pointer;transition:all .2s}
  .thumb:hover{border-color:#00d4ff;transform:scale(1.02)}
  .thumb img{width:100%;height:140px;object-fit:cover;display:block;background:#111}
  .label{padding:6px 8px;font-size:10px;color:#8899a6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .pagination{margin-top:16px;display:flex;gap:8px;align-items:center}
  a.btn{padding:6px 14px;border:1px solid rgba(0,255,136,.4);color:#00ff88;text-decoration:none;border-radius:4px;font-size:12px}
  a.btn:hover{background:rgba(0,255,136,.1)}
  #modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:99;align-items:center;justify-content:center}
  #modal.open{display:flex}
  #modal img{max-width:90vw;max-height:90vh;border:1px solid #00d4ff}
  #modal .close{position:absolute;top:16px;right:24px;color:#fff;font-size:24px;cursor:pointer}
</style></head>
<body>
<h1>Screenshots — __DOMAIN__</h1>
<div class="grid" id="grid">Loading...</div>
<div class="pagination" id="pager"></div>
<div id="modal" onclick="closeModal()">
  <span class="close">&#x2715;</span>
  <img id="modal-img" src="" alt="">
</div>
<script>
const domain = "__DOMAIN__";
let page = __PAGE__;
async function load(){
  const r = await fetch("/api/gallery/"+encodeURIComponent(domain)+"?page="+page);
  const d = await r.json();
  const g = document.getElementById("grid");
  if(!d.data.items.length){g.innerHTML="<p>No screenshots.</p>";return;}
  g.innerHTML = d.data.items.map(it=>`
    <div class="thumb" onclick="openModal('/screenshots/${encodeURIComponent(domain.replace(/[^\\w\\-\\.]/g,'_'))+'/'+encodeURIComponent(it.screenshot_path.split('/').pop())}')">
      <img loading="lazy" src="/screenshots/${encodeURIComponent(domain.replace(/[^\\w\\-\\.]/g,'_'))+'/'+encodeURIComponent(it.screenshot_path.split('/').pop())}" onerror="this.style.display='none'">
      <div class="label">${it.subdomain}</div>
    </div>`).join("");
  const p = document.getElementById("pager");
  p.innerHTML = (page>1?`<a class="btn" href="/gallery/${encodeURIComponent(domain)}?page=${page-1}">&#8249; Prev</a>`:"") +
    `<span style="color:#8899a6;font-size:12px">${page}/${d.data.pages}</span>` +
    (page<d.data.pages?`<a class="btn" href="/gallery/${encodeURIComponent(domain)}?page=${page+1}">Next &#8250;</a>`:"");
}
function openModal(src){document.getElementById("modal-img").src=src;document.getElementById("modal").classList.add("open")}
function closeModal(){document.getElementById("modal").classList.remove("open")}
load();
</script></body></html>"""

# ═══════════════════════════════════════════════════════════
#  FRONTEND SPA  (single-page app, cyberpunk theme)
# ═══════════════════════════════════════════════════════════
FRONTEND_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconForge</title>
<style>
:root{
  --bg:#0a0a0f;--bg2:#0f1117;--card:#111827;--card2:#1a1f35;
  --border:rgba(0,255,136,.12);--bh:rgba(0,255,136,.35);
  --text:#e2e8f0;--text2:#8899a6;
  --green:#00ff88;--cyan:#00d4ff;--pink:#ff3377;
  --orange:#ff8800;--purple:#9d4edd;--yellow:#ffcc00;--red:#ff4444;
  --gg:0 0 10px rgba(0,255,136,.4);--gc:0 0 10px rgba(0,212,255,.4);
  --gp:0 0 10px rgba(255,51,119,.4);
  --font:'JetBrains Mono','Fira Code','Cascadia Code','Courier New',monospace;
  --r:6px;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;min-height:100vh}
a{color:inherit;text-decoration:none}
#header{border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;
  height:52px;background:var(--bg2);box-shadow:0 2px 20px rgba(0,0,0,.5);
  position:sticky;top:0;z-index:100}
.logo{font-size:18px;font-weight:700;color:var(--green);letter-spacing:2px;text-shadow:var(--gg)}
.logo span{color:var(--cyan)}
.ver{color:var(--text2);font-size:10px;margin-left:8px;opacity:.7}
.hsp{flex:1}
.huser{color:var(--text2);font-size:11px}
.huser b{color:var(--cyan)}
.hbtn{background:none;border:1px solid var(--border);color:var(--text2);
  padding:4px 10px;border-radius:4px;cursor:pointer;font-family:var(--font);font-size:11px;
  margin-left:12px;transition:all .2s}
.hbtn:hover{border-color:var(--pink);color:var(--pink)}
#nav{background:var(--bg2);border-bottom:1px solid var(--border);
  padding:0 24px;display:flex;gap:2px;overflow-x:auto;scrollbar-width:none}
#nav::-webkit-scrollbar{display:none}
.ni{padding:10px 14px;color:var(--text2);font-size:11px;white-space:nowrap;
  border-bottom:2px solid transparent;transition:all .2s;cursor:pointer;
  text-transform:uppercase;letter-spacing:1px}
.ni:hover{color:var(--green)}
.ni.active{color:var(--green);border-bottom-color:var(--green);text-shadow:var(--gg)}
#content{padding:20px 24px;max-width:1600px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:16px;transition:border-color .2s}
.card:hover{border-color:var(--bh)}
.ct{color:var(--green);font-size:11px;letter-spacing:1px;text-transform:uppercase;margin-bottom:12px}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:12px;margin-bottom:20px}
.sc{background:var(--card2);border:1px solid var(--border);border-radius:var(--r);padding:16px}
.sv{font-size:32px;font-weight:700;color:var(--green);line-height:1}
.sl{color:var(--text2);font-size:11px;margin-top:4px;letter-spacing:.5px}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 12px;color:var(--green);font-size:11px;
  text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--border);
  white-space:nowrap;font-weight:600}
td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04);color:var(--text);font-size:12px}
tr:hover td{background:rgba(0,255,136,.03)}
.nd{color:var(--text2);text-align:center;padding:32px}
.bdg{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;
  font-weight:600;text-transform:uppercase;letter-spacing:.5px}
.bg{background:rgba(0,255,136,.15);color:var(--green);border:1px solid rgba(0,255,136,.3)}
.bc{background:rgba(0,212,255,.15);color:var(--cyan);border:1px solid rgba(0,212,255,.3)}
.bp{background:rgba(255,51,119,.15);color:var(--pink);border:1px solid rgba(255,51,119,.3)}
.bo{background:rgba(255,136,0,.15);color:var(--orange);border:1px solid rgba(255,136,0,.3)}
.bpu{background:rgba(157,78,221,.15);color:var(--purple);border:1px solid rgba(157,78,221,.3)}
.bgr{background:rgba(68,85,85,.3);color:var(--text2);border:1px solid var(--border)}
.br{background:rgba(255,68,68,.15);color:var(--red);border:1px solid rgba(255,68,68,.3)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.pulse{animation:pulse 1.5s infinite}
.btn{display:inline-block;padding:6px 14px;border-radius:4px;cursor:pointer;
  font-family:var(--font);font-size:12px;font-weight:600;border:1px solid;
  transition:all .2s;text-transform:uppercase;letter-spacing:.5px;background:none}
.btn-g{color:var(--green);border-color:rgba(0,255,136,.4)}
.btn-g:hover{background:rgba(0,255,136,.1);box-shadow:var(--gg)}
.btn-c{color:var(--cyan);border-color:rgba(0,212,255,.4)}
.btn-c:hover{background:rgba(0,212,255,.1);box-shadow:var(--gc)}
.btn-p{color:var(--pink);border-color:rgba(255,51,119,.4)}
.btn-p:hover{background:rgba(255,51,119,.1);box-shadow:var(--gp)}
.btn-o{color:var(--orange);border-color:rgba(255,136,0,.4)}
.btn-o:hover{background:rgba(255,136,0,.1)}
.btn-gr{color:var(--text2);border-color:var(--border)}
.btn-gr:hover{border-color:var(--text2);color:var(--text)}
.btn-sm{padding:3px 8px;font-size:11px}
.fg{margin-bottom:12px}
.fl{display:block;color:var(--text2);font-size:11px;margin-bottom:4px;letter-spacing:.5px}
input,select,textarea{width:100%;padding:8px 10px;background:var(--bg);
  border:1px solid var(--border);border-radius:4px;color:var(--text);
  font-family:var(--font);font-size:12px;transition:border-color .2s;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--green);box-shadow:0 0 0 2px rgba(0,255,136,.1)}
textarea{resize:vertical;min-height:60px}
.sf{display:flex;gap:8px;margin-bottom:20px}
.si{flex:1;padding:10px 14px;background:var(--card);border:1px solid var(--border);
  border-radius:4px;color:var(--text);font-family:var(--font);font-size:13px;outline:none}
.si:focus{border-color:var(--green)}
.jc{background:var(--card);border:1px solid var(--border);border-radius:6px;
  padding:14px 16px;margin-bottom:10px}
.jc.running{border-left:3px solid var(--green)}
.jc.paused{border-left:3px solid var(--orange)}
.jc.failed{border-left:3px solid var(--red)}
.jc.cancelled{border-left:3px solid var(--text2)}
.jh{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}
.jd{font-size:14px;font-weight:600;color:var(--cyan);flex:1;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.jm{color:var(--text2);font-size:11px;white-space:nowrap}
.js_{color:var(--green);font-size:11px;white-space:nowrap}
.pb{height:3px;background:rgba(255,255,255,.07);border-radius:2px;margin:8px 0}
.pf{height:100%;background:var(--green);border-radius:2px;box-shadow:var(--gg);transition:width .5s}
.ja{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}
.lt{font-size:10px;color:var(--text2);background:var(--bg);border:1px solid var(--border);
  border-radius:4px;padding:6px 10px;margin-top:8px;max-height:80px;overflow-y:auto;
  font-family:var(--font);white-space:pre-wrap;word-break:break-all}
.wg{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.wc{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:14px}
.wn{color:var(--cyan);font-size:13px;font-weight:600;margin-bottom:8px}
.wb{height:6px;background:rgba(255,255,255,.07);border-radius:3px;margin:6px 0}
.wf{height:100%;border-radius:3px;transition:width .5s}
.wfr{background:var(--green);box-shadow:var(--gg)}
.wfw{background:var(--orange)}
.wst{display:flex;justify-content:space-between;font-size:11px;color:var(--text2)}
.rg{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}
.rc{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:14px}
.rt{color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.rv{font-size:36px;font-weight:700;line-height:1;margin-bottom:8px}
canvas.sp{width:100%;height:50px;display:block}
.lc{background:var(--bg);border:1px solid var(--border);border-radius:6px;
  height:480px;overflow-y:auto;padding:10px;font-size:11px;font-family:var(--font)}
.ll{padding:2px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.lts{color:var(--text2);margin-right:8px}
.lsr{color:var(--purple);margin-right:8px;display:inline-block;min-width:80px}
.lINFO{color:var(--text)}.lWARNING{color:var(--orange)}.lERROR{color:var(--red)}.lDEBUG{color:var(--text2)}
.lctr{display:flex;gap:10px;margin-bottom:10px;align-items:center;flex-wrap:wrap}
.lctr input,.lctr select{flex:0 0 auto;width:auto;padding:5px 8px}
#overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;
  display:none;align-items:center;justify-content:center}
#overlay.open{display:flex}
.modal{background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:24px;min-width:360px;max-width:680px;width:92%;max-height:85vh;overflow-y:auto}
.mth{color:var(--green);font-size:16px;font-weight:700;margin-bottom:16px;
  display:flex;justify-content:space-between;align-items:center}
.mcl{background:none;border:none;color:var(--text2);cursor:pointer;font-size:20px}
.mft{margin-top:16px;display:flex;gap:8px;justify-content:flex-end}
.toast{position:fixed;bottom:24px;right:24px;padding:10px 18px;border-radius:4px;
  font-size:12px;z-index:500;pointer-events:none}
@keyframes tsi{from{transform:translateX(110%);opacity:0}to{transform:none;opacity:1}}
.toast{animation:tsi .3s ease}
.tst{background:rgba(0,255,136,.15);border:1px solid rgba(0,255,136,.4);color:var(--green)}
.ter{background:rgba(255,68,68,.15);border:1px solid rgba(255,68,68,.4);color:var(--red)}
.tin{background:rgba(0,212,255,.15);border:1px solid rgba(0,212,255,.4);color:var(--cyan)}
.acc{border:1px solid var(--border);border-radius:6px;margin-bottom:8px;overflow:hidden}
.ach{padding:12px 16px;cursor:pointer;display:flex;justify-content:space-between;
  align-items:center;background:var(--card);color:var(--text);font-weight:600;font-size:12px}
.ach:hover{background:var(--card2)}
.acb{display:none;padding:16px;background:var(--bg2);border-top:1px solid var(--border)}
.acb.open{display:block}
.aar{transition:transform .2s;color:var(--text2);font-size:12px}
.aar.open{transform:rotate(90deg)}
.sh{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:8px}
.stt{color:var(--green);font-size:14px;font-weight:700;letter-spacing:1px}
.fb{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.fb input,.fb select{flex:1;min-width:110px}
.toggle{position:relative;display:inline-block;width:36px;height:20px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.tsl{position:absolute;inset:0;background:rgba(68,85,85,.5);border-radius:20px;cursor:pointer;transition:.3s}
.tsl:before{content:'';position:absolute;height:14px;width:14px;left:3px;bottom:3px;
  background:var(--text2);border-radius:50%;transition:.3s}
input:checked+.tsl{background:var(--green)}
input:checked+.tsl:before{transform:translateX(16px);background:var(--bg)}
.tw-row{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.gc{width:100%;height:280px;background:var(--bg2);border-radius:6px;border:1px solid var(--border);display:block}
.chip{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;margin:1px;
  background:var(--card2);border:1px solid var(--border);color:var(--text2)}
.sev-critical{color:var(--red)}.sev-high{color:var(--pink)}
.sev-medium{color:var(--orange)}.sev-low{color:var(--yellow)}.sev-info{color:var(--cyan)}
hr{border:none;border-top:1px solid var(--border);margin:12px 0}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(0,255,136,.3)}
@media(max-width:900px){.rg{grid-template-columns:1fr}}
@media(max-width:600px){.sg{grid-template-columns:repeat(2,1fr)};#content{padding:12px}}
</style>
</head>
<body>
<div id="app" style="display:none">
  <header id="header">
    <span class="logo">RECON<span>FORGE</span></span>
    <span class="ver">v2.0</span>
    <div class="hsp"></div>
    <span id="huser" class="huser"></span>
    <button class="hbtn" onclick="App.logout()">Logout</button>
  </header>
  <nav id="nav"></nav>
  <main id="content"></main>
</div>
<div id="overlay" onclick="App.closeModal(event)">
  <div id="modal" class="modal" onclick="event.stopPropagation()"></div>
</div>
<!-- Login screen -->
<div id="lscreen" style="position:fixed;inset:0;background:var(--bg);
  display:flex;align-items:center;justify-content:center;z-index:900">
  <form onsubmit="event.preventDefault(); doLogin(event); return false;" action="javascript:void(0)" style="background:var(--card);border:1px solid var(--border);
    border-radius:8px;padding:36px 32px;min-width:320px;max-width:380px;width:90%;text-align:center">
    <div style="font-size:22px;font-weight:700;color:var(--green);letter-spacing:3px;margin-bottom:4px;text-shadow:var(--gg)">RECON<span style="color:var(--cyan)">FORGE</span></div>
    <div style="color:var(--text2);font-size:11px;margin-bottom:28px">Security Reconnaissance Platform</div>
    <div class="fg" style="text-align:left"><label class="fl">Username</label><input id="l-user" name="username" autocomplete="username" placeholder="admin"></div>
    <div class="fg" style="text-align:left"><label class="fl">Password</label><input id="l-pass" name="password" type="password" autocomplete="current-password"></div>
    <div id="l-err" style="color:var(--red);font-size:12px;min-height:18px;margin-bottom:10px"></div>
    <button type="submit" class="btn btn-g" style="width:100%;padding:10px">&#9654; Login</button>
  </form>
</div>
<script>
const App = {
  state:{
    tab:'overview',
    running_jobs:[],queued_jobs:[],completed_jobs:[],
    stats:{},workers:{},resources:{},session:{},
    targets:[],report:[],monitors:[],users:[],config:{},backups:[],logs:[],
    logFilter:{src:'',level:'',q:''},
    reportDomain:'',reportFilter:{q:'',status:'',interesting:'',screenshots:''},
    targetDomain:'',settingsTab:'tools',
  },
  pollId:null, graph:null,

  async init(){
    await this.fetchState();
    this.router();
    window.addEventListener('hashchange',()=>this.router());
    this.startPoll();
  },

  router(){
    const h=window.location.hash.slice(1)||'/overview';
    const parts=h.split('/').filter(Boolean);
    const tab=parts[0]||'overview';
    this.state.tab=tab;
    if(tab==='targets'&&parts[1]) this.state.targetDomain=decodeURIComponent(parts[1]);
    if(tab==='reports'&&parts[1]) this.state.reportDomain=decodeURIComponent(parts[1]);
    this.render();
    const lazy=['targets','reports','monitors','settings'];
    if(lazy.includes(tab)) setTimeout(()=>this.lazyLoad(tab),0);
  },

  startPoll(){
    const ACTIVE=['overview','jobs','queue','workers','resources'];
    if(this.pollId) clearInterval(this.pollId);
    this.pollId=setInterval(async()=>{
      if(ACTIVE.includes(this.state.tab)) await this.fetchState();
    },8000);
  },

  async fetchState(){
    try{
      const r=await fetch('/api/state');
      if(r.status===401){this.showLogin();return;}
      const d=await r.json();
      if(d.success){
        Object.assign(this.state,d.data);
        const u=document.getElementById('huser');
        if(u) u.innerHTML='<b>'+(this.state.session.username||'')+'</b>&nbsp;<span style="color:var(--text2)">['+this.state.session.role+']</span>';
        this.render();
      }
    }catch(e){}
  },

  render(){
    const TABS=['overview','jobs','queue','workers','targets','reports','monitors','resources','logs','settings'];
    const nav=document.getElementById('nav');
    if(nav) nav.innerHTML=TABS.map(t=>'<span class="ni'+(this.state.tab===t?' active':'')+'" onclick="App.go(\''+t+'\')">'+(t==='resources'?'system':t)+'</span>').join('');
    const el=document.getElementById('content');
    if(!el) return;
    const map={
      overview:()=>this.renderOverview(),
      jobs:()=>this.renderJobs(),
      queue:()=>this.renderQueue(),
      workers:()=>this.renderWorkers(),
      targets:()=>this.renderTargets(),
      reports:()=>this.renderReports(),
      monitors:()=>this.renderMonitors(),
      resources:()=>this.renderResources(),
      logs:()=>this.renderLogs(),
      settings:()=>this.renderSettings(),
    };
    el.innerHTML=(map[this.state.tab]||(() => '<p class="nd">Tab not found.</p>'))();
    this.postRender();
  },

  postRender(){
    if(this.state.tab==='resources') setTimeout(()=>this.drawCharts(),50);
    if(this.state.tab==='targets'&&this.state.targetDomain) setTimeout(()=>this.loadGraph(),50);
    document.querySelectorAll('.ach').forEach(h=>{
      if(h._bound) return; h._bound=true;
      h.addEventListener('click',()=>{
        const b=h.nextElementSibling, a=h.querySelector('.aar');
        b.classList.toggle('open');
        if(a) a.classList.toggle('open');
      });
    });
  },

  go(tab,sub){
    this.state.tab=tab;
    window.location.hash='/'+tab+(sub?'/'+encodeURIComponent(sub):'');
  },

  async lazyLoad(tab){
    const map={
      targets:  async()=>{ const r=await this.api('/api/targets'); if(r) this.state.targets=r; },
      reports:  async()=>{
        if(!this.state.targets.length){ const t=await this.api('/api/targets'); if(t) this.state.targets=t; }
        if(this.state.reportDomain){ const r=await this.api('/api/reports/'+encodeURIComponent(this.state.reportDomain)+'?'+this.reportQS()); if(r!==null) this.state.report=r; }
      },
      monitors: async()=>{ const r=await this.api('/api/monitors'); if(r) this.state.monitors=r; },
      settings: async()=>{
        const [cfg,tgts]=await Promise.all([this.api('/api/config'),this.api('/api/targets')]);
        if(cfg) this.state.config=cfg;
        if(tgts) this.state.targets=tgts;
        if(this.state.settingsTab==='users'){ const u=await this.api('/api/users'); if(u) this.state.users=u; }
        if(this.state.settingsTab==='backups'){ const b=await this.api('/api/backups'); if(b) this.state.backups=b; }
      },
    };
    if(map[tab]){ await map[tab](); this.render(); }
  },

  reportQS(){
    const f=this.state.reportFilter, p=[];
    if(f.q) p.push('q='+encodeURIComponent(f.q));
    if(f.status) p.push('status='+encodeURIComponent(f.status));
    if(f.interesting==='1') p.push('has_findings=1');
    if(f.screenshots==='1') p.push('has_screenshots=1');
    return p.join('&');
  },

  async api(url,method,body){
    try{
      const opts={method:method||'GET',headers:{}};
      if(body){opts.body=JSON.stringify(body);opts.headers['Content-Type']='application/json';}
      const r=await fetch(url,opts);
      if(r.status===401){this.showLogin();return null;}
      const d=await r.json();
      if(!d.success){this.toast(d.message||'Error','er');return null;}
      return d.data;
    }catch(e){this.toast('Network error','er');return null;}
  },
  async post(url,body){return this.api(url,'POST',body);},
  async put(url,body){return this.api(url,'PUT',body);},
  async del(url){return this.api(url,'DELETE');},

  toast(msg,type='in'){
    const el=document.createElement('div');
    el.className='toast t'+type;el.textContent=msg;
    document.body.appendChild(el);
    setTimeout(()=>el.remove(),3200);
  },

  showLogin(){
    document.getElementById('app').style.display='none';
    document.getElementById('lscreen').style.display='flex';
  },

  closeModal(e){
    if(e.target===document.getElementById('overlay'))
      document.getElementById('overlay').classList.remove('open');
  },

  showModal(title,html,footer){
    document.getElementById('modal').innerHTML=
      '<div class="mth">'+title+'<button class="mcl" onclick="document.getElementById(\'overlay\').classList.remove(\'open\')">&times;</button></div>'+
      html+(footer?'<div class="mft">'+footer+'</div>':'');
    document.getElementById('overlay').classList.add('open');
  },

  async logout(){
    await fetch('/api/logout',{method:'POST'});
    window.location='/login';
  },

  // ── OVERVIEW ─────────────────────────────────────────────
  renderOverview(){
    const s=this.state.stats||{};
    const cards=[
      ['Running',this.state.running_jobs.length,'var(--green)'],
      ['Queued',(this.state.queued_jobs||[]).length,'var(--cyan)'],
      ['Domains',s.total_domains||0,'var(--purple)'],
      ['Subdomains',s.total_subdomains||0,'var(--cyan)'],
      ['Findings',s.total_findings||0,'var(--pink)'],
    ];
    const statsH=cards.map(([l,v,c])=>'<div class="sc"><div class="sv" style="color:'+c+'">'+v+'</div><div class="sl">'+l+'</div></div>').join('');
    const rateH=this.state.rate_delay>0?'<div style="color:var(--orange);font-size:11px;margin-bottom:10px">&#9888; Rate-limit delay: '+this.state.rate_delay+'s</div>':'';
    const activeH=this.state.running_jobs.length
      ?this.state.running_jobs.map(j=>this.jobCard(j,false)).join('')
      :'<div class="nd">No active jobs. Enter a domain below to start.</div>';
    return '<div class="sh"><span class="stt">&#9670; Overview</span><span class="jm">Max jobs: '+this.state.max_jobs+' &bull; Dynamic: '+(this.state.dynamic_mode?'<span style="color:var(--green)">ON</span>':'OFF')+'</span></div>'+
      '<div class="sg">'+statsH+'</div>'+rateH+
      '<form class="sf" onsubmit="App.submitScan(event)">'+
      '<input class="si" id="scan-dom" placeholder="target.com  /  acme.*  /  *.corp.com" autocomplete="off">'+
      '<button type="submit" class="btn btn-g">&#9654; Scan</button></form>'+activeH;
  },

  async submitScan(e){
    e.preventDefault();
    const domain=document.getElementById('scan-dom').value.trim();
    if(!domain) return;
    const r=await this.post('/api/jobs',{domain});
    if(r){document.getElementById('scan-dom').value='';this.toast(r.length+' job(s) queued','st');await this.fetchState();}
  },

  // ── JOBS ─────────────────────────────────────────────────
  renderJobs(){
    const active=(this.state.running_jobs||[]).concat((this.state.queued_jobs||[]).filter(j=>j.status==='pending'));
    const hist=this.state.completed_jobs||[];
    const aH=active.length?active.map(j=>this.jobCard(j,true)).join(''):'<div class="nd">No active jobs.</div>';
    const hH=hist.map(j=>'<tr><td>'+this.esc(j.domain)+'</td><td>'+this.badge(j.status)+'</td>'+
      '<td>'+(j.subdomain_count||0)+' subs</td><td class="lts">'+(j.completed_at||'')+'</td>'+
      '<td>'+this.esc(j.username||'')+'</td>'+
      '<td><button class="btn btn-c btn-sm" onclick="App.go(\'reports\',\''+this.esc(j.domain)+'\')">Report</button></td></tr>').join('');
    return '<div class="sh"><span class="stt">&#9670; Jobs</span>'+
      '<form class="sf" style="margin:0" onsubmit="App.submitScan(event)">'+
      '<input class="si" id="scan-dom" placeholder="domain.com" style="width:220px">'+
      '<button class="btn btn-g btn-sm" type="submit">&#9654; Scan</button></form></div>'+
      aH+'<br><div class="sh"><span class="stt">&#9670; History</span></div>'+
      '<div class="tw"><table><thead><tr><th>Domain</th><th>Status</th><th>Results</th><th>Completed</th><th>User</th><th></th></tr></thead>'+
      '<tbody>'+(hH||'<tr><td colspan="6" class="nd">No history.</td></tr>')+'</tbody></table></div>';
  },

  jobCard(j,controls){
    const pct=j.steps_total?Math.round((j.steps_done/j.steps_total)*100):0;
    const clr={running:'var(--green)',paused:'var(--orange)',failed:'var(--red)',cancelled:'var(--text2)'}[j.status]||'var(--cyan)';
    let ctrl='';
    if(controls&&['running','paused','pending'].includes(j.status)){
      const pauseBtn=j.status==='paused'
        ?'<button class="btn btn-g btn-sm" onclick="App.jobAction(\''+j.id+'\',\'resume\')">&#9654; Resume</button>'
        :'<button class="btn btn-o btn-sm" onclick="App.jobAction(\''+j.id+'\',\'pause\')">&#9646;&#9646; Pause</button>';
      ctrl='<div class="ja">'+pauseBtn+
        '<button class="btn btn-gr btn-sm" onclick="App.jobAction(\''+j.id+'\',\'skip-step\')">&#8677; Skip</button>'+
        '<button class="btn btn-p btn-sm" onclick="App.jobAction(\''+j.id+'\',\'cancel\')">&#215; Cancel</button></div>';
    }
    const logs=(j.logs||[]).slice(-6).join('\n');
    return '<div class="jc '+j.status+'">'+
      '<div class="jh"><span class="jd">'+this.esc(j.domain)+'</span>'+this.badge(j.status)+
      '<span class="jm">'+j.subdomain_count+' subs &bull; '+j.steps_done+'/'+j.steps_total+' steps</span>'+
      '<span class="js_">'+(j.current_step||'')+'</span></div>'+
      '<div class="pb"><div class="pf" style="width:'+pct+'%;background:'+clr+'"></div></div>'+
      ctrl+(logs?'<div class="lt">'+this.esc(logs)+'</div>':'')+
      '</div>';
  },

  async jobAction(id,action){
    await this.post('/api/jobs/'+id+'/'+action);
    await this.fetchState();
  },

  // ── QUEUE ────────────────────────────────────────────────
  renderQueue(){
    const q=this.state.queued_jobs||[];
    const rows=q.map((j,i)=>'<tr><td>'+(i+1)+'</td><td>'+this.esc(j.domain)+'</td>'+
      '<td>'+this.esc(j.username||'')+'</td><td class="lts">'+j.queued_at+'</td>'+
      '<td><button class="btn btn-p btn-sm" onclick="App.jobAction(\''+j.id+'\',\'cancel\')">Cancel</button></td></tr>').join('');
    return '<div class="sh"><span class="stt">&#9670; Queue ('+q.length+')</span></div>'+
      '<div class="tw"><table><thead><tr><th>#</th><th>Domain</th><th>User</th><th>Queued</th><th></th></tr></thead>'+
      '<tbody>'+(rows||'<tr><td colspan="5" class="nd">Queue empty.</td></tr>')+'</tbody></table></div>';
  },

  // ── WORKERS ──────────────────────────────────────────────
  renderWorkers(){
    const w=this.state.workers||{};
    const wH=Object.entries(w).map(([k,g])=>{
      const rp=g.max?Math.min(100,Math.round((g.running/g.max)*100)):0;
      return '<div class="wc"><div class="wn">'+(g.name||k)+'</div>'+
        '<div class="wst"><span>Running: <b style="color:var(--green)">'+g.running+'/'+g.max+'</b></span>'+
        '<span>Waiting: <b style="color:var(--orange)">'+g.waiting+'</b></span></div>'+
        '<div class="wb"><div class="wf wfr" style="width:'+rp+'%"></div></div>'+
        (g.waiting?'<div class="wb"><div class="wf wfw" style="width:'+Math.min(100,g.waiting*25)+'%"></div></div>':'')+
        '</div>';
    }).join('');
    return '<div class="sh"><span class="stt">&#9670; Workers</span>'+
      '<span class="jm">Max jobs: '+this.state.max_jobs+' &bull; Dynamic: '+(this.state.dynamic_mode?'<span style="color:var(--green)">ON</span>':'OFF')+'</span></div>'+
      '<div class="wg">'+(wH||'<div class="nd">No workers initialised yet.</div>')+'</div>';
  },

  // ── TARGETS ──────────────────────────────────────────────
  renderTargets(){
    const targets=this.state.targets||[];
    const rows=targets.map(t=>'<tr>'+
      '<td><span style="color:var(--cyan);cursor:pointer" onclick="App.loadTarget(\''+this.esc(t.domain)+'\')">'+this.esc(t.domain)+'</span></td>'+
      '<td>'+t.sub_count+'</td><td>'+(t.findings||0)+'</td><td class="lts">'+t.created_at+'</td>'+
      '<td><button class="btn btn-c btn-sm" onclick="App.go(\'reports\',\''+this.esc(t.domain)+'\')">Report</button> '+
      '<a class="btn btn-gr btn-sm" href="/gallery/'+encodeURIComponent(t.domain)+'" target="_blank">Gallery</a> '+
      '<button class="btn btn-p btn-sm" onclick="App.deleteTarget(\''+this.esc(t.domain)+'\')">Del</button></td></tr>').join('');
    const graphH=this.state.targetDomain
      ?'<div class="sh" style="margin-top:20px"><span class="stt">&#9670; '+this.esc(this.state.targetDomain)+'</span></div>'+
        '<canvas id="ngraph" class="gc"></canvas>'
      :'';
    return '<div class="sh"><span class="stt">&#9670; Targets</span>'+
      '<button class="btn btn-g btn-sm" onclick="App.lazyLoad(\'targets\').then(()=>App.render())">&#8635; Refresh</button></div>'+
      '<div class="tw"><table><thead><tr><th>Domain</th><th>Subdomains</th><th>Findings</th><th>Added</th><th></th></tr></thead>'+
      '<tbody>'+(rows||'<tr><td colspan="5" class="nd">No targets yet — run a scan first.</td></tr>')+'</tbody></table></div>'+graphH;
  },

  async loadTarget(domain){
    this.state.targetDomain=domain;
    this.render();
    await this.loadGraph();
  },

  async loadGraph(){
    const domain=this.state.targetDomain;
    if(!domain) return;
    const subs=await this.api('/api/subdomains/'+encodeURIComponent(domain));
    if(!subs) return;
    const canvas=document.getElementById('ngraph');
    if(!canvas) return;
    canvas.width=canvas.offsetWidth||900;
    canvas.height=280;
    if(!this.graph){this.graph=new NodeGraph(canvas);}
    else{if(this.graph.frame) cancelAnimationFrame(this.graph.frame);this.graph.canvas=canvas;}
    this.graph.load(domain,subs);
  },

  async deleteTarget(domain){
    if(!confirm('Delete all data for '+domain+'?')) return;
    await this.del('/api/targets/'+encodeURIComponent(domain));
    this.state.targets=this.state.targets.filter(t=>t.domain!==domain);
    if(this.state.targetDomain===domain) this.state.targetDomain='';
    this.toast('Deleted','st');this.render();
  },

  // ── REPORTS ──────────────────────────────────────────────
  renderReports(){
    const targets=this.state.targets||[];
    const domain=this.state.reportDomain;
    if(!targets.length) this.lazyLoad('reports');
    const domSel='<select onchange="App.setReportDomain(this.value)" style="width:auto;min-width:200px">'+
      '<option value="">-- select domain --</option>'+
      targets.map(t=>'<option value="'+this.esc(t.domain)+'"'+(t.domain===domain?' selected':'')+'>'+this.esc(t.domain)+'</option>').join('')+
      '</select>';
    if(!domain) return '<div class="sh"><span class="stt">&#9670; Reports</span></div><p style="color:var(--text2);margin:12px 0">Domain: '+domSel+'</p>';
    const f=this.state.reportFilter;
    const filterBar='<div class="fb">'+
      '<input placeholder="Search..." value="'+this.esc(f.q||'')+'" oninput="App.state.reportFilter.q=this.value">'+
      '<input placeholder="HTTP status" value="'+this.esc(f.status||'')+'" oninput="App.state.reportFilter.status=this.value" style="max-width:120px">'+
      '<select onchange="App.state.reportFilter.interesting=this.value" style="max-width:160px"><option value="">All</option><option value="1"'+(f.interesting==='1'?' selected':'')+'>Has findings</option></select>'+
      '<select onchange="App.state.reportFilter.screenshots=this.value" style="max-width:160px"><option value="">All</option><option value="1"'+(f.screenshots==='1'?' selected':'')+'>Has screenshots</option></select>'+
      '<button class="btn btn-c btn-sm" onclick="App.loadReport()">&#128269; Filter</button>'+
      '<button class="btn btn-gr btn-sm" onclick="App.exportReport()">&#8659; CSV</button></div>';
    const rows=(this.state.report||[]).map(r=>{
      const nf=Array.isArray(r.nuclei_findings)?r.nuclei_findings:[];
      const techs=Array.isArray(r.http_technologies)?r.http_technologies:[];
      const sevRank={critical:4,high:3,medium:2,low:1,info:0};
      const topSev=nf.reduce((m,f_)=>sevRank[f_.severity]>(sevRank[m]||0)?f_.severity:m,'');
      const stCls=r.http_status?r.http_status<300?'bg':r.http_status<400?'bc':r.http_status<500?'bo':'br':'';
      return '<tr>'+
        '<td><a href="http://'+this.esc(r.subdomain)+'" target="_blank" style="color:var(--cyan)">'+this.esc(r.subdomain)+'</a></td>'+
        '<td>'+(r.http_status?'<span class="bdg '+stCls+'">'+r.http_status+'</span>':'')+'</td>'+
        '<td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+this.esc(r.http_title||'')+'</td>'+
        '<td>'+techs.slice(0,4).map(t=>'<span class="chip">'+this.esc(t)+'</span>').join('')+'</td>'+
        '<td>'+(nf.length?'<span class="sev-'+(topSev||'info')+'">'+nf.length+' ('+topSev+')</span>':'')+'</td>'+
        '<td>'+(r.screenshot_path?'<a href="/gallery/'+encodeURIComponent(domain)+'" target="_blank" style="color:var(--cyan)">&#128247;</a>':'')+'</td>'+
        '</tr>';
    }).join('');
    return '<div class="sh"><span class="stt">&#9670; Reports</span>'+domSel+'</div>'+
      filterBar+
      '<div class="tw"><table><thead><tr><th>Subdomain</th><th>Status</th><th>Title</th><th>Tech</th><th>Findings</th><th>&#128247;</th></tr></thead>'+
      '<tbody>'+(rows||'<tr><td colspan="6" class="nd">No results. Select a domain and apply filters.</td></tr>')+'</tbody></table></div>';
  },

  async setReportDomain(d){
    this.state.reportDomain=d;
    if(d){await this.loadReport();}else{this.render();}
  },

  async loadReport(){
    if(!this.state.reportDomain){this.render();return;}
    const r=await this.api('/api/reports/'+encodeURIComponent(this.state.reportDomain)+'?'+this.reportQS());
    if(r!==null) this.state.report=r;
    this.render();
  },

  exportReport(){
    const rows=this.state.report||[];
    const csv=['subdomain,http_status,title,technologies,nuclei_findings,nikto_results'].concat(
      rows.map(r=>[r.subdomain,r.http_status||'',
        '"'+(r.http_title||'').replace(/"/g,'""')+'"',
        '"'+(Array.isArray(r.http_technologies)?r.http_technologies.join(';'):'').replace(/"/g,'""')+'"',
        (Array.isArray(r.nuclei_findings)?r.nuclei_findings.length:0),
        (Array.isArray(r.nikto_results)?r.nikto_results.length:0)].join(','))
    ).join('\n');
    const a=document.createElement('a');
    a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
    a.download=(this.state.reportDomain||'report')+'.csv';
    a.click();
  },

  // ── MONITORS ─────────────────────────────────────────────
  renderMonitors(){
    const mons=this.state.monitors||[];
    const rows=mons.map(m=>'<tr>'+
      '<td>'+this.esc(m.name)+'</td>'+
      '<td style="max-width:220px;word-break:break-all;font-size:11px">'+this.esc(m.url)+'</td>'+
      '<td>'+(m.enabled?'<span class="bdg bg">ON</span>':'<span class="bdg bgr">OFF</span>')+'</td>'+
      '<td class="lts">'+(m.last_checked||'never')+'</td>'+
      '<td style="color:var(--text2);font-size:11px">'+this.esc(m.last_result||'')+'</td>'+
      '<td><button class="btn btn-o btn-sm" onclick="App.toggleMonitor('+m.id+','+m.enabled+')">Toggle</button> '+
      '<button class="btn btn-p btn-sm" onclick="App.deleteMonitor('+m.id+')">Del</button></td></tr>').join('');
    const addForm='<div class="card" style="margin-top:16px"><div class="ct">Add Feed Monitor</div>'+
      '<div class="fg"><label class="fl">Name</label><input id="mon-name" placeholder="My Domains Feed"></div>'+
      '<div class="fg"><label class="fl">URL &mdash; HTTP/HTTPS or file:///path/to/file.txt</label><input id="mon-url" placeholder="https://example.com/newdomains.txt"></div>'+
      '<button class="btn btn-g" onclick="App.addMonitor()">+ Add Monitor</button></div>';
    return '<div class="sh"><span class="stt">&#9670; Monitors</span>'+
      '<button class="btn btn-c btn-sm" onclick="App.lazyLoad(\'monitors\').then(()=>App.render())">&#8635;</button></div>'+
      '<div class="tw"><table><thead><tr><th>Name</th><th>URL</th><th>Status</th><th>Last Check</th><th>Result</th><th></th></tr></thead>'+
      '<tbody>'+(rows||'<tr><td colspan="6" class="nd">No monitors. Add one below.</td></tr>')+'</tbody></table></div>'+addForm;
  },

  async addMonitor(){
    const name=document.getElementById('mon-name').value.trim();
    const url=document.getElementById('mon-url').value.trim();
    if(!name||!url) return this.toast('name and url required','er');
    await this.post('/api/monitors',{name,url});
    await this.lazyLoad('monitors');this.render();this.toast('Monitor added','st');
  },
  async toggleMonitor(id,en){await this.put('/api/monitors/'+id,{enabled:!en});await this.lazyLoad('monitors');this.render();},
  async deleteMonitor(id){await this.del('/api/monitors/'+id);this.state.monitors=this.state.monitors.filter(m=>m.id!==id);this.render();},

  // ── RESOURCES ────────────────────────────────────────────
  renderResources(){
    const r=this.state.resources||{};
    const cpu=(r.cpu||0).toFixed(1),mem=(r.memory||0).toFixed(1),disk=(r.disk||0).toFixed(1);
    const cpuC=cpu>=90?'var(--red)':cpu>=75?'var(--orange)':'var(--green)';
    const memC=mem>=90?'var(--red)':mem>=80?'var(--orange)':'var(--cyan)';
    const dskC=disk>=90?'var(--red)':disk>=80?'var(--orange)':'var(--purple)';
    return '<div class="sh"><span class="stt">&#9670; System Resources</span><span class="jm" id="res-ts"></span></div>'+
      '<div class="rg">'+
      '<div class="rc"><div class="rt">CPU Utilization</div><div class="rv" style="color:'+cpuC+'">'+cpu+'%</div><canvas class="sp" id="cpu-c"></canvas></div>'+
      '<div class="rc"><div class="rt">Memory</div><div class="rv" style="color:'+memC+'">'+mem+'%</div><canvas class="sp" id="mem-c"></canvas></div>'+
      '<div class="rc"><div class="rt">Disk (data dir)</div><div class="rv" style="color:'+dskC+'">'+disk+'%</div><canvas class="sp" id="dsk-c"></canvas></div>'+
      '</div>';
  },

  drawCharts(){
    const r=this.state.resources||{};
    drawSparkline('cpu-c',r.cpu_history||[],'#00ff88');
    drawSparkline('mem-c',r.mem_history||[],'#00d4ff');
    drawSparkline('dsk-c',r.disk_history||[],'#9d4edd');
  },

  // ── LOGS ─────────────────────────────────────────────────
  renderLogs(){
    const f=this.state.logFilter;
    const srcs=['system','pipeline','dnsx','httpx','nuclei','nikto','amass','subfinder','assetfinder','findomain','sublist3r','crtsh','github_subdomains','theharvester','gowitness','monitor','backup','cleanup','dynamic','dispatch','ratelimit'];
    const ctrl='<div class="lctr">'+
      '<input placeholder="Search..." style="flex:1;min-width:100px" value="'+this.esc(f.q||'')+'" oninput="App.state.logFilter.q=this.value;App.loadLogs()">'+
      '<select onchange="App.state.logFilter.src=this.value;App.loadLogs()" style="width:auto"><option value="">All sources</option>'+srcs.map(s=>'<option value="'+s+'"'+(f.src===s?' selected':'')+'>'+s+'</option>').join('')+'</select>'+
      '<select onchange="App.state.logFilter.level=this.value;App.loadLogs()" style="width:auto"><option value="">All levels</option>'+['INFO','WARNING','ERROR','DEBUG'].map(l=>'<option value="'+l+'"'+(f.level===l?' selected':'')+'>'+l+'</option>').join('')+'</select>'+
      '<button class="btn btn-g btn-sm" onclick="App.loadLogs()">&#8635;</button></div>';
    const lines=(this.state.logs||[]).slice().reverse().map(l=>
      '<div class="ll"><span class="lts">'+l.ts+'</span><span class="lsr">'+l.src+'</span><span class="l'+l.level+'">'+this.esc(l.msg)+'</span></div>'
    ).join('');
    return '<div class="sh"><span class="stt">&#9670; Logs</span></div>'+ctrl+'<div class="lc">'+(lines||'<div class="nd">No logs match filters.</div>')+'</div>';
  },

  async loadLogs(){
    const f=this.state.logFilter,p=[];
    if(f.q) p.push('q='+encodeURIComponent(f.q));
    if(f.src) p.push('src='+encodeURIComponent(f.src));
    if(f.level) p.push('level='+encodeURIComponent(f.level));
    const r=await this.api('/api/logs?'+p.join('&'));
    if(r!==null) this.state.logs=r;
    this.render();
  },

  // ── SETTINGS ─────────────────────────────────────────────
  renderSettings(){
    const cfg=this.state.config||{},tools=cfg.tools||{};
    const st=this.state.settingsTab;
    const tabs=['tools','concurrency','apikeys','users','backups'];
    const tabBar=tabs.map(t=>'<button class="btn '+(st===t?'btn-g':'btn-gr')+' btn-sm" onclick="App.setSettingsTab(\''+t+'\')">'+t+'</button>').join(' ');
    let body='';
    if(st==='tools'){
      const tCards=Object.entries(tools).map(([k,t])=>{
        const id_=k.replace(/_/g,'-');
        return '<div class="acc"><div class="ach"><span>'+(t.name||k)+'</span><span class="aar">&#9654;</span></div>'+
          '<div class="acb">'+
          '<div class="tw-row" style="margin-bottom:10px"><label class="toggle"><input type="checkbox" id="te-'+id_+'" '+(t.enabled?'checked':'')+' onchange="App.toolProp(\''+k+'\',\'enabled\',this.checked)"><span class="tsl"></span></label>'+
          '<span style="color:var(--text2);font-size:12px">Enabled</span></div>'+
          '<div class="fg"><label class="fl">Command template ($DOMAIN$ $OUTPUT$ $INPUT_FILE$ $THREADS$ $WORDLIST$ $SUBDOMAIN$)</label>'+
          '<input id="tc-'+id_+'" value="'+this.esc(t.cmd||'')+'" onchange="App.toolProp(\''+k+'\',\'cmd\',this.value)"></div>'+
          '<div class="fg"><label class="fl">Max concurrent</label>'+
          '<input type="number" id="tm-'+id_+'" value="'+(t.max_concurrent||3)+'" min="1" max="20" style="width:70px" onchange="App.toolProp(\''+k+'\',\'max_concurrent\',+this.value)"></div>'+
          '<p style="color:var(--text2);font-size:11px">'+this.esc(t.description||'')+'</p></div></div>';
      }).join('');
      body=tCards+'<br><button class="btn btn-g" onclick="App.saveConfig()">&#10003; Save Tool Config</button>';
    }else if(st==='concurrency'){
      body='<div class="fg"><label class="fl">Max Running Jobs</label><input type="number" id="c-maxj" value="'+(cfg.max_running_jobs||5)+'" style="width:80px"></div>'+
        '<div class="tw-row" style="margin-bottom:10px"><label class="toggle"><input type="checkbox" id="c-dyn" '+(cfg.dynamic_mode?'checked':'')+' onchange="App.state.config.dynamic_mode=this.checked"><span class="tsl"></span></label><span style="color:var(--text2);font-size:12px">Dynamic mode (auto-scale based on CPU/RAM)</span></div>'+
        '<div class="fg"><label class="fl">Dynamic Min Jobs</label><input type="number" id="c-dmin" value="'+(cfg.dyn_min_jobs||1)+'" style="width:70px"></div>'+
        '<div class="fg"><label class="fl">Dynamic Max Jobs</label><input type="number" id="c-dmax" value="'+(cfg.dyn_max_jobs||10)+'" style="width:70px"></div>'+
        '<div class="fg"><label class="fl">Threads per tool</label><input type="number" id="c-thr" value="'+(cfg.threads||50)+'" style="width:70px"></div>'+
        '<div class="fg"><label class="fl">Wordlist path</label><input id="c-wl" value="'+this.esc(cfg.wordlist||'')+'"></div>'+
        '<div class="fg"><label class="fl">TLD expansion list (comma-separated)</label><input id="c-tlds" value="'+this.esc((cfg.tld_list||[]).join(','))+'"></div>'+
        '<br><button class="btn btn-g" onclick="App.saveConcurrency()">&#10003; Save</button>';
    }else if(st==='apikeys'){
      body='<div class="fg"><label class="fl">GitHub Token (for github-subdomains)</label>'+
        '<input id="c-gh" type="password" value="'+this.esc(cfg.github_token||'')+'" placeholder="ghp_..."></div>'+
        '<br><button class="btn btn-g" onclick="App.saveApiKeys()">&#10003; Save API Keys</button>';
    }else if(st==='users'){
      const urows=(this.state.users||[]).map(u=>'<tr><td>'+u.id+'</td><td>'+this.esc(u.username)+'</td><td>'+u.role+'</td><td class="lts">'+u.created_at+'</td>'+
        '<td><button class="btn btn-p btn-sm" onclick="App.deleteUser('+u.id+')">Del</button></td></tr>').join('');
      body='<div class="tw"><table><thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th><th></th></tr></thead>'+
        '<tbody>'+(urows||'<tr><td colspan="5" class="nd">No users.</td></tr>')+'</tbody></table></div><hr>'+
        '<div class="ct">New User</div>'+
        '<div class="fg"><label class="fl">Username</label><input id="nu-u" placeholder="username"></div>'+
        '<div class="fg"><label class="fl">Password</label><input id="nu-p" type="password"></div>'+
        '<div class="fg"><label class="fl">Role</label><select id="nu-r"><option value="user">user</option><option value="admin">admin</option></select></div>'+
        '<button class="btn btn-g" onclick="App.createUser()">+ Create User</button>';
    }else if(st==='backups'){
      const brows=(this.state.backups||[]).map(b=>'<tr><td>'+this.esc(b.name)+'</td>'+
        '<td>'+this.fmtBytes(b.size)+'</td><td class="lts">'+b.created_at+'</td>'+
        '<td><button class="btn btn-o btn-sm" onclick="App.restoreBackup(\''+this.esc(b.name)+'\')">&#8661; Restore</button></td></tr>').join('');
      body='<button class="btn btn-g" style="margin-bottom:12px" onclick="App.createBackup()">&#128190; Create Backup Now</button>'+
        '<div class="tw"><table><thead><tr><th>File</th><th>Size</th><th>Created</th><th></th></tr></thead>'+
        '<tbody>'+(brows||'<tr><td colspan="4" class="nd">No backups.</td></tr>')+'</tbody></table></div>';
    }
    return '<div class="sh"><span class="stt">&#9670; Settings</span></div>'+
      '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px">'+tabBar+'</div>'+
      '<div class="card">'+body+'</div>';
  },

  async setSettingsTab(t){
    this.state.settingsTab=t;
    if(t==='users'){ const u=await this.api('/api/users'); if(u) this.state.users=u; }
    if(t==='backups'){ const b=await this.api('/api/backups'); if(b) this.state.backups=b; }
    if(!Object.keys(this.state.config).length){ const c=await this.api('/api/config'); if(c) this.state.config=c; }
    this.render();
  },

  toolProp(key,prop,val){
    if(!this.state.config.tools) this.state.config.tools={};
    if(!this.state.config.tools[key]) this.state.config.tools[key]={};
    this.state.config.tools[key][prop]=val;
  },
  async saveConfig(){ await this.put('/api/config',{tools:this.state.config.tools}); this.toast('Tool config saved','st'); },
  async saveConcurrency(){
    await this.put('/api/config',{
      max_running_jobs:+(document.getElementById('c-maxj').value),
      dynamic_mode:document.getElementById('c-dyn').checked,
      dyn_min_jobs:+(document.getElementById('c-dmin').value),
      dyn_max_jobs:+(document.getElementById('c-dmax').value),
      threads:+(document.getElementById('c-thr').value),
      wordlist:document.getElementById('c-wl').value,
      tld_list:document.getElementById('c-tlds').value.split(',').map(s=>s.trim()).filter(Boolean),
    });
    this.toast('Settings saved','st');
    await this.fetchState();
  },
  async saveApiKeys(){ await this.put('/api/config',{github_token:document.getElementById('c-gh').value}); this.toast('Saved','st'); },
  async createUser(){
    const u=document.getElementById('nu-u').value.trim(),p=document.getElementById('nu-p').value,r=document.getElementById('nu-r').value;
    if(!u||!p) return this.toast('username + password required','er');
    await this.post('/api/users',{username:u,password:p,role:r});
    const users=await this.api('/api/users'); if(users) this.state.users=users;
    this.render(); this.toast('User created','st');
  },
  async deleteUser(id){
    if(!confirm('Delete user?')) return;
    await this.del('/api/users/'+id);
    const users=await this.api('/api/users'); if(users) this.state.users=users;
    this.render();
  },
  async createBackup(){
    const r=await this.post('/api/backups',{});
    if(r){this.toast('Backup: '+r.name,'st');const b=await this.api('/api/backups');if(b)this.state.backups=b;this.render();}
  },
  async restoreBackup(name){
    if(!confirm('Restore '+name+'? Current data will be replaced.')) return;
    await this.post('/api/backups/restore/'+encodeURIComponent(name));
    this.toast('Restored','st');
  },

  badge(s){
    const m={running:'bg pulse',pending:'bc',paused:'bo',completed:'bc',failed:'br',cancelled:'bgr'};
    return '<span class="bdg '+(m[s]||'bgr')+'">'+s+'</span>';
  },
  esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');},
  fmtBytes(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'KB';return(b/1048576).toFixed(1)+'MB';},
};

// ── sparkline ───────────────────────────────────────────────
function drawSparkline(id,data,color){
  const canvas=document.getElementById(id);
  if(!canvas||!data||!data.length) return;
  const dpr=window.devicePixelRatio||1;
  canvas.width=canvas.offsetWidth*dpr;canvas.height=canvas.offsetHeight*dpr;
  const ctx=canvas.getContext('2d');ctx.scale(dpr,dpr);
  const w=canvas.offsetWidth,h=canvas.offsetHeight;
  ctx.clearRect(0,0,w,h);
  const step=w/Math.max(data.length-1,1);
  ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=1.5;ctx.shadowColor=color;ctx.shadowBlur=5;
  data.forEach((v,i)=>{const x=i*step,y=h-(v/100)*h*0.88-h*0.06;i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);});
  ctx.stroke();ctx.shadowBlur=0;
  if(data.length>1){
    ctx.lineTo((data.length-1)*step,h);ctx.lineTo(0,h);ctx.closePath();
    ctx.fillStyle=color.replace('#00ff88','rgba(0,255,136,0.12)').replace('#00d4ff','rgba(0,212,255,0.12)').replace('#9d4edd','rgba(157,78,221,0.12)');
    ctx.fill();
  }
}

// ── node graph ──────────────────────────────────────────────
class NodeGraph{
  constructor(canvas){this.canvas=canvas;this.nodes=[];this.frame=null;}
  load(domain,subs){
    const cx=this.canvas.width/2,cy=this.canvas.height/2;
    this.nodes=[{id:domain,label:domain,x:cx,y:cy,r:9,color:'#00ff88',type:'root',vx:0,vy:0}];
    subs.slice(0,80).forEach((s,i)=>{
      const a=(i/Math.max(subs.length,1))*Math.PI*2,rd=110+(i%4)*30;
      const c=s.http_status===200?'#00d4ff':s.http_status?'#ff8800':'#9d4edd';
      this.nodes.push({id:s.subdomain,label:s.subdomain.replace('.'+domain,''),
        x:cx+Math.cos(a)*rd,y:cy+Math.sin(a)*rd,r:4,color:c,type:'sub',vx:0,vy:0});
    });
    if(this.frame) cancelAnimationFrame(this.frame);
    const tick=()=>{this.physics();this.draw();this.frame=requestAnimationFrame(tick);};tick();
  }
  physics(){
    const[root,...rest]=this.nodes;
    rest.forEach(n=>{
      const dx=root.x-n.x,dy=root.y-n.y,d=Math.hypot(dx,dy)||1,f=(d-155)*0.016;
      n.vx+=(dx/d)*f;n.vy+=(dy/d)*f;
      rest.forEach(m=>{if(m===n)return;const ex=n.x-m.x,ey=n.y-m.y,ed=Math.hypot(ex,ey)||1;if(ed<36){n.vx+=(ex/ed)*0.3;n.vy+=(ey/ed)*0.3;}});
      n.vx*=0.87;n.vy*=0.87;
      n.x=Math.max(16,Math.min(this.canvas.width-16,n.x+n.vx));
      n.y=Math.max(16,Math.min(this.canvas.height-16,n.y+n.vy));
    });
  }
  draw(){
    const ctx=this.canvas.getContext('2d');
    ctx.fillStyle='#0a0a0f';ctx.fillRect(0,0,this.canvas.width,this.canvas.height);
    const[root,...rest]=this.nodes;
    ctx.strokeStyle='rgba(0,255,136,0.1)';ctx.lineWidth=0.5;
    rest.forEach(n=>{ctx.beginPath();ctx.moveTo(root.x,root.y);ctx.lineTo(n.x,n.y);ctx.stroke();});
    this.nodes.forEach(n=>{
      ctx.beginPath();ctx.arc(n.x,n.y,n.r,0,Math.PI*2);
      ctx.fillStyle=n.color;ctx.shadowColor=n.color;ctx.shadowBlur=10;ctx.fill();ctx.shadowBlur=0;
      if(n.type==='root'||rest.length<22){
        ctx.fillStyle='#c8d6e5';ctx.font='9px monospace';ctx.fillText(n.label,n.x+n.r+3,n.y+3);
      }
    });
  }
}

// ── boot ────────────────────────────────────────────────────
async function doLogin(e){
  e.preventDefault();
  const u=document.getElementById('l-user').value,p=document.getElementById('l-pass').value;
  const err=document.getElementById('l-err');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
    const d=await r.json();
    if(d.success){
      document.getElementById('lscreen').style.display='none';
      document.getElementById('app').style.display='';
      App.init();
    }else{err.textContent=d.message||'Login failed';}
  }catch(ex){err.textContent='Network error';}
}

window.addEventListener('DOMContentLoaded',async()=>{
  try{
    const r=await fetch('/api/state');
    if(r.status===401){
      document.getElementById('lscreen').style.display='flex';
    }else{
      document.getElementById('lscreen').style.display='none';
      document.getElementById('app').style.display='';
      App.init();
    }
  }catch(e){
    document.getElementById('lscreen').style.display='flex';
  }
});
</script>
</body>
</html>"""

# ═══════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════
def _generate_self_signed(cert_path: str, key_path: str) -> None:
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes",
            "-subj", "/CN=ReconForge/O=ReconForge/C=US",
        ], check=True, capture_output=True)
        emit(f"Self-signed cert: {cert_path}", "INFO", "tls")
    except Exception as e:
        emit(f"openssl failed: {e}. Falling back to HTTP.", "WARNING", "tls")
        raise

def main() -> None:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{VERSION}")
    parser.add_argument("--host",  default=DEFAULT_HOST)
    parser.add_argument("--port",  type=int, default=DEFAULT_PORT)
    parser.add_argument("--https", action="store_true")
    parser.add_argument("--cert",  default="")
    parser.add_argument("--key",   default="")
    parser.add_argument("--skip-setup", action="store_true")
    args = parser.parse_args()

    # First-run wizard. Runs BEFORE the server binds and BEFORE init_db
    # writes anything, so credentials/keys land in
    # ~/.config/reconforge/settings.json (local file, 0600) and never
    # touch the web DB. --skip-setup disables for systemd/CI use.
    if not args.skip_setup:
        from wizard.app import is_setup_complete, run_text_wizard, settings_path
        if not is_setup_complete():
            if not sys.stdin.isatty():
                print(f"\n[setup] {settings_path()} not found and stdin is "
                      "not a TTY.\n[setup] Run `python -m wizard` "
                      "interactively first, or pass --skip-setup to bypass "
                      "(the app will run but tools will lack identities/keys).\n",
                      file=sys.stderr)
                sys.exit(2)
            print("\n[setup] First run detected — launching setup wizard.")
            print("[setup] Pass --skip-setup to bypass.\n")
            run_text_wizard()
            print("\n[setup] Wizard complete. Starting server…\n")

    # Init
    init_db()
    init_tool_gates()

    if not args.skip_setup:
        ensure_admin()
        # Seed the web DB's config table from the local settings file so
        # the Settings page in the UI is pre-populated. The local file
        # stays the source of truth for keys; the DB is just a mirror.
        _seed_config_from_settings()

    # Load config into cache
    get_config("max_running_jobs", 5)
    get_config("dynamic_mode", False)

    # TLS
    ctx = None
    if args.https or args.cert:
        cert = args.cert or os.path.join(DATA_DIR, "server.crt")
        key  = args.key  or os.path.join(DATA_DIR, "server.key")
        if not os.path.exists(cert) or not os.path.exists(key):
            try:
                _generate_self_signed(cert, key)
            except Exception:
                args.https = False
        if os.path.exists(cert) and os.path.exists(key):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)

    # Start background workers
    start_workers()

    # HTTP server
    server = HTTPServer((args.host, args.port), ReconHandler)
    if ctx:
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    proto = "https" if ctx else "http"
    emit(f"Listening on {proto}://{args.host}:{args.port}", "INFO", "system")
    display_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    print(f"\n  {APP_NAME} v{VERSION}  —  {proto}://{display_host}:{args.port}\n")

    def _sig(*_):
        emit("Shutting down…", "INFO", "system")
        _shutdown.set()
        server.shutdown()

    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _sig()

if __name__ == "__main__":
    main()
