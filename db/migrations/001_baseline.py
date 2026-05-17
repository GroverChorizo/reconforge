"""001 — baseline schema. Mirrors main._SCHEMA exactly.

CREATE IF NOT EXISTS makes this safe to apply against an existing DB
that was initialized by main.init_db() before the runner existed.
"""

name = "001_baseline"

_SQL = """
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


def up(conn):
    conn.executescript(_SQL)


def down(conn):
    # forward-only by policy; baseline never reverts
    raise NotImplementedError("baseline is not reversible")
