"""005 — programs as first-class entity.

Until v3, scope JSON was passed at job-creation time and never persisted as
its own row. v3 makes Programs the root context for Mission Control, scope
badges, mode selection, and the workspace shell. Every job belongs to one
program; legacy jobs get a nullable program_id (left NULL on existing rows).

scope_json + out_of_scope_json mirror the structure consumed by
scope_guard.check (see scope_guard.py docstring for the schema).
"""

name = "005_programs"

_SQL = """
CREATE TABLE IF NOT EXISTS programs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    slug                TEXT UNIQUE NOT NULL,
    name                TEXT NOT NULL,
    platform            TEXT NOT NULL,                 -- intigriti|hackerone|bugcrowd|yeswehack|synack|other
    platform_handle     TEXT,
    policy_url          TEXT,
    scope_json          TEXT NOT NULL DEFAULT '[]',     -- list[entry]
    out_of_scope_json   TEXT NOT NULL DEFAULT '[]',     -- list[entry]
    bounty_ranges_json  TEXT NOT NULL DEFAULT '{}',     -- {severity: [low, high]}
    contacts_json       TEXT NOT NULL DEFAULT '{}',     -- {email, slack, ...}
    notes               TEXT DEFAULT '',
    created_at          TEXT DEFAULT (datetime('now')),
    updated_at          TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_programs_platform ON programs(platform);
"""


def _has_column(conn, table: str, col: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any((r[1] if not isinstance(r, dict) else r["name"]) == col for r in rows)


def up(conn):
    conn.executescript(_SQL)
    # Bridge FKs onto pre-existing tables. SQLite ADD COLUMN is forward-only
    # and tolerates re-runs only if we check first.
    if not _has_column(conn, "targets", "program_id"):
        conn.execute(
            "ALTER TABLE targets ADD COLUMN program_id INTEGER "
            "REFERENCES programs(id) ON DELETE SET NULL"
        )
    if not _has_column(conn, "completed_jobs", "program_id"):
        conn.execute(
            "ALTER TABLE completed_jobs ADD COLUMN program_id INTEGER "
            "REFERENCES programs(id) ON DELETE SET NULL"
        )
    conn.commit()


def down(conn):
    # forward-only by policy
    raise NotImplementedError("005 is not reversible")
