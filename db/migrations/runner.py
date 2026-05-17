#!/usr/bin/env python3
"""
Forward-only SQLite migration runner.

Discovers ``NNN_name.py`` files in this directory, sorts by filename, and
applies any not yet recorded in the existing ``migrations`` ledger table
(created by ``main._SCHEMA``).

Each migration module exposes::

    name = "002_findings_attack"

    def up(conn: sqlite3.Connection) -> None: ...
    def down(conn: sqlite3.Connection) -> None: ...  # optional, forward-only by policy

Invocation:
    python -m db.migrations.runner status      # from reconforge/ dir
    python -m db.migrations.runner up
    python -m db.migrations.runner up --no-backup
"""
from __future__ import annotations

import argparse
import importlib
import os
import pkgutil
import re
import sqlite3
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple

_MIG_FILE_RE = re.compile(r"^\d{3}_[a-z0-9_]+$")


# ── discovery ───────────────────────────────────────────────────────
def _migrations_pkg():
    """Return this package itself; we discover sibling files dynamically."""
    return sys.modules[__package__]


def discover() -> List[str]:
    """Return migration module names in lexical order (NNN_*)."""
    pkg = _migrations_pkg()
    names = []
    for _finder, name, ispkg in pkgutil.iter_modules(pkg.__path__):
        if ispkg or name == "runner":
            continue
        if _MIG_FILE_RE.match(name):
            names.append(name)
    return sorted(names)


def _load(name: str):
    return importlib.import_module(f"{__package__}.{name}")


# ── ledger ──────────────────────────────────────────────────────────
def _ensure_ledger(conn: sqlite3.Connection) -> None:
    """Idempotent: main._SCHEMA already creates this, but the runner
    must work even before main.init_db has been called (e.g. from CLI)."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS migrations ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  name TEXT UNIQUE NOT NULL,"
        "  applied_at TEXT DEFAULT (datetime('now'))"
        ")"
    )
    conn.commit()


def applied(conn: sqlite3.Connection) -> List[str]:
    _ensure_ledger(conn)
    rows = conn.execute("SELECT name FROM migrations ORDER BY name").fetchall()
    return [r[0] for r in rows]


def pending(conn: sqlite3.Connection) -> List[str]:
    done = set(applied(conn))
    return [n for n in discover() if n not in done]


# ── apply ───────────────────────────────────────────────────────────
def _apply_one(conn: sqlite3.Connection, name: str) -> None:
    mod = _load(name)
    if not hasattr(mod, "up"):
        raise RuntimeError(f"migration {name} has no up()")
    mod.up(conn)
    conn.execute("INSERT INTO migrations(name) VALUES(?)", (name,))
    conn.commit()


def run_pending(
    conn: sqlite3.Connection,
    backup_fn: Optional[Callable[[], str]] = None,
) -> List[str]:
    """Apply all pending migrations in order. Returns names applied.

    If backup_fn is provided AND there is at least one pending migration
    AND the DB already has user data, call backup_fn() first. Backup
    failure aborts the migration run (better to stop than risk an
    unrecoverable schema change).
    """
    todo = pending(conn)
    if not todo:
        return []

    if backup_fn is not None and _has_user_data(conn):
        try:
            backup_fn()
        except Exception as e:
            raise RuntimeError(f"pre-migration backup failed: {e}") from e

    applied_now: List[str] = []
    for name in todo:
        try:
            _apply_one(conn, name)
            applied_now.append(name)
        except Exception:
            # roll back the in-flight migration; previously-applied ones stay
            conn.rollback()
            raise
    return applied_now


def _has_user_data(conn: sqlite3.Connection) -> bool:
    """Heuristic: do we have anything worth backing up?"""
    for tbl in ("targets", "subdomains", "users", "completed_jobs"):
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()
            if row and row[0] > 0:
                return True
        except sqlite3.OperationalError:
            continue
    return False


# ── status ──────────────────────────────────────────────────────────
def status(conn: sqlite3.Connection) -> dict:
    return {"applied": applied(conn), "pending": pending(conn)}


# ── CLI ─────────────────────────────────────────────────────────────
def _open_db() -> Tuple[sqlite3.Connection, Callable[[], str]]:
    """Open the configured DB without importing main (which has side effects).

    Honors RECON_DATA_DIR env var, falls back to <repo>/recon_data.
    Returns (conn, backup_fn) where backup_fn defers to main.create_backup
    when the module is importable.
    """
    base = Path(__file__).resolve().parent.parent.parent
    data_dir = os.environ.get("RECON_DATA_DIR", str(base / "recon_data"))
    db_path = os.path.join(data_dir, "recon.db")
    os.makedirs(data_dir, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    def _backup() -> str:
        try:
            sys.path.insert(0, str(base))
            import main as M
            # main.DATA_DIR etc. may not be initialized; sync them
            M.DATA_DIR = data_dir
            M.DB_PATH = db_path
            M.BACKUP_DIR = os.path.join(data_dir, "backups")
            M.TEMP_DIR = os.path.join(data_dir, "tmp")
            os.makedirs(M.BACKUP_DIR, exist_ok=True)
            os.makedirs(M.TEMP_DIR, exist_ok=True)
            return M.create_backup("pre_migration")
        except Exception as e:
            # Fall back to a simple file copy so we never migrate w/o a backup
            import shutil
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = os.path.join(data_dir, "backups")
            os.makedirs(backup_dir, exist_ok=True)
            dst = os.path.join(backup_dir, f"pre_migration_{ts}.db")
            shutil.copy2(db_path, dst)
            return dst

    return conn, _backup


def _cli(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="db.migrations.runner")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="Show applied and pending migrations.")
    up = sub.add_parser("up", help="Apply all pending migrations.")
    up.add_argument("--no-backup", action="store_true",
                    help="Skip pre-migration backup (use only when DB is fresh).")
    args = p.parse_args(argv)

    conn, backup_fn = _open_db()
    try:
        if args.cmd == "status":
            s = status(conn)
            print(f"applied ({len(s['applied'])}):")
            for n in s["applied"]:
                print(f"  [x] {n}")
            print(f"pending ({len(s['pending'])}):")
            for n in s["pending"]:
                print(f"  [ ] {n}")
            return 0
        if args.cmd == "up":
            done = run_pending(conn, None if args.no_backup else backup_fn)
            if done:
                print(f"applied {len(done)} migration(s):")
                for n in done:
                    print(f"  [x] {n}")
            else:
                print("nothing to do - already up to date")
            return 0
    finally:
        conn.close()
    return 2


if __name__ == "__main__":
    sys.exit(_cli())
