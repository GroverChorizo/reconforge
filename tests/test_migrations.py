"""
Tests for the Phase 2 migration runner + the four shipped migrations.

Covers:
  - discovery (lexical ordering)
  - apply against fresh DB
  - apply against populated-by-main.init_db DB (back-compat path)
  - idempotency (re-run is a no-op)
  - backup_fn invoked only when data exists AND pending migrations exist
  - FK cascade on findings → attack_techniques and findings → submission_drafts
  - CLI status / up
"""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import main as M
from db.migrations import runner as R


# ═══════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════
@pytest.fixture
def fresh_db(tmp_path):
    """A bare SQLite file with nothing in it."""
    path = tmp_path / "fresh.db"
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    yield conn, path
    conn.close()


@pytest.fixture
def main_initialized_db(tmp_path):
    """A DB that main.init_db() has already touched — what most users have."""
    M.DATA_DIR        = str(tmp_path)
    M.DB_PATH         = str(tmp_path / "recon.db")
    M.JOBS_DIR        = str(tmp_path / "jobs")
    M.SCREENSHOTS_DIR = str(tmp_path / "screenshots")
    M.BACKUP_DIR      = str(tmp_path / "backups")
    M.TEMP_DIR        = str(tmp_path / "tmp")
    M._db_local.conn = None
    M._cfg_cache.clear()
    M.init_db()
    yield M.get_db(), Path(M.DB_PATH)
    try:
        if hasattr(M._db_local, "conn") and M._db_local.conn:
            M._db_local.conn.close()
            M._db_local.conn = None
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
#  DISCOVERY
# ═══════════════════════════════════════════════════════════
class TestDiscovery:

    def test_finds_all_migrations(self):
        mods = R.discover()
        assert mods == [
            "001_baseline",
            "002_findings_attack",
            "003_agent_memory",
            "004_submission_drafts",
            "005_programs",
            "006_evidence_modes_taxonomy",
            "007_recon_assets",
        ]

    def test_runner_module_excluded(self):
        assert "runner" not in R.discover()


# ═══════════════════════════════════════════════════════════
#  FRESH DB
# ═══════════════════════════════════════════════════════════
class TestFreshDB:

    def test_pending_lists_all_four(self, fresh_db):
        conn, _ = fresh_db
        assert R.pending(conn) == [
            "001_baseline",
            "002_findings_attack",
            "003_agent_memory",
            "004_submission_drafts",
            "005_programs",
            "006_evidence_modes_taxonomy",
            "007_recon_assets",
        ]

    def test_run_pending_applies_all_four(self, fresh_db):
        conn, _ = fresh_db
        applied = R.run_pending(conn)
        assert len(applied) == 7

    def test_baseline_tables_exist(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        for tbl in ("targets", "subdomains", "users", "history", "monitors"):
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (tbl,)
            ).fetchone()
            assert row is not None, f"missing table {tbl}"

    def test_new_tables_exist(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        for tbl in ("findings", "attack_techniques", "agent_memory",
                    "agent_runs", "submission_drafts", "recon_assets"):
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (tbl,)
            ).fetchone()
            assert row is not None, f"missing table {tbl}"

    def test_ledger_populated(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        rows = conn.execute("SELECT name FROM migrations ORDER BY name").fetchall()
        names = [r[0] for r in rows]
        assert names == [
            "001_baseline",
            "002_findings_attack",
            "003_agent_memory",
            "004_submission_drafts",
            "005_programs",
            "006_evidence_modes_taxonomy",
            "007_recon_assets",
        ]


# ═══════════════════════════════════════════════════════════
#  IDEMPOTENCY
# ═══════════════════════════════════════════════════════════
class TestIdempotency:

    def test_second_run_is_noop(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        applied_again = R.run_pending(conn)
        assert applied_again == []

    def test_pending_empty_after_apply(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        assert R.pending(conn) == []


# ═══════════════════════════════════════════════════════════
#  POPULATED DB (back-compat)
# ═══════════════════════════════════════════════════════════
class TestPopulatedDB:

    def test_main_init_db_runs_migrations(self, main_initialized_db):
        # main.init_db() now invokes the runner; all migrations should be applied.
        conn, _ = main_initialized_db
        rows = conn.execute("SELECT name FROM migrations").fetchall()
        names = {r[0] for r in rows}
        assert names == {
            "001_baseline",
            "002_findings_attack",
            "003_agent_memory",
            "004_submission_drafts",
            "005_programs",
            "006_evidence_modes_taxonomy",
            "007_recon_assets",
        }

    def test_existing_data_preserved(self, main_initialized_db):
        conn, _ = main_initialized_db
        # write a target before re-running migrations
        conn.execute("INSERT INTO targets(domain) VALUES (?)", ("preserved.com",))
        conn.commit()
        # second run is a no-op
        applied = R.run_pending(conn)
        assert applied == []
        row = conn.execute("SELECT domain FROM targets WHERE domain='preserved.com'").fetchone()
        assert row is not None


# ═══════════════════════════════════════════════════════════
#  BACKUP BEHAVIOR
# ═══════════════════════════════════════════════════════════
class TestBackup:

    def test_no_backup_when_db_empty(self, fresh_db):
        conn, _ = fresh_db
        calls = []
        R.run_pending(conn, backup_fn=lambda: (calls.append(1), "noop.tar.gz")[1])
        assert calls == [], "backup must not fire on empty DB"

    def test_backup_fires_when_data_present(self, fresh_db):
        conn, _ = fresh_db
        # apply baseline so tables exist, then add a user-data row
        R.run_pending(conn)
        conn.execute("INSERT INTO targets(domain) VALUES (?)", ("hasdata.com",))
        conn.execute("DELETE FROM migrations WHERE name='004_submission_drafts'")
        conn.execute("DROP TABLE submission_drafts")
        conn.commit()
        calls = []
        R.run_pending(conn, backup_fn=lambda: (calls.append(1), "backup.tar.gz")[1])
        assert calls == [1], "backup must fire when re-migrating populated DB"

    def test_backup_failure_aborts_migration(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        conn.execute("INSERT INTO targets(domain) VALUES (?)", ("hasdata.com",))
        conn.execute("DELETE FROM migrations WHERE name='004_submission_drafts'")
        conn.execute("DROP TABLE submission_drafts")
        conn.commit()
        def boom():
            raise OSError("disk full")
        with pytest.raises(RuntimeError, match="backup failed"):
            R.run_pending(conn, backup_fn=boom)
        # submission_drafts must NOT have been re-applied
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='submission_drafts'"
        ).fetchone()
        assert row is None


# ═══════════════════════════════════════════════════════════
#  SCHEMA / FOREIGN KEY BEHAVIOR
# ═══════════════════════════════════════════════════════════
class TestSchema:

    def test_finding_cascade_to_attack_techniques(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        conn.execute(
            "INSERT INTO findings(bug_id, domain, vuln_class, title) VALUES (?,?,?,?)",
            ("BUG-T-001", "x.com", "idor", "test")
        )
        fid = conn.execute("SELECT id FROM findings WHERE bug_id='BUG-T-001'").fetchone()[0]
        conn.execute(
            "INSERT INTO attack_techniques(finding_id, tactic, technique_id) VALUES (?,?,?)",
            (fid, "TA0001", "T1190")
        )
        conn.commit()
        conn.execute("DELETE FROM findings WHERE id=?", (fid,))
        conn.commit()
        row = conn.execute(
            "SELECT COUNT(*) FROM attack_techniques WHERE finding_id=?", (fid,)
        ).fetchone()
        assert row[0] == 0, "cascade delete failed"

    def test_finding_cascade_to_submission_drafts(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        conn.execute(
            "INSERT INTO findings(bug_id, domain, vuln_class, title) VALUES (?,?,?,?)",
            ("BUG-T-002", "x.com", "ssrf", "t")
        )
        fid = conn.execute("SELECT id FROM findings WHERE bug_id='BUG-T-002'").fetchone()[0]
        conn.execute(
            "INSERT INTO submission_drafts(finding_id, platform) VALUES (?,?)",
            (fid, "hackerone")
        )
        conn.commit()
        conn.execute("DELETE FROM findings WHERE id=?", (fid,))
        conn.commit()
        row = conn.execute(
            "SELECT COUNT(*) FROM submission_drafts WHERE finding_id=?", (fid,)
        ).fetchone()
        assert row[0] == 0

    def test_agent_memory_unique_constraint(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        conn.execute(
            "INSERT INTO agent_memory(job_id, agent, key, value_json) VALUES (?,?,?,?)",
            ("J1", "strategist", "plan_v1", '{"a":1}')
        )
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO agent_memory(job_id, agent, key, value_json) VALUES (?,?,?,?)",
                ("J1", "strategist", "plan_v1", '{"a":2}')
            )

    def test_submission_drafts_unique_constraint(self, fresh_db):
        conn, _ = fresh_db
        R.run_pending(conn)
        conn.execute(
            "INSERT INTO findings(bug_id, domain, vuln_class, title) VALUES (?,?,?,?)",
            ("BUG-T-003", "x.com", "xss", "t")
        )
        fid = conn.execute("SELECT id FROM findings WHERE bug_id='BUG-T-003'").fetchone()[0]
        conn.execute(
            "INSERT INTO submission_drafts(finding_id, platform) VALUES (?,?)",
            (fid, "hackerone")
        )
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO submission_drafts(finding_id, platform) VALUES (?,?)",
                (fid, "hackerone")
            )


# ═══════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════
class TestCLI:

    def _run(self, args, data_dir):
        env = os.environ.copy()
        env["RECON_DATA_DIR"] = str(data_dir)
        # Use module form so package imports resolve.
        return subprocess.run(
            [sys.executable, "-m", "db.migrations.runner", *args],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=30,
        )

    def test_status_on_fresh_dir(self, tmp_path):
        r = self._run(["status"], tmp_path)
        assert r.returncode == 0, r.stderr
        assert "pending (7)" in r.stdout

    def test_up_applies_all(self, tmp_path):
        r = self._run(["up", "--no-backup"], tmp_path)
        assert r.returncode == 0, r.stderr
        assert "applied 7 migration" in r.stdout

    def test_up_twice_noop(self, tmp_path):
        self._run(["up", "--no-backup"], tmp_path)
        r = self._run(["up", "--no-backup"], tmp_path)
        assert r.returncode == 0
        assert "nothing to do" in r.stdout.lower()
