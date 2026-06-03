"""Tests for the recon-monitor scheduler: the quiet-band cadence ladder, the
new-asset delta, the reschedule math, and the CyberBrain post-complete hook.

Run: pytest tests/test_schedule.py -v
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import main as M  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Each test gets its own data dir + DB (mirrors test_reconforge.py)."""
    M.DATA_DIR        = str(tmp_path)
    M.DB_PATH         = str(tmp_path / "recon.db")
    M.JOBS_DIR        = str(tmp_path / "jobs")
    M.SCREENSHOTS_DIR = str(tmp_path / "screenshots")
    M.BACKUP_DIR      = str(tmp_path / "backups")
    M.TEMP_DIR        = str(tmp_path / "tmp")
    M._db_local.conn = None
    M._cfg_cache.clear()
    M.init_db()
    # Keep the hook focused on delta+reschedule: no file emit / vault / notify.
    M.set_config("auto_emit_contract", False)
    M.set_config("auto_ingest_vault", False)
    M.set_config("notify_on_new_assets", False)
    yield
    try:
        if getattr(M._db_local, "conn", None):
            M._db_local.conn.close()
            M._db_local.conn = None
    except Exception:
        pass


def _utc(days_ago=0):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return (now - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


def _enroll(domain, *, last_run_at=None, last_new_asset_at=None, interval=86400):
    M.db_exec(
        "INSERT INTO recon_schedule(domain,enabled,interval_seconds,last_run_at,last_new_asset_at) "
        "VALUES(?,?,?,?,?)", (domain, 1, interval, last_run_at, last_new_asset_at))


def _add_sub(domain, sub, created_at):
    M.db_exec("INSERT INTO subdomains(domain,subdomain,created_at) VALUES(?,?,?)",
              (domain, sub, created_at))


def _job(domain):
    j = M.Job(domain, "scheduler", {"monitor": True})
    j.started_at = _utc(0)
    j.completed_at = _utc(0)
    return j


# ── pure cadence ladder ──────────────────────────────────────────────
def test_interval_bands_exact_edges():
    assert M._monitor_interval_for(0)    == 4   * 3600
    assert M._monitor_interval_for(2.9)  == 4   * 3600
    assert M._monitor_interval_for(3)    == 8   * 3600
    assert M._monitor_interval_for(6)    == 12  * 3600
    assert M._monitor_interval_for(9)    == 24  * 3600
    assert M._monitor_interval_for(12)   == 48  * 3600
    assert M._monitor_interval_for(15)   == 96  * 3600
    assert M._monitor_interval_for(18)   == 168 * 3600


def test_interval_caps_at_seven_days():
    assert M._monitor_interval_for(30)   == 168 * 3600
    assert M._monitor_interval_for(1000) == 168 * 3600


# ── delta drives the cadence ─────────────────────────────────────────
def test_new_assets_reset_cadence_to_floor():
    """A quiet target (24h) that suddenly produces new assets snaps to 4h."""
    _enroll("example.com", last_run_at=_utc(1), last_new_asset_at=_utc(20), interval=86400)
    _add_sub("example.com", "old.example.com", _utc(5))    # before boundary → not new
    _add_sub("example.com", "new1.example.com", _utc(0))   # after boundary → new
    _add_sub("example.com", "new2.example.com", _utc(0))

    M._post_complete(_job("example.com"), "completed")

    row = M.db_row("SELECT * FROM recon_schedule WHERE domain=?", ("example.com",))
    assert row["last_delta_count"] == 2
    assert row["interval_seconds"] == 4 * 3600          # reset to floor
    assert row["next_run_at"] is not None


def test_quiet_run_steps_up_by_band():
    """No new assets and quiet ~10 days → interval is the 9-day band (24h)."""
    _enroll("quiet.com", last_run_at=_utc(1), last_new_asset_at=_utc(10), interval=43200)
    _add_sub("quiet.com", "stale.quiet.com", _utc(5))      # before boundary → not new

    M._post_complete(_job("quiet.com"), "completed")

    row = M.db_row("SELECT * FROM recon_schedule WHERE domain=?", ("quiet.com",))
    assert row["last_delta_count"] == 0
    assert row["interval_seconds"] == 24 * 3600
    # last_new_asset_at unchanged on a quiet run
    assert row["last_new_asset_at"].startswith(_utc(10)[:10])


def test_first_run_is_baseline_no_alert_floor_cadence():
    """First run (last_run_at NULL): everything is baseline, cadence at 4h."""
    _enroll("fresh.com", last_run_at=None, last_new_asset_at=None)
    _add_sub("fresh.com", "a.fresh.com", _utc(0))
    _add_sub("fresh.com", "b.fresh.com", _utc(0))

    with patch.object(M, "_notify_new_assets") as notify:
        M._post_complete(_job("fresh.com"), "completed")
        notify.assert_not_called()                          # baseline never alerts

    row = M.db_row("SELECT * FROM recon_schedule WHERE domain=?", ("fresh.com",))
    assert row["last_delta_count"] == 0
    assert row["interval_seconds"] == 4 * 3600
    assert row["last_new_asset_at"] is not None             # baseline establishes the clock


# ── notification + isolation ─────────────────────────────────────────
def test_notify_fires_on_new_assets():
    M.set_config("notify_on_new_assets", True)
    _enroll("alert.com", last_run_at=_utc(1), last_new_asset_at=_utc(2))
    _add_sub("alert.com", "new.alert.com", _utc(0))

    with patch("main.shutil.which", return_value="/usr/bin/notify"), \
         patch("main.subprocess.run") as run:
        M._post_complete(_job("alert.com"), "completed")
        assert run.called
        argv = run.call_args[0][0]
        assert argv[0] == "notify" and "monitor-alert.com" in argv


def test_unenrolled_domain_is_noop():
    """A completed job for a non-enrolled domain must not create a schedule row."""
    M._post_complete(_job("random.com"), "completed")
    assert M.db_row("SELECT * FROM recon_schedule WHERE domain=?", ("random.com",)) is None


def test_hook_failure_never_breaks_completion():
    """A crash inside the post-hook must not stop a job from being recorded."""
    job = _job("boom.com")
    with M._lock:
        M._jobs[job.id] = job
    with patch.object(M, "_post_complete", side_effect=RuntimeError("kaboom")):
        M._complete_job(job, "completed")                   # must not raise
    row = M.db_row("SELECT * FROM completed_jobs WHERE job_id=?", (job.id,))
    assert row is not None and row["domain"] == "boom.com"


def test_monitor_job_skips_loud_steps():
    job = M.Job("x.com", "scheduler", {"monitor": True})
    for loud in ("nuclei", "nikto", "gowitness"):
        assert job.should_skip(loud)
    assert not job.should_skip("httpx")
