"""
pytest test suite for ReconForge.

Run:
    pip install pytest
    pytest tests/ -v
"""
import json
import os
import sys
import threading
import time
import io
import sqlite3
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# ── make main importable ────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))
import main as M


# ═══════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════
@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Give each test its own isolated data directory and DB."""
    M.DATA_DIR        = str(tmp_path)
    M.DB_PATH         = str(tmp_path / "recon.db")
    M.JOBS_DIR        = str(tmp_path / "jobs")
    M.SCREENSHOTS_DIR = str(tmp_path / "screenshots")
    M.BACKUP_DIR      = str(tmp_path / "backups")
    M.TEMP_DIR        = str(tmp_path / "tmp")
    # Force a new thread-local connection
    M._db_local.conn = None
    M._cfg_cache.clear()
    M._rate_delay = 0.0
    M.init_db()
    # These tests exercise job scheduling / pipeline mechanics, not scope. Opt
    # into unscoped submission so the fail-closed Scope Guard doesn't reject the
    # throwaway targets they enqueue. (allow_unscoped only applies when no active
    # program is set; a test that configures one still gets full enforcement.)
    M.set_config("allow_unscoped", True)
    yield
    # Teardown: close connection
    try:
        if hasattr(M._db_local, "conn") and M._db_local.conn:
            M._db_local.conn.close()
            M._db_local.conn = None
    except Exception:
        pass


@pytest.fixture
def admin(isolated_db):
    """Create an admin user, return (uid, token)."""
    uid   = M.create_user("admin", "password123", "admin")
    token = M.create_session(uid, "admin", "admin")
    return uid, token


@pytest.fixture
def regular_user(isolated_db):
    """Create a regular user, return (uid, token)."""
    uid   = M.create_user("scanner", "pass456", "user")
    token = M.create_session(uid, "scanner", "user")
    return uid, token


def make_handler(method, path, body=None, token=None, session=None):
    """Build a minimal mock request handler for API tests."""
    h = MagicMock(spec=M.ReconHandler)
    h.path = path
    h.headers = {}
    if token:
        h.headers["Cookie"] = f"session={token}"
    if body is not None:
        enc = json.dumps(body).encode()
        h.headers["Content-Length"] = str(len(enc))
        h.rfile = io.BytesIO(enc)
    else:
        h.headers["Content-Length"] = "0"
        h.rfile = io.BytesIO(b"")
    h.wfile = io.BytesIO()
    # Capture _json calls so we can inspect responses
    responses = []
    def capture_json(obj, status=200):
        responses.append((status, obj))
    h._json = capture_json
    h._ok   = lambda data=None, msg="OK": capture_json({"success": True, "message": msg, "data": data})
    h._err  = lambda msg, status=400: capture_json({"success": False, "message": msg}, status)
    h._responses = responses
    return h


# ═══════════════════════════════════════════════════════════
#  AUTHENTICATION
# ═══════════════════════════════════════════════════════════
class TestAuthentication:

    def test_hash_password_is_deterministic(self):
        ph, salt = M.hash_password("secret", "fixedsalt")
        ph2, _   = M.hash_password("secret", "fixedsalt")
        assert ph == ph2

    def test_hash_different_passwords(self):
        ph1, s1 = M.hash_password("abc")
        ph2, s2 = M.hash_password("def")
        assert ph1 != ph2

    def test_verify_correct_password(self):
        ph, salt = M.hash_password("mypassword")
        assert M.verify_password("mypassword", ph, salt)

    def test_verify_wrong_password(self):
        ph, salt = M.hash_password("correct")
        assert not M.verify_password("wrong", ph, salt)

    def test_create_session_and_retrieve(self, isolated_db):
        uid   = M.create_user("u1", "p1", "user")
        token = M.create_session(uid, "u1", "user")
        sess  = M.get_session(token)
        assert sess is not None
        assert sess["username"] == "u1"
        assert sess["role"]     == "user"

    def test_delete_session(self, isolated_db):
        uid   = M.create_user("u2", "p2", "user")
        token = M.create_session(uid, "u2", "user")
        M.delete_session(token)
        assert M.get_session(token) is None

    def test_invalid_token_returns_none(self, isolated_db):
        assert M.get_session("not_a_real_token") is None

    def test_ensure_admin_creates_once(self, isolated_db):
        pw = M.ensure_admin()
        assert pw is not None  # created
        pw2 = M.ensure_admin()
        assert pw2 is None     # already exists

    def test_admin_role_stored(self, isolated_db):
        M.ensure_admin()
        row = M.db_row("SELECT role FROM users WHERE username='admin'")
        assert row["role"] == "admin"


# ═══════════════════════════════════════════════════════════
#  DATABASE  (config, history, CRUD helpers)
# ═══════════════════════════════════════════════════════════
class TestDatabase:

    def test_config_round_trip(self, isolated_db):
        M.set_config("my_key", {"nested": [1, 2, 3]})
        val = M.get_config("my_key")
        assert val == {"nested": [1, 2, 3]}

    def test_config_default(self, isolated_db):
        val = M.get_config("nonexistent_key", "default_value")
        assert val == "default_value"

    def test_config_overwrite(self, isolated_db):
        M.set_config("k", 1)
        M.set_config("k", 2)
        assert M.get_config("k") == 2

    def test_config_cache_invalidated(self, isolated_db):
        M.set_config("cached_k", "first")
        # Manually clear cache to force DB read
        M._cfg_cache.clear()
        assert M.get_config("cached_k") == "first"

    def test_add_history(self, isolated_db):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("x.com",))
        M.add_history("x.com", "test_src", "test_event")
        rows = M.db_rows("SELECT * FROM history WHERE domain='x.com'")
        assert len(rows) == 1
        assert rows[0]["source"] == "test_src"
        assert rows[0]["text"]   == "test_event"

    def test_row_to_dict(self, isolated_db):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("y.com",))
        row = M.db_row("SELECT * FROM targets WHERE domain='y.com'")
        d   = M.row_to_dict(row)
        assert isinstance(d, dict)
        assert d["domain"] == "y.com"

    def test_row_to_dict_none(self, isolated_db):
        assert M.row_to_dict(None) is None

    def test_subdomains_unique_constraint(self, isolated_db):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("z.com",))
        M.db_exec("INSERT OR IGNORE INTO subdomains(domain,subdomain) VALUES (?,?)", ("z.com","api.z.com"))
        M.db_exec("INSERT OR IGNORE INTO subdomains(domain,subdomain) VALUES (?,?)", ("z.com","api.z.com"))
        rows = M.db_rows("SELECT * FROM subdomains WHERE domain='z.com'")
        assert len(rows) == 1

    def test_wal_mode(self, isolated_db):
        row = M.db_row("PRAGMA journal_mode")
        assert row[0] == "wal"


# ═══════════════════════════════════════════════════════════
#  WILDCARD EXPANSION
# ═══════════════════════════════════════════════════════════
class TestWildcardExpansion:

    def test_exact_domain(self, isolated_db):
        result = M.expand_domain("example.com")
        assert result == ["example.com"]

    def test_wildcard_star_tld(self, isolated_db):
        M.set_config("tld_list", ["com", "io", "net"])
        result = M.expand_domain("acme.*")
        assert result == ["acme.com", "acme.io", "acme.net"]

    def test_wildcard_subdomain(self, isolated_db):
        result = M.expand_domain("*.example.com")
        assert result == ["example.com"]

    def test_wildcard_uses_configured_tlds(self, isolated_db):
        M.set_config("tld_list", ["xyz", "io"])
        result = M.expand_domain("corp.*")
        assert "corp.xyz" in result
        assert "corp.io"  in result
        assert len(result) == 2

    def test_no_expansion_for_plain_domain(self, isolated_db):
        result = M.expand_domain("sub.domain.co.uk")
        assert result == ["sub.domain.co.uk"]


# ═══════════════════════════════════════════════════════════
#  TOOL GATE  (concurrency limiter)
# ═══════════════════════════════════════════════════════════
class TestToolGate:

    def test_acquire_release(self):
        gate = M.ToolGate("test_gate", max_concurrent=3)
        gate.acquire()
        assert gate.running == 1
        gate.release()
        assert gate.running == 0

    def test_max_concurrent_blocks(self):
        gate = M.ToolGate("block_gate", max_concurrent=1)
        gate.acquire()
        acquired = threading.Event()

        def try_acquire():
            gate.acquire()
            acquired.set()
            gate.release()

        t = threading.Thread(target=try_acquire)
        t.start()
        time.sleep(0.1)
        assert not acquired.is_set()  # blocked
        gate.release()
        t.join(timeout=2)
        assert acquired.is_set()  # unblocked

    def test_waiting_counter(self):
        gate = M.ToolGate("wait_gate", max_concurrent=1)
        gate.acquire()
        # waiting thread
        done = threading.Event()
        def waiter():
            gate.acquire()
            gate.release()
            done.set()
        t = threading.Thread(target=waiter)
        t.start()
        time.sleep(0.05)
        assert gate.waiting == 1
        gate.release()
        t.join(timeout=2)
        assert gate.waiting == 0

    def test_status_dict(self):
        gate = M.ToolGate("status_gate", max_concurrent=5)
        gate.acquire()
        s = gate.status()
        assert s["name"]    == "status_gate"
        assert s["running"] == 1
        assert s["max"]     == 5
        gate.release()

    def test_context_manager(self):
        gate = M.ToolGate("ctx_gate", max_concurrent=2)
        with gate:
            assert gate.running == 1
        assert gate.running == 0

    def test_init_tool_gates(self, isolated_db):
        M._tool_gates.clear()
        M.init_tool_gates()
        assert "amass"  in M._tool_gates
        assert "nuclei" in M._tool_gates
        assert "nikto"  in M._tool_gates
        assert len(M._tool_gates) == len(M._DEFAULT_TOOLS)


# ═══════════════════════════════════════════════════════════
#  JOB SCHEDULING
# ═══════════════════════════════════════════════════════════
class TestJobScheduling:

    def test_submit_single_domain(self, isolated_db):
        M.init_tool_gates()
        jobs = M.submit_domain("example.com", "admin")
        assert len(jobs) == 1
        assert jobs[0].domain   == "example.com"
        assert jobs[0].status   == "pending"
        assert jobs[0].username == "admin"

    def test_submit_wildcard_expands(self, isolated_db):
        M.init_tool_gates()
        M.set_config("tld_list", ["com", "net", "io"])
        jobs = M.submit_domain("acme.*", "admin")
        assert len(jobs) == 3
        domains = {j.domain for j in jobs}
        assert "acme.com" in domains
        assert "acme.net" in domains
        assert "acme.io"  in domains

    def test_submit_adds_to_queue(self, isolated_db):
        M.init_tool_gates()
        before = M._pending.qsize()
        M.submit_domain("queue-test.com", "admin")
        assert M._pending.qsize() == before + 1

    def test_submit_registers_in_jobs_dict(self, isolated_db):
        M.init_tool_gates()
        jobs = M.submit_domain("jobs-dict.com", "admin")
        with M._lock:
            assert jobs[0].id in M._jobs

    def test_job_pause_resume(self, isolated_db):
        M.init_tool_gates()
        jobs = M.submit_domain("pause.io", "user")
        job  = jobs[0]
        job.pause_event.set()
        assert job.pause_event.is_set()
        job.pause_event.clear()
        assert not job.pause_event.is_set()

    def test_job_cancel_event(self, isolated_db):
        M.init_tool_gates()
        jobs = M.submit_domain("cancel.io", "user")
        job  = jobs[0]
        job.cancel_event.set()
        assert job.cancel_event.is_set()

    def test_job_add_subs_signals_event(self, isolated_db):
        M.init_tool_gates()
        jobs = M.submit_domain("subs.com", "user")
        job  = jobs[0]
        assert not job.first_sub_event.is_set()
        job.add_subs({"api.subs.com"})
        assert job.first_sub_event.is_set()

    def test_job_add_subs_filters_by_domain(self, isolated_db):
        M.init_tool_gates()
        jobs = M.submit_domain("filtered.com", "user")
        job  = jobs[0]
        job.add_subs({"api.filtered.com", "evil.other.com", "sub.filtered.com"})
        subs = job.get_subs()
        assert "api.filtered.com" in subs
        assert "sub.filtered.com" in subs
        assert "evil.other.com"   not in subs

    def test_job_skip_step(self, isolated_db):
        M.init_tool_gates()
        jobs = M.submit_domain("skip.com", "user")
        job  = jobs[0]
        job.current_step = "dnsx"
        job.skip("dnsx")
        assert job.should_skip("dnsx")
        assert not job.should_skip("httpx")

    def test_job_to_dict(self, isolated_db):
        M.init_tool_gates()
        jobs = M.submit_domain("dict.com", "user")
        d    = jobs[0].to_dict()
        assert d["domain"]   == "dict.com"
        assert d["username"] == "user"
        assert d["status"]   == "pending"
        assert "logs"        in d

    def test_job_logging(self, isolated_db):
        M.init_tool_gates()
        jobs = M.submit_domain("log.com", "user")
        job  = jobs[0]
        job.log("test message", "test_src")
        logs = job.get_logs()
        assert any("test message" in l for l in logs)

    def test_running_count(self, isolated_db):
        M.init_tool_gates()
        # Clear existing jobs
        with M._lock:
            M._jobs.clear()
        jobs = M.submit_domain("count.com", "user")
        job  = jobs[0]
        job.status = "running"
        assert M._running_count() == 1
        job.status = "completed"
        assert M._running_count() == 0


# ═══════════════════════════════════════════════════════════
#  SUBDOMAIN FILTERING
# ═══════════════════════════════════════════════════════════
class TestSubdomainFiltering:

    def _seed(self, domain="example.com"):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", (domain,))
        data = [
            (domain, "api.example.com",    200, "API",   0),
            (domain, "admin.example.com",  403, "Admin", 1),
            (domain, "old.example.com",    404, None,    0),
            (domain, "dev.example.com",    200, "Dev",   1),
        ]
        for (dm, sub, status, title, interesting) in data:
            M.db_exec(
                "INSERT OR IGNORE INTO subdomains(domain,subdomain,http_status,http_title,interesting) "
                "VALUES (?,?,?,?,?)",
                (dm, sub, status, title, interesting)
            )

    def test_filter_by_status(self, isolated_db):
        self._seed()
        rows = M.db_rows(
            "SELECT * FROM subdomains WHERE domain='example.com' AND http_status=200")
        assert len(rows) == 2
        hosts = {r["subdomain"] for r in rows}
        assert "api.example.com" in hosts
        assert "dev.example.com" in hosts

    def test_filter_interesting(self, isolated_db):
        self._seed()
        rows = M.db_rows(
            "SELECT * FROM subdomains WHERE domain='example.com' AND interesting=1")
        assert len(rows) == 2

    def test_filter_not_found(self, isolated_db):
        self._seed()
        rows = M.db_rows(
            "SELECT * FROM subdomains WHERE domain='example.com' AND http_status=500")
        assert len(rows) == 0

    def test_filter_by_title(self, isolated_db):
        self._seed()
        rows = M.db_rows(
            "SELECT * FROM subdomains WHERE domain='example.com' AND http_title='API'")
        assert len(rows) == 1
        assert rows[0]["subdomain"] == "api.example.com"

    def test_nuclei_findings_stored(self, isolated_db):
        self._seed()
        findings = json.dumps([
            {"template": "cve-2021-xxx", "severity": "critical", "name": "RCE"}
        ])
        M.db_exec(
            "UPDATE subdomains SET nuclei_findings=?, interesting=1 "
            "WHERE domain='example.com' AND subdomain='admin.example.com'",
            (findings,)
        )
        row = M.db_row(
            "SELECT nuclei_findings FROM subdomains "
            "WHERE domain='example.com' AND subdomain='admin.example.com'")
        parsed = json.loads(row["nuclei_findings"])
        assert parsed[0]["severity"] == "critical"


# ═══════════════════════════════════════════════════════════
#  BACKUP / RESTORE
# ═══════════════════════════════════════════════════════════
class TestBackup:

    def test_create_backup_file_exists(self, isolated_db):
        name = M.create_backup("pytest")
        assert name.endswith(".tar.gz")
        assert os.path.exists(os.path.join(M.BACKUP_DIR, name))

    def test_create_backup_is_valid_tar(self, isolated_db):
        import tarfile
        name = M.create_backup("valid")
        path = os.path.join(M.BACKUP_DIR, name)
        assert tarfile.is_tarfile(path)

    def test_backup_contains_db(self, isolated_db):
        import tarfile
        name = M.create_backup("db_check")
        path = os.path.join(M.BACKUP_DIR, name)
        with tarfile.open(path) as t:
            names = t.getnames()
        assert "recon.db" in names

    def test_list_backups(self, isolated_db):
        M.create_backup("list1")
        M.create_backup("list2")
        backups = M.list_backups()
        assert len(backups) >= 2
        assert all("name" in b and "size" in b for b in backups)

    def test_restore_fails_if_jobs_running(self, isolated_db):
        name = M.create_backup("restore_test")
        # Inject a fake running job
        job = M.Job("running.com", "admin")
        job.status = "running"
        with M._lock:
            M._jobs[job.id] = job
        with pytest.raises(RuntimeError, match="running"):
            M.restore_backup(name)
        with M._lock:
            M._jobs.pop(job.id, None)

    def test_restore_nonexistent_raises(self, isolated_db):
        with pytest.raises(FileNotFoundError):
            M.restore_backup("does_not_exist.tar.gz")

    def test_prune_keeps_max_backups(self, isolated_db):
        for i in range(15):
            M.create_backup(f"prune_{i:02d}")
        backups = M.list_backups()
        assert len(backups) <= M.MAX_BACKUPS


# ═══════════════════════════════════════════════════════════
#  RATE LIMITING
# ═══════════════════════════════════════════════════════════
class TestRateLimit:

    def test_handle_rate_limit_increases_delay(self, isolated_db):
        M._rate_delay = 0.0
        M._handle_rate_limit()
        assert M._rate_delay == M.RATE_INCREMENT

    def test_handle_rate_limit_respects_max(self, isolated_db):
        M._rate_delay = M.MAX_RATE_DELAY
        M._handle_rate_limit()
        assert M._rate_delay <= M.MAX_RATE_DELAY

    def test_reset_rate_limit(self, isolated_db):
        M._rate_delay = 15.0
        M._reset_rate_limit()
        assert M._rate_delay == 0.0

    def test_multiple_rate_limit_calls(self, isolated_db):
        M._rate_delay = 0.0
        for _ in range(10):
            M._handle_rate_limit()
        assert M._rate_delay == M.MAX_RATE_DELAY


# ═══════════════════════════════════════════════════════════
#  API ENDPOINTS  (unit-level, no real HTTP)
# ═══════════════════════════════════════════════════════════
class TestAPIEndpoints:

    def test_login_valid(self, isolated_db):
        M.create_user("testlogin", "testpass", "user")
        row = M.db_row("SELECT * FROM users WHERE username='testlogin'")
        assert row is not None
        assert M.verify_password("testpass", row["password_hash"], row["salt"])

    def test_login_wrong_password(self, isolated_db):
        M.create_user("wrongpw", "correct", "user")
        row = M.db_row("SELECT * FROM users WHERE username='wrongpw'")
        assert not M.verify_password("incorrect", row["password_hash"], row["salt"])

    def test_api_state_structure(self, isolated_db, admin):
        uid, token = admin
        # Manually call _api_state equivalent by checking DB
        stats = {
            "total_domains":    M.db_row("SELECT COUNT(*) as c FROM targets")["c"],
            "total_subdomains": M.db_row("SELECT COUNT(*) as c FROM subdomains")["c"],
        }
        assert stats["total_domains"]    == 0
        assert stats["total_subdomains"] == 0

    def test_submit_domain_api_logic(self, isolated_db, admin):
        M.init_tool_gates()
        uid, token = admin
        sess = {"username": "admin", "role": "admin", "user_id": uid}
        jobs = M.submit_domain("api-test.com", sess["username"])
        assert len(jobs) == 1

    def test_targets_list_after_scan(self, isolated_db):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("listed.com",))
        rows = M.db_rows("SELECT * FROM targets")
        assert any(r["domain"] == "listed.com" for r in rows)

    def test_subdomains_api_logic(self, isolated_db):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("sub-api.com",))
        M.db_exec("INSERT OR IGNORE INTO subdomains(domain,subdomain,http_status) VALUES (?,?,?)",
                  ("sub-api.com", "mail.sub-api.com", 200))
        rows = M.db_rows(
            "SELECT * FROM subdomains WHERE domain='sub-api.com' AND http_status=200")
        assert len(rows) == 1

    def test_config_set_get_via_api(self, isolated_db):
        M.set_config("max_running_jobs", 8)
        M._cfg_cache.clear()
        assert M.get_config("max_running_jobs") == 8

    def test_history_recorded_on_submit(self, isolated_db):
        M.init_tool_gates()
        M.submit_domain("history-test.com", "admin")
        rows = M.db_rows(
            "SELECT * FROM history WHERE domain='history-test.com'")
        assert len(rows) >= 1

    def test_create_and_list_monitors(self, isolated_db):
        M.db_exec("INSERT INTO monitors(name,url,enabled) VALUES (?,?,1)",
                  ("My Feed", "https://example.com/feed.txt"))
        rows = M.db_rows("SELECT * FROM monitors")
        assert len(rows) == 1
        assert rows[0]["name"] == "My Feed"

    def test_delete_monitor(self, isolated_db):
        c = M.db_exec("INSERT INTO monitors(name,url,enabled) VALUES (?,?,1)",
                      ("Del Feed", "http://x.com/f.txt"))
        mid = c.lastrowid
        M.db_exec("DELETE FROM monitors WHERE id=?", (mid,))
        assert M.db_row("SELECT * FROM monitors WHERE id=?", (mid,)) is None

    def test_users_create_and_delete(self, isolated_db):
        uid = M.create_user("newuser", "newpass", "user")
        row = M.db_row("SELECT * FROM users WHERE id=?", (uid,))
        assert row["username"] == "newuser"
        M.db_exec("DELETE FROM users WHERE id=?", (uid,))
        assert M.db_row("SELECT * FROM users WHERE id=?", (uid,)) is None


# ═══════════════════════════════════════════════════════════
#  BUILD COMMAND TEMPLATE
# ═══════════════════════════════════════════════════════════
class TestBuildCmd:

    def test_basic_substitution(self):
        cmd = M.build_cmd("amass enum -d $DOMAIN$ -o $OUTPUT$",
                          {"$DOMAIN$": "example.com", "$OUTPUT$": "/tmp/out.txt"})
        assert cmd == ["amass", "enum", "-d", "example.com", "-o", "/tmp/out.txt"]

    def test_partial_substitution(self):
        cmd = M.build_cmd("tool -d $DOMAIN$ -t $THREADS$",
                          {"$DOMAIN$": "x.com", "$THREADS$": "50"})
        assert "$DOMAIN$"  not in " ".join(cmd)
        assert "$THREADS$" not in " ".join(cmd)

    def test_no_substitution(self):
        cmd = M.build_cmd("echo hello world", {})
        assert cmd == ["echo", "hello", "world"]


# ═══════════════════════════════════════════════════════════
#  TOOL AVAILABILITY
# ═══════════════════════════════════════════════════════════
class TestToolAvailability:

    def test_crtsh_always_available(self, isolated_db):
        assert M.is_tool_available("crtsh")

    def test_missing_binary_not_available(self, isolated_db):
        with patch("shutil.which", return_value=None):
            assert not M.is_tool_available("amass")

    def test_present_binary_available(self, isolated_db):
        with patch("shutil.which", return_value="/usr/bin/amass"):
            assert M.is_tool_available("amass")

    def test_tool_with_empty_cmd_not_available(self, isolated_db):
        tools = M.get_tools_config()
        empty_cmd_tools = [k for k, v in tools.items() if not v.get("cmd") and v.get("parse_mode") != "api"]
        for k in empty_cmd_tools:
            assert not M.is_tool_available(k)


# ═══════════════════════════════════════════════════════════
#  PIPELINE STEP TRACKING
# ═══════════════════════════════════════════════════════════
class TestPipelineStepTracking:

    def test_mark_and_check_step(self, isolated_db):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("steps.com",))
        M.init_tool_gates()
        jobs = M.submit_domain("steps.com", "user")
        job  = jobs[0]
        job.mark_step("amass")
        assert job.is_done("amass")
        assert not job.is_done("subfinder")

    def test_completed_steps_persist(self, isolated_db):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("persist.com",))
        M.init_tool_gates()
        jobs = M.submit_domain("persist.com", "user")
        job  = jobs[0]
        job.mark_step("dnsx")
        # Read from DB directly
        row = M.db_row(
            "SELECT completed_steps FROM targets WHERE domain='persist.com'")
        cs = json.loads(row["completed_steps"])
        assert "dnsx" in cs

    def test_flush_subs_to_db(self, isolated_db):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("flush.com",))
        M.init_tool_gates()
        jobs = M.submit_domain("flush.com", "user")
        job  = jobs[0]
        job.add_subs({"api.flush.com", "mail.flush.com"})
        added = M._flush_subs_to_db(job)
        assert added == 2
        rows = M.db_rows("SELECT * FROM subdomains WHERE domain='flush.com'")
        assert len(rows) == 2

    def test_write_sub_list(self, isolated_db, tmp_path):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("write.com",))
        M.init_tool_gates()
        jobs = M.submit_domain("write.com", "user")
        job  = jobs[0]
        job.add_subs({"api.write.com", "www.write.com"})
        out = str(tmp_path / "subs.txt")
        n = M._write_sub_list(job, out)
        assert n == 2
        with open(out) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert "api.write.com" in lines
        assert "www.write.com" in lines

    def test_get_job_dir_creates_directory(self, isolated_db, tmp_path):
        jd = M.get_job_dir("testdir.com")
        assert os.path.isdir(jd)


# ═══════════════════════════════════════════════════════════
#  MISC / REGRESSION
# ═══════════════════════════════════════════════════════════
class TestMisc:

    def test_rows_to_list(self, isolated_db):
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("rl1.com",))
        M.db_exec("INSERT OR IGNORE INTO targets(domain) VALUES (?)", ("rl2.com",))
        rows = M.db_rows("SELECT domain FROM targets ORDER BY domain")
        lst  = M.rows_to_list(rows)
        assert isinstance(lst, list)
        assert all(isinstance(d, dict) for d in lst)
        domains = [d["domain"] for d in lst]
        assert "rl1.com" in domains
        assert "rl2.com" in domains

    def test_emit_writes_to_log_buffer(self, isolated_db):
        before = len(M._log_buf)
        M.emit("unit test log entry", "INFO", "pytest")
        assert len(M._log_buf) == before + 1
        last = list(M._log_buf)[-1]
        assert last["msg"] == "unit test log entry"
        assert last["src"] == "pytest"

    def test_gallery_html_template(self):
        html = M.GALLERY_HTML.replace("__DOMAIN__", "test.com").replace("__PAGE__", "1")
        assert "test.com" in html
        assert "__DOMAIN__" not in html
        assert "__PAGE__"   not in html

    def test_frontend_html_has_required_sections(self):
        assert "ReconForge"       in M.FRONTEND_HTML
        assert "login"            in M.FRONTEND_HTML.lower()
        assert "api/state"        in M.FRONTEND_HTML
        assert "renderOverview"   in M.FRONTEND_HTML
        assert "renderJobs"       in M.FRONTEND_HTML
        assert "renderReports"    in M.FRONTEND_HTML
        assert "drawSparkline"    in M.FRONTEND_HTML
        assert "NodeGraph"        in M.FRONTEND_HTML

    def test_default_tools_count(self):
        # Lower-bound check so adding tools in Phase C batches doesn't
        # require touching this assertion. 16 is the Phase B baseline
        # (original 14 + ffuf + nmap stayed when enabled flags flipped).
        assert len(M._DEFAULT_TOOLS) >= 16

    def test_pipeline_steps_list(self):
        assert "amass"    in M._PIPELINE_STEPS
        assert "dnsx"     in M._PIPELINE_STEPS
        assert "httpx"    in M._PIPELINE_STEPS
        assert "nuclei"   in M._PIPELINE_STEPS
        assert "nikto"    in M._PIPELINE_STEPS
        assert "gowitness" in M._PIPELINE_STEPS
