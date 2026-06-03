"""OPSEC enforcement tests — the per-tool flag builder, auto program-identity
headers, the proxy env, and the agent-runner proxy bridge. OPSEC is rule #1:
these guard that every target-touching tool the app runs is throttled,
attributable, and proxy-routable.

Run: pytest tests/test_opsec.py -v
"""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import main as M  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    M.DATA_DIR = str(tmp_path)
    M.DB_PATH = str(tmp_path / "recon.db")
    M.JOBS_DIR = str(tmp_path / "jobs")
    M.SCREENSHOTS_DIR = str(tmp_path / "ss")
    M.BACKUP_DIR = str(tmp_path / "bk")
    M.TEMP_DIR = str(tmp_path / "tmp")
    M._db_local.conn = None
    M._cfg_cache.clear()
    M.init_db()
    yield
    try:
        if getattr(M._db_local, "conn", None):
            M._db_local.conn.close()
            M._db_local.conn = None
    except Exception:
        pass


def _job(monitor=False):
    return M.Job("x.com", "u", {"monitor": True} if monitor else {})


# ── per-tool flag builder ────────────────────────────────────────────
def test_httpx_stealth_defaults():
    f = M._opsec_flags("httpx", _job())
    assert "-random-agent" in f
    assert "-rl" in f and "50" in f            # stealth-by-default rate
    assert "-http-proxy" not in f              # no proxy configured


def test_httpx_monitor_adds_jitter():
    f = M._opsec_flags("httpx", _job(monitor=True))
    assert "-delay" in f and "200ms" in f


def test_nuclei_flags_with_proxy():
    M.set_config("opsec_http_proxy", "http://127.0.0.1:8080")
    f = M._opsec_flags("nuclei", _job())
    assert "-rl" in f
    assert "-proxy" in f and "http://127.0.0.1:8080" in f


def test_dnsx_rate_only():
    f = M._opsec_flags("dnsx", _job())
    assert f[:2] == ["-rl", "50"]
    assert "-H" not in f and "-proxy" not in f


def test_rate_limit_configurable():
    assert M._opsec_rate_limit() == 50
    M.set_config("opsec_rate_limit", 150)
    assert M._opsec_rate_limit() == 150


# ── auto program-identity headers ────────────────────────────────────
def test_program_headers_intigriti():
    M.set_config("platform_identities", {"intigriti": "grover"})
    with patch.object(M, "_active_program", return_value={"platform": "intigriti"}):
        assert "X-Intigriti-Username: grover" in M._program_headers()


def test_program_header_injected_into_httpx():
    M.set_config("platform_identities", {"intigriti": "grover"})
    with patch.object(M, "_active_program", return_value={"platform": "intigriti"}):
        f = M._opsec_flags("httpx", _job())
    i = f.index("-H")
    assert f[i + 1] == "X-Intigriti-Username: grover"


def test_hackerone_ua_suppresses_random_agent():
    M.set_config("platform_identities", {"hackerone": "grover"})
    with patch.object(M, "_active_program", return_value={"platform": "hackerone"}):
        f = M._opsec_flags("httpx", _job())
    assert "-random-agent" not in f            # UA is pinned, don't randomize
    assert any("User-Agent: grover-bb-research (hackerone.com/grover)" in x for x in f)


# ── proxy env ────────────────────────────────────────────────────────
def test_opsec_env_none_without_proxy():
    assert M._opsec_env() is None


def test_opsec_env_sets_proxy_vars():
    M.set_config("opsec_http_proxy", "socks5://127.0.0.1:9050")
    env = M._opsec_env()
    assert env["HTTP_PROXY"] == "socks5://127.0.0.1:9050"
    assert env["https_proxy"] == "socks5://127.0.0.1:9050"


def test_runner_proxy_bridge():
    from tools import runner
    runner.set_proxy("http://127.0.0.1:8080")
    try:
        env = runner._proxied_env(None)
        assert env["HTTP_PROXY"] == "http://127.0.0.1:8080"
        # an explicitly-passed env is never overridden
        assert runner._proxied_env({"A": "B"}) == {"A": "B"}
    finally:
        runner.set_proxy("")
