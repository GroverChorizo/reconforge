"""
Tests for scope_guard.py — pure-logic scope validation.

Per CLAUDE.md doctrine:
  - Wildcard scope (*.example.com) does NOT include example.com itself.
  - Out-of-scope entries ALWAYS win, even if matched by an in-scope rule.
  - Platform header injection is non-negotiable (X-Intigriti-Username: researcher etc.).
"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import scope_guard as SG
import main as M


# ═══════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════
@pytest.fixture
def basic_program():
    return {
        "name": "basic",
        "platform": "intigriti",
        "platform_handle": "researcher",
        "in_scope": [
            {"type": "domain",   "value": "example.com",     "tier": 1},
            {"type": "wildcard", "value": "*.example.com",   "tier": 2},
            {"type": "cidr",     "value": "203.0.113.0/24",  "tier": 3},
        ],
        "out_of_scope": [
            {"type": "domain",   "value": "careers.example.com"},
            {"type": "wildcard", "value": "*.dev.example.com"},
        ],
    }


@pytest.fixture
def mobile_program():
    return {
        "name": "mobile",
        "platform": "hackerone",
        "platform_handle": "researcher",
        "in_scope": [
            {"type": "mobile_ios",     "value": "com.example.app"},
            {"type": "mobile_android", "value": "com.example.app"},
            {"type": "source_code",    "value": "https://github.com/example"},
        ],
        "out_of_scope": [],
    }


@pytest.fixture
def ipv6_program():
    return {
        "name": "v6",
        "platform": "synack",
        "platform_handle": "researcher",
        "in_scope": [
            {"type": "cidr", "value": "2001:db8::/32"},
        ],
        "out_of_scope": [],
    }


# ═══════════════════════════════════════════════════════════
#  EXACT DOMAIN MATCHING
# ═══════════════════════════════════════════════════════════
class TestDomainMatching:

    def test_exact_apex_matches(self, basic_program):
        r = SG.check("example.com", basic_program)
        assert r["allowed"] is True
        assert r["tier"] == 1

    def test_case_insensitive(self, basic_program):
        r = SG.check("EXAMPLE.COM", basic_program)
        assert r["allowed"] is True

    def test_trailing_dot_normalized(self, basic_program):
        r = SG.check("example.com.", basic_program)
        assert r["allowed"] is True

    def test_unrelated_domain_rejected(self, basic_program):
        r = SG.check("evil.com", basic_program)
        assert r["allowed"] is False
        assert "no in_scope rule matched" in r["reason"]


# ═══════════════════════════════════════════════════════════
#  WILDCARD SEMANTICS (CLAUDE.md doctrine)
# ═══════════════════════════════════════════════════════════
class TestWildcardSemantics:

    def test_wildcard_matches_subdomain(self, basic_program):
        r = SG.check("api.example.com", basic_program)
        assert r["allowed"] is True
        assert r["tier"] == 2  # tier from wildcard, not apex

    def test_wildcard_matches_deep_subdomain(self, basic_program):
        r = SG.check("a.b.c.example.com", basic_program)
        assert r["allowed"] is True

    def test_wildcard_alone_excludes_apex(self):
        # apex NOT explicitly listed → wildcard rule alone must NOT match it
        prog = {
            "platform": "intigriti", "platform_handle": "researcher",
            "in_scope":    [{"type": "wildcard", "value": "*.solo.com"}],
            "out_of_scope": [],
        }
        r_apex = SG.check("solo.com", prog)
        r_sub  = SG.check("api.solo.com", prog)
        assert r_apex["allowed"] is False
        assert r_sub["allowed"]  is True

    def test_wildcard_does_not_match_sibling(self, basic_program):
        # *.example.com must not match "exampleXcom" or "notexample.com"
        assert SG.check("notexample.com", basic_program)["allowed"] is False


# ═══════════════════════════════════════════════════════════
#  OUT-OF-SCOPE PRECEDENCE
# ═══════════════════════════════════════════════════════════
class TestOutOfScopePrecedence:

    def test_explicit_oos_beats_wildcard_in_scope(self, basic_program):
        # careers.example.com IS matched by *.example.com BUT is OOS
        r = SG.check("careers.example.com", basic_program)
        assert r["allowed"] is False
        assert "out_of_scope" in r["reason"]

    def test_oos_wildcard_beats_in_scope_wildcard(self, basic_program):
        # api.dev.example.com matches *.example.com AND *.dev.example.com
        # OOS wildcard wins.
        r = SG.check("api.dev.example.com", basic_program)
        assert r["allowed"] is False

    def test_oos_apex_with_in_scope_wildcard(self):
        prog = {
            "platform": "intigriti", "platform_handle": "researcher",
            "in_scope":    [{"type": "wildcard", "value": "*.foo.com"}],
            "out_of_scope": [{"type": "domain",  "value": "blocked.foo.com"}],
        }
        assert SG.check("blocked.foo.com", prog)["allowed"] is False
        assert SG.check("allowed.foo.com", prog)["allowed"] is True


# ═══════════════════════════════════════════════════════════
#  CIDR MATCHING (v4 + v6)
# ═══════════════════════════════════════════════════════════
class TestCIDR:

    def test_ipv4_in_cidr(self, basic_program):
        r = SG.check("203.0.113.42", basic_program)
        assert r["allowed"] is True
        assert r["tier"] == 3

    def test_ipv4_outside_cidr(self, basic_program):
        r = SG.check("198.51.100.1", basic_program)
        assert r["allowed"] is False

    def test_ipv6_in_cidr(self, ipv6_program):
        r = SG.check("2001:db8::1", ipv6_program)
        assert r["allowed"] is True

    def test_ipv6_outside_cidr(self, ipv6_program):
        r = SG.check("2001:db9::1", ipv6_program)
        assert r["allowed"] is False

    def test_v4_against_v6_cidr_rejected(self, ipv6_program):
        r = SG.check("203.0.113.1", ipv6_program)
        assert r["allowed"] is False


# ═══════════════════════════════════════════════════════════
#  MOBILE BUNDLE IDS & SOURCE CODE
# ═══════════════════════════════════════════════════════════
class TestMobileAndRepo:

    def test_ios_bundle_match(self, mobile_program):
        r = SG.check("com.example.app", mobile_program)
        assert r["allowed"] is True

    def test_unrelated_bundle_rejected(self, mobile_program):
        r = SG.check("com.evil.app", mobile_program)
        assert r["allowed"] is False

    def test_repo_url_prefix_match(self, mobile_program):
        r = SG.check("https://github.com/example/api", mobile_program)
        assert r["allowed"] is True

    def test_repo_url_non_match(self, mobile_program):
        r = SG.check("https://github.com/attacker/payload", mobile_program)
        assert r["allowed"] is False


# ═══════════════════════════════════════════════════════════
#  URL NORMALIZATION
# ═══════════════════════════════════════════════════════════
class TestNormalization:

    def test_scheme_stripped(self, basic_program):
        assert SG.check("https://api.example.com", basic_program)["allowed"] is True

    def test_port_stripped(self, basic_program):
        assert SG.check("api.example.com:8080", basic_program)["allowed"] is True

    def test_url_with_path(self, basic_program):
        assert SG.check("https://api.example.com/v1/users", basic_program)["allowed"] is True

    def test_empty_target_rejected(self, basic_program):
        r = SG.check("", basic_program)
        assert r["allowed"] is False
        assert r["reason"] == "empty target"


# ═══════════════════════════════════════════════════════════
#  PLATFORM HEADER INJECTION
# ═══════════════════════════════════════════════════════════
class TestPlatformHeaders:

    def test_intigriti_header(self, basic_program):
        r = SG.check("example.com", basic_program)
        assert r["headers"].get("X-Intigriti-Username") == "researcher"

    def test_hackerone_user_agent(self, mobile_program):
        r = SG.check("com.example.app", mobile_program)
        ua = r["headers"].get("User-Agent", "")
        assert "researcher-bb-research" in ua
        assert "hackerone.com/researcher" in ua

    def test_bugcrowd_header(self):
        prog = {"platform": "bugcrowd", "platform_handle": "researcher",
                "in_scope": [{"type": "domain", "value": "bc.com"}], "out_of_scope": []}
        r = SG.check("bc.com", prog)
        assert r["headers"].get("X-Bugcrowd-Username") == "researcher"

    def test_yeswehack_header(self):
        prog = {"platform": "yeswehack", "platform_handle": "researcher",
                "in_scope": [{"type": "domain", "value": "y.com"}], "out_of_scope": []}
        r = SG.check("y.com", prog)
        assert r["headers"].get("X-YesWeHack-Username") == "researcher"

    def test_no_handle_no_headers(self):
        prog = {"platform": "intigriti", "in_scope": [{"type": "domain", "value": "x.com"}]}
        r = SG.check("x.com", prog)
        assert r["headers"] == {}


# ═══════════════════════════════════════════════════════════
#  RESULT SHAPE
# ═══════════════════════════════════════════════════════════
class TestResultShape:

    def test_allowed_has_all_keys(self, basic_program):
        r = SG.check("example.com", basic_program)
        for k in ("allowed", "reason", "tier", "platform", "headers", "matched"):
            assert k in r

    def test_rejected_tier_is_minus_one(self, basic_program):
        r = SG.check("evil.com", basic_program)
        assert r["tier"] == -1

    def test_matched_entry_returned_on_allow(self, basic_program):
        r = SG.check("api.example.com", basic_program)
        assert r["matched"] is not None
        assert r["matched"]["value"] == "*.example.com"


# ═══════════════════════════════════════════════════════════
#  PROGRAM LOADER + EXAMPLE FILES
# ═══════════════════════════════════════════════════════════
class TestExampleScopeFiles:

    def test_example_json_loads(self):
        path = Path(__file__).parent.parent / "scopes" / "example.json"
        prog = SG.load_program(path)
        assert prog["platform"] == "intigriti"

    def test_examplecorp_apex_allowed(self):
        prog = SG.load_program(Path(__file__).parent.parent / "scopes" / "examplecorp.json")
        assert SG.check("examplecorp.com", prog)["allowed"] is True

    def test_examplecorp_subdomain_allowed(self):
        prog = SG.load_program(Path(__file__).parent.parent / "scopes" / "examplecorp.json")
        assert SG.check("api.examplecorp.com", prog)["allowed"] is True

    def test_examplecorp_careers_blocked(self):
        prog = SG.load_program(Path(__file__).parent.parent / "scopes" / "examplecorp.json")
        r = SG.check("careers.examplecorp.com", prog)
        assert r["allowed"] is False
        assert "out_of_scope" in r["reason"]

    def test_examplecorp_view_e_blocked(self):
        prog = SG.load_program(Path(__file__).parent.parent / "scopes" / "examplecorp.json")
        assert SG.check("view.e.examplecorp.com", prog)["allowed"] is False


# ═══════════════════════════════════════════════════════════
#  MAIN.PY INTEGRATION
# ═══════════════════════════════════════════════════════════
@pytest.fixture(autouse=False)
def isolated_db(tmp_path):
    M.DATA_DIR        = str(tmp_path)
    M.DB_PATH         = str(tmp_path / "recon.db")
    M.JOBS_DIR        = str(tmp_path / "jobs")
    M.SCREENSHOTS_DIR = str(tmp_path / "screenshots")
    M.BACKUP_DIR      = str(tmp_path / "backups")
    M.TEMP_DIR        = str(tmp_path / "tmp")
    M._db_local.conn = None
    M._cfg_cache.clear()
    M._rate_delay = 0.0
    M.init_db()
    M.init_tool_gates()
    with M._lock:
        M._jobs.clear()
    yield
    try:
        if hasattr(M._db_local, "conn") and M._db_local.conn:
            M._db_local.conn.close()
            M._db_local.conn = None
    except Exception:
        pass


class TestSubmitDomainIntegration:

    def test_no_active_program_fails_closed(self, isolated_db):
        # doctrine: Scope Guard blocks any execution against an unauthorized
        # target. With no active program we REFUSE (fail-closed), not allow.
        jobs = M.submit_domain("anything.com", "admin")
        assert jobs == []

    def test_allow_unscoped_override_permits(self, isolated_db):
        # explicit, loudly-logged escape hatch for deliberate no-program runs
        M.set_config("allow_unscoped", True)
        jobs = M.submit_domain("anything.com", "admin")
        assert len(jobs) == 1

    def test_in_scope_domain_passes(self, isolated_db):
        M.set_config("active_program", "scopes/examplecorp.json")
        jobs = M.submit_domain("api.examplecorp.com", "admin")
        assert len(jobs) == 1
        assert jobs[0].domain == "api.examplecorp.com"

    def test_out_of_scope_domain_rejected_no_job(self, isolated_db):
        M.set_config("active_program", "scopes/examplecorp.json")
        jobs = M.submit_domain("careers.examplecorp.com", "admin")
        assert jobs == []

    def test_rejection_writes_history(self, isolated_db):
        M.set_config("active_program", "scopes/examplecorp.json")
        M.submit_domain("careers.examplecorp.com", "admin")
        rows = M.db_rows(
            "SELECT * FROM history WHERE domain='careers.examplecorp.com' AND source='scope_guard'"
        )
        assert len(rows) == 1
        assert "REJECTED" in rows[0]["text"]

    def test_unrelated_domain_rejected(self, isolated_db):
        M.set_config("active_program", "scopes/examplecorp.json")
        jobs = M.submit_domain("attacker.com", "admin")
        assert jobs == []
