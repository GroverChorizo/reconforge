"""Phase 16 — scope_status derivation + blocked_targets endpoint.

The SPA components (<scope-badge>, pre-flight modal) are exercised manually
in the Scope workbench view; this test file covers the backend they consume.

Covers:
  * scope_check returns scope_status ∈ {in, blocked, ambiguous, unknown}
    for every decision path of scope_guard.check.
  * blocked_targets() reads agent_memory rows where scope_guard.last_check
    has allowed=False, ordered by recency, with the 4-status enum attached.
  * GET /api/v2/programs/{slug}/blocked_targets dispatches cleanly with
    optional ?limit= query.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core import programs as P
from api import routes, server
from db.migrations import runner as MIG


# ── fixtures ──────────────────────────────────────────────────────
@pytest.fixture
def db(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    MIG.run_pending(conn)
    yield conn
    conn.close()


@pytest.fixture
def acme(db):
    return P.create_program(
        db,
        name="ACME Program",
        platform="intigriti",
        platform_handle="researcher",
        scope=[{"type": "wildcard", "value": "*.acme.com", "tier": 2}],
        out_of_scope=[{"type": "domain", "value": "careers.acme.com"}],
    )


def _seed_scope_check(db, job_id, check, ts_offset_seconds=0):
    """Insert an agent_memory row mimicking ScopeGuardAgent.remember()."""
    db.execute(
        "INSERT INTO agent_memory(job_id, agent, key, value_json, "
        "created_at, updated_at) "
        "VALUES (?, 'scope_guard', 'last_check', ?, "
        "datetime('now', ?), datetime('now', ?))",
        (job_id, json.dumps(check),
         f"{ts_offset_seconds} seconds", f"{ts_offset_seconds} seconds"),
    )
    db.commit()


# ── scope_status derivation ───────────────────────────────────────
class TestScopeStatusDerivation:

    def test_in_scope_wildcard(self, acme, db):
        r = P.scope_check(db, acme.slug, "api.acme.com")
        assert r["allowed"] is True
        assert r["scope_status"] == "in"

    def test_blocked_by_out_of_scope(self, acme, db):
        r = P.scope_check(db, acme.slug, "careers.acme.com")
        assert r["allowed"] is False
        assert r["scope_status"] == "blocked"

    def test_ambiguous_when_no_rule_matches(self, acme, db):
        r = P.scope_check(db, acme.slug, "unaffiliated.example.org")
        assert r["allowed"] is False
        assert r["scope_status"] == "ambiguous"

    def test_apex_of_wildcard_is_ambiguous_not_blocked(self, acme, db):
        # CLAUDE.md doctrine: *.acme.com does NOT match acme.com itself,
        # AND no out_of_scope rule covers it → ambiguous, needs operator
        # review (could legitimately be in or out depending on program).
        r = P.scope_check(db, acme.slug, "acme.com")
        assert r["scope_status"] == "ambiguous"

    def test_unknown_program_is_unknown_status(self, db):
        r = P.scope_check(db, "no-such-program", "x.com")
        assert r["scope_status"] == "unknown"

    def test_empty_target_is_unknown_status(self, acme, db):
        r = P.scope_check(db, acme.slug, "")
        assert r["scope_status"] == "unknown"


# ── blocked_targets() ─────────────────────────────────────────────
class TestBlockedTargets:

    def test_empty(self, acme, db):
        out = P.blocked_targets(db)
        assert out == []

    def test_only_returns_rejections(self, acme, db):
        _seed_scope_check(db, "J1", {
            "allowed": True, "reason": "in_scope: wildcard=*.acme.com",
            "matched": {"type": "wildcard", "value": "*.acme.com"},
            "platform": "intigriti",
        })
        _seed_scope_check(db, "J2", {
            "allowed": False, "reason": "out_of_scope: domain=careers.acme.com",
            "matched": {"type": "domain", "value": "careers.acme.com"},
            "platform": "intigriti",
        })
        out = P.blocked_targets(db)
        assert len(out) == 1
        assert out[0]["job_id"] == "J2"
        assert out[0]["target"] == "careers.acme.com"
        assert out[0]["scope_status"] == "blocked"

    def test_orders_by_recency_desc(self, acme, db):
        _seed_scope_check(db, "old", {
            "allowed": False, "reason": "out_of_scope: domain=old.com",
            "matched": {"value": "old.com"},
        }, ts_offset_seconds=-3600)
        _seed_scope_check(db, "new", {
            "allowed": False, "reason": "out_of_scope: domain=new.com",
            "matched": {"value": "new.com"},
        }, ts_offset_seconds=0)
        out = P.blocked_targets(db)
        assert [b["job_id"] for b in out] == ["new", "old"]

    def test_limit_param(self, acme, db):
        for i in range(5):
            _seed_scope_check(db, f"J{i}", {
                "allowed": False, "reason": "out_of_scope: domain=x.com",
                "matched": {"value": f"x{i}.com"},
            }, ts_offset_seconds=-i)
        out = P.blocked_targets(db, limit=2)
        assert len(out) == 2

    def test_skips_malformed_rows(self, acme, db):
        db.execute(
            "INSERT INTO agent_memory(job_id, agent, key, value_json) "
            "VALUES ('bad', 'scope_guard', 'last_check', 'not json{')"
        )
        _seed_scope_check(db, "ok", {
            "allowed": False, "reason": "out_of_scope: domain=careers.acme.com",
            "matched": {"value": "careers.acme.com"},
        })
        db.commit()
        out = P.blocked_targets(db)
        assert len(out) == 1
        assert out[0]["job_id"] == "ok"

    def test_attaches_scope_status(self, acme, db):
        _seed_scope_check(db, "amb", {
            "allowed": False, "reason": "no in_scope rule matched",
            "matched": None,
        })
        _seed_scope_check(db, "blk", {
            "allowed": False, "reason": "out_of_scope: domain=careers.acme.com",
            "matched": {"value": "careers.acme.com"},
        })
        out = P.blocked_targets(db)
        statuses = {b["job_id"]: b["scope_status"] for b in out}
        assert statuses == {"amb": "ambiguous", "blk": "blocked"}


# ── api.routes wrapper ───────────────────────────────────────────
class TestRoute:

    def test_program_blocked_targets_route(self, acme, db):
        _seed_scope_check(db, "J9", {
            "allowed": False, "reason": "out_of_scope: domain=careers.acme.com",
            "matched": {"value": "careers.acme.com"},
        })
        out = routes.program_blocked_targets(db, acme.slug)
        assert out["count"] == 1
        assert out["blocked"][0]["target"] == "careers.acme.com"


# ── dispatcher ───────────────────────────────────────────────────
class TestPhase16Dispatch:

    def test_blocked_targets_route(self, acme, db):
        _seed_scope_check(db, "J1", {
            "allowed": False, "reason": "out_of_scope: domain=careers.acme.com",
            "matched": {"value": "careers.acme.com"},
        })
        status, body = server.dispatch(
            "GET", f"/api/v2/programs/{acme.slug}/blocked_targets", {}, None, db,
        )
        assert status == 200
        assert body["count"] == 1

    def test_blocked_targets_limit_qs(self, acme, db):
        for i in range(5):
            _seed_scope_check(db, f"J{i}", {
                "allowed": False, "reason": "out_of_scope: domain=x",
                "matched": {"value": f"x{i}.com"},
            }, ts_offset_seconds=-i)
        status, body = server.dispatch(
            "GET", f"/api/v2/programs/{acme.slug}/blocked_targets",
            {"limit": ["2"]}, None, db,
        )
        assert status == 200
        assert body["count"] == 2

    def test_blocked_targets_clamped_limit(self, acme, db):
        # Limit > 200 is clamped to 200 server-side. Empty data → still 200.
        status, body = server.dispatch(
            "GET", f"/api/v2/programs/{acme.slug}/blocked_targets",
            {"limit": ["999"]}, None, db,
        )
        assert status == 200
        assert body["count"] == 0

    def test_scope_check_route_includes_status(self, acme, db):
        status, body = server.dispatch(
            "POST", f"/api/v2/programs/{acme.slug}/scope_check", {},
            {"target": "api.acme.com"}, db,
        )
        assert status == 200
        assert body["scope_status"] == "in"

    def test_scope_check_blocked_status(self, acme, db):
        status, body = server.dispatch(
            "POST", f"/api/v2/programs/{acme.slug}/scope_check", {},
            {"target": "careers.acme.com"}, db,
        )
        assert status == 200
        assert body["scope_status"] == "blocked"
