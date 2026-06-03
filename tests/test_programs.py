"""Phase 13 — Programs CRUD + scope_check + v2 dispatch.

Covers:
  * Migration 005 applies cleanly + is idempotent.
  * core.programs CRUD (create with dup slug → unique suffix; reject bad platform).
  * scope_check delegates to scope_guard.check and returns program_slug.
  * api.server.dispatch routes for every Phase 13 endpoint.
  * Legacy /api/v2/<unknown> returns 404 with our shape.
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
        bounty_ranges={"critical": [2000, 5000]},
    )


# ── migration ─────────────────────────────────────────────────────
class TestMigration005:

    def test_programs_table_exists(self, db):
        rows = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='programs'"
        ).fetchall()
        assert len(rows) == 1

    def test_program_id_added_to_targets(self, db):
        cols = [r["name"] for r in db.execute("PRAGMA table_info(targets)").fetchall()]
        assert "program_id" in cols

    def test_program_id_added_to_completed_jobs(self, db):
        cols = [r["name"] for r in db.execute(
            "PRAGMA table_info(completed_jobs)"
        ).fetchall()]
        assert "program_id" in cols

    def test_re_run_is_idempotent(self, db):
        # ALTER TABLE ADD COLUMN is not idempotent in SQLite — migration 005
        # guards each ALTER with PRAGMA table_info check. Verify by running
        # up() a second time on a DB that already has it applied.
        import importlib
        mod = importlib.import_module("db.migrations.005_programs")
        mod.up(db)  # must not raise "duplicate column name"


# ── CRUD ──────────────────────────────────────────────────────────
class TestCRUD:

    def test_create_basic(self, db):
        p = P.create_program(db, name="Test", platform="hackerone")
        assert p.id > 0
        assert p.slug == "test"
        assert p.platform == "hackerone"

    def test_create_with_paste_scope(self, acme):
        assert acme.scope[0]["value"] == "*.acme.com"
        assert acme.out_of_scope[0]["value"] == "careers.acme.com"
        assert acme.bounty_ranges == {"critical": [2000, 5000]}

    def test_slug_uniqueness(self, db):
        a = P.create_program(db, name="Same Name", platform="other")
        b = P.create_program(db, name="Same Name", platform="other")
        assert a.slug != b.slug
        assert b.slug.startswith("same-name-")

    def test_reject_bad_platform(self, db):
        with pytest.raises(ValueError, match="platform"):
            P.create_program(db, name="x", platform="nopelang")

    def test_reject_empty_name(self, db):
        with pytest.raises(ValueError, match="name"):
            P.create_program(db, name="", platform="other")

    def test_list_orders_by_recent(self, db):
        P.create_program(db, name="First", platform="other")
        P.create_program(db, name="Second", platform="other")
        out = P.list_programs(db)
        assert out[0].name == "Second"

    def test_get_by_slug(self, acme, db):
        p = P.get_program(db, "acme-program")
        assert p is not None
        assert p.id == acme.id

    def test_get_by_id(self, acme, db):
        p = P.get_program(db, acme.id)
        assert p is not None
        assert p.slug == acme.slug

    def test_get_missing(self, db):
        assert P.get_program(db, "no-such") is None
        assert P.get_program(db, 99999) is None

    def test_delete(self, acme, db):
        assert P.delete_program(db, acme.slug) is True
        assert P.get_program(db, acme.slug) is None

    def test_delete_missing(self, db):
        assert P.delete_program(db, "ghost") is False


# ── scope_check ───────────────────────────────────────────────────
class TestScopeCheck:

    def test_in_scope_wildcard(self, acme, db):
        r = P.scope_check(db, acme.slug, "api.acme.com")
        assert r["allowed"] is True
        assert r["tier"] == 2
        assert r["program_slug"] == acme.slug

    def test_apex_not_covered_by_wildcard(self, acme, db):
        # CLAUDE.md doctrine: *.acme.com does NOT include acme.com itself.
        r = P.scope_check(db, acme.slug, "acme.com")
        assert r["allowed"] is False

    def test_out_of_scope_wins(self, acme, db):
        # careers.acme.com matches both *.acme.com (in) and the out_of_scope
        # entry. Exclusion wins.
        r = P.scope_check(db, acme.slug, "careers.acme.com")
        assert r["allowed"] is False
        assert "out_of_scope" in r["reason"]

    def test_no_match(self, acme, db):
        r = P.scope_check(db, acme.slug, "example.org")
        assert r["allowed"] is False
        assert "no in_scope rule matched" in r["reason"]

    def test_unknown_program(self, db):
        r = P.scope_check(db, "no-such-program", "x.com")
        assert r["allowed"] is False
        assert r["reason"] == "unknown program"

    def test_intigriti_header_attached(self, acme, db):
        r = P.scope_check(db, acme.slug, "api.acme.com")
        assert r["headers"].get("X-Intigriti-Username") == "researcher"


# ── v2 dispatch ───────────────────────────────────────────────────
class TestV2Dispatch:

    def test_list_empty(self, db):
        status, body = server.dispatch("GET", "/api/v2/programs", {}, None, db)
        assert status == 200
        assert body == {"programs": [], "count": 0}

    def test_create_then_list(self, db):
        status, body = server.dispatch(
            "POST", "/api/v2/programs", {},
            {"name": "Roundtrip", "platform": "bugcrowd",
             "scope": [{"type": "domain", "value": "rt.com"}]},
            db,
        )
        assert status == 201
        assert body["program"]["slug"] == "roundtrip"

        status, body = server.dispatch("GET", "/api/v2/programs", {}, None, db)
        assert status == 200
        assert body["count"] == 1

    def test_create_missing_fields(self, db):
        status, body = server.dispatch(
            "POST", "/api/v2/programs", {}, {"name": "x"}, db,
        )
        assert status == 400
        assert "required" in body["error"]

    def test_create_bad_platform(self, db):
        status, body = server.dispatch(
            "POST", "/api/v2/programs", {},
            {"name": "x", "platform": "evilplatform"}, db,
        )
        assert status == 400

    def test_detail(self, acme, db):
        status, body = server.dispatch(
            "GET", f"/api/v2/programs/{acme.slug}", {}, None, db,
        )
        assert status == 200
        assert body["program"]["name"] == acme.name

    def test_detail_404(self, db):
        status, body = server.dispatch(
            "GET", "/api/v2/programs/ghost", {}, None, db,
        )
        assert status == 404

    def test_scope_check_route(self, acme, db):
        status, body = server.dispatch(
            "POST", f"/api/v2/programs/{acme.slug}/scope_check", {},
            {"target": "x.acme.com"}, db,
        )
        assert status == 200
        assert body["allowed"] is True

    def test_scope_check_requires_target(self, acme, db):
        status, body = server.dispatch(
            "POST", f"/api/v2/programs/{acme.slug}/scope_check", {}, {}, db,
        )
        assert status == 400

    def test_delete_route(self, acme, db):
        status, body = server.dispatch(
            "DELETE", f"/api/v2/programs/{acme.slug}", {}, None, db,
        )
        assert status == 200
        assert body["deleted"] is True

    def test_unknown_route_404(self, db):
        status, body = server.dispatch("GET", "/api/v2/nope", {}, None, db)
        assert status == 404
        assert "not found" in body["error"]

    def test_method_mismatch_404(self, acme, db):
        # POST to a GET-only route returns 404 (not 405) — caller chose not
        # to special-case method-allowed for the v2 surface.
        status, _ = server.dispatch(
            "PUT", f"/api/v2/programs/{acme.slug}", {}, None, db,
        )
        assert status == 404


# ── back-compat ───────────────────────────────────────────────────
class TestLegacyApiUntouched:
    """Phase 13 must not break the existing routes used by the legacy SPA."""

    def test_existing_routes_module_still_importable(self):
        # Smoke import — if routes.py grew a syntax error this fails fast.
        from api import routes as r
        assert callable(r.attack_heatmap)
        assert callable(r.findings_list)
        assert callable(r.programs_list)  # newly added
