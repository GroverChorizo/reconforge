"""Phase 18 — asset tree builder + tools category grouping."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core import programs as P, assets as A
from api import routes, server
from db.migrations import runner as MIG
from tools import detect as D


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
        db, name="ACME", platform="intigriti", platform_handle="researcher",
        scope=[{"type": "wildcard", "value": "*.acme.com", "tier": 2}],
        out_of_scope=[{"type": "domain", "value": "careers.acme.com"}],
    )


@pytest.fixture
def seeded(db, acme):
    db.execute("INSERT INTO subdomains(domain, subdomain, http_status, http_title, "
                "http_technologies, ip_addresses) "
                "VALUES ('acme.com','api.acme.com',200,'API home','[\"nginx\"]','[\"1.2.3.4\"]')")
    db.execute("INSERT INTO subdomains(domain, subdomain, http_status, http_title) "
                "VALUES ('acme.com','auth.acme.com',200,'Auth')")
    db.execute("INSERT INTO subdomains(domain, subdomain) "
                "VALUES ('acme.com','careers.acme.com')")
    db.execute("INSERT INTO subdomains(domain, subdomain) "
                "VALUES ('other.org','www.other.org')")
    # Attach a finding to one subdomain.
    sid = db.execute("SELECT id FROM subdomains WHERE subdomain='api.acme.com'").fetchone()[0]
    db.execute("INSERT INTO findings(bug_id, job_id, domain, subdomain_id, "
                "vuln_class, title, confidence, status) "
                "VALUES ('BUG-001','J1','api.acme.com',?,'ssrf','SSRF',0.9,'new')",
                (sid,))
    db.commit()
    return db


# ── tree builder ──────────────────────────────────────────────────
class TestTreeShape:

    def test_in_program_only(self, seeded, acme):
        tree = A.build_asset_tree(seeded, acme)
        # other.org is excluded — out-of-program; careers.acme.com excluded too
        # (out_of_scope by program rule, domain_in_program returns False).
        subs = {n["subdomain"] for r in tree for n in r["subdomains"]}
        assert subs == {"api.acme.com", "auth.acme.com"}

    def test_grouped_by_root_domain(self, seeded, acme):
        tree = A.build_asset_tree(seeded, acme)
        assert len(tree) == 1
        assert tree[0]["root_domain"] == "acme.com"
        assert tree[0]["subdomain_count"] == 2

    def test_finding_count_attached(self, seeded, acme):
        tree = A.build_asset_tree(seeded, acme)
        subs = {n["subdomain"]: n for r in tree for n in r["subdomains"]}
        assert subs["api.acme.com"]["finding_count"] == 1
        assert subs["auth.acme.com"]["finding_count"] == 0

    def test_in_scope_only_filter(self, seeded, acme):
        # Already only-in-program; in_scope_only is a no-op here because
        # the program scope rule itself sets scope_status='in' for both.
        tree = A.build_asset_tree(seeded, acme, in_scope_only=True)
        assert sum(n["subdomain_count"] for n in tree) == 2

    def test_with_findings_only_filter(self, seeded, acme):
        tree = A.build_asset_tree(seeded, acme, with_findings_only=True)
        subs = {n["subdomain"] for r in tree for n in r["subdomains"]}
        assert subs == {"api.acme.com"}

    def test_search_filter(self, seeded, acme):
        tree = A.build_asset_tree(seeded, acme, q="api")
        subs = {n["subdomain"] for r in tree for n in r["subdomains"]}
        assert subs == {"api.acme.com"}

    def test_scope_status_attached(self, seeded, acme):
        tree = A.build_asset_tree(seeded, acme)
        for r in tree:
            for n in r["subdomains"]:
                assert n["scope_status"] == "in"


# ── detail ───────────────────────────────────────────────────────
class TestAssetDetail:

    def test_detail_includes_findings(self, seeded):
        sid = seeded.execute(
            "SELECT id FROM subdomains WHERE subdomain='api.acme.com'"
        ).fetchone()[0]
        out = A.asset_detail(seeded, sid)
        assert out["subdomain"] == "api.acme.com"
        assert out["technologies"] == ["nginx"]
        assert out["ip_addresses"] == ["1.2.3.4"]
        assert len(out["findings"]) == 1

    def test_detail_missing(self, seeded):
        assert A.asset_detail(seeded, 99999) is None


# ── routes + dispatcher ──────────────────────────────────────────
class TestRoutes:

    def test_assets_route(self, seeded, acme):
        status, body = server.dispatch(
            "GET", f"/api/v2/programs/{acme.slug}/assets", {}, None, seeded,
        )
        assert status == 200
        assert body["subdomain_count"] == 2

    def test_assets_route_filter_qs(self, seeded, acme):
        status, body = server.dispatch(
            "GET", f"/api/v2/programs/{acme.slug}/assets",
            {"q": ["api"], "in_scope_only": ["1"]}, None, seeded,
        )
        assert status == 200
        assert body["subdomain_count"] == 1

    def test_asset_detail_route(self, seeded):
        sid = seeded.execute(
            "SELECT id FROM subdomains WHERE subdomain='api.acme.com'"
        ).fetchone()[0]
        status, body = server.dispatch(
            "GET", f"/api/v2/assets/{sid}", {}, None, seeded,
        )
        assert status == 200
        assert body["subdomain"] == "api.acme.com"

    def test_asset_detail_404(self, seeded):
        status, _ = server.dispatch("GET", "/api/v2/assets/99999", {}, None, seeded)
        assert status == 404


# ── tools detect category ────────────────────────────────────────
class TestToolCategory:

    def test_every_catalog_entry_has_category(self):
        for name, entry in D.CATALOG.items():
            assert entry.category in {
                "subdomain", "dns_http", "screenshot", "vuln",
                "fuzz", "api", "graphql", "cloud", "js", "other",
            }, f"{name} has unexpected category {entry.category!r}"

    def test_scan_surfaces_category(self):
        statuses = D.scan()
        assert all(getattr(s, "category", None) for s in statuses)

    def test_tool_health_route_includes_category(self):
        # Force refresh to bypass the test-cross-pollination cache.
        out = routes.tool_health(refresh=True)
        assert all("category" in t for t in out["tools"])
