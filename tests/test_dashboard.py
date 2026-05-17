"""Phase 17 — Mission Control dashboard endpoint.

Covers:
  * GET /api/v2/programs/{slug}/dashboard returns the 8-widget bundle.
  * scope_summary counts rules + observed assets in/blocked/ambiguous.
  * recent_assets only includes in-scope hosts, ordered by recency.
  * new_findings filters by domain-in-program and confidence floor.
  * active_jobs surfaces running agent_runs.
  * next_best_actions reads agent_memory(strategist, next_actions).
  * reports_ready joins submission_drafts to findings + filters by program.
  * tool_summary includes installed/missing counts.
  * 404 for unknown program.
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
        platform_handle="grover",
        scope=[{"type": "wildcard", "value": "*.acme.com", "tier": 2}],
        out_of_scope=[{"type": "domain", "value": "careers.acme.com"}],
        bounty_ranges={"critical": [2000, 5000]},
        notes="Researcher must respect rate limits.",
    )


@pytest.fixture
def seeded(db, acme):
    # Subdomains: 2 in-scope, 1 blocked, 1 ambiguous.
    for sub in ("api.acme.com", "auth.acme.com"):
        db.execute(
            "INSERT INTO subdomains(domain, subdomain, http_status, http_title) "
            "VALUES (?,?,?,?)",
            ("acme.com", sub, 200, f"{sub} home"),
        )
    db.execute(
        "INSERT INTO subdomains(domain, subdomain, http_status, http_title) "
        "VALUES ('acme.com','careers.acme.com',200,'Careers')"
    )
    db.execute(
        "INSERT INTO subdomains(domain, subdomain, http_status, http_title) "
        "VALUES ('other.org','www.other.org',200,'unrelated')"
    )

    # Findings: one new + high-confidence in scope, one out of scope, one low conf.
    db.execute(
        "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, "
        "confidence, cvss_score, status) "
        "VALUES ('BUG-001','J1','api.acme.com','ssrf','SSRF in webhook',"
        "0.9, 9.1,'new')"
    )
    db.execute(
        "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, "
        "confidence, status) "
        "VALUES ('BUG-002','J1','www.other.org','xss','XSS unrelated',"
        "0.9,'new')"
    )
    db.execute(
        "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, "
        "confidence, status) "
        "VALUES ('BUG-003','J1','api.acme.com','idor','low conf',"
        "0.3,'new')"
    )

    # Submission drafts: one for an in-program finding (BUG-001).
    fid1 = db.execute("SELECT id FROM findings WHERE bug_id='BUG-001'").fetchone()[0]
    db.execute(
        "INSERT INTO submission_drafts(finding_id, platform, title, severity, "
        "human_approved) VALUES (?, 'hackerone', 'SSRF in webhook', 'Critical', 0)",
        (fid1,),
    )
    fid_off = db.execute("SELECT id FROM findings WHERE bug_id='BUG-002'").fetchone()[0]
    db.execute(
        "INSERT INTO submission_drafts(finding_id, platform, title, severity, "
        "human_approved) VALUES (?, 'hackerone', 'XSS unrelated', 'High', 0)",
        (fid_off,),
    )

    # An already-approved draft for BUG-001 — should NOT appear in reports_ready.
    db.execute(
        "INSERT INTO submission_drafts(finding_id, platform, title, severity, "
        "human_approved) VALUES (?, 'intigriti', 'SSRF approved', 'Critical', 1)",
        (fid1,),
    )

    # Active agent_runs.
    db.execute(
        "INSERT INTO agent_runs(job_id, agent, model, status, "
        "started_at) VALUES ('J1','recon','claude-haiku-4-5-20251001',"
        "'running', datetime('now'))"
    )

    # Next best actions stored by Strategist.
    db.execute(
        "INSERT INTO agent_memory(job_id, agent, key, value_json) "
        "VALUES ('J1','strategist','next_actions', ?)",
        (json.dumps([
            {"text": "Run passive recon", "why": "no baseline assets yet"},
            "Manually verify nuclei medium findings",
        ]),),
    )
    db.commit()
    return db


# ── endpoint shape ────────────────────────────────────────────────
class TestDashboardShape:

    def test_returns_all_eight_keys(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug)
        assert set(out.keys()) >= {
            "program", "scope_summary", "active_jobs", "recent_assets",
            "new_findings", "tool_summary", "next_best_actions", "reports_ready",
        }

    def test_missing_program_returns_none(self, seeded):
        assert routes.program_dashboard(seeded, "no-such-program") is None


# ── scope_summary ─────────────────────────────────────────────────
class TestScopeSummary:

    def test_rule_counts(self, seeded, acme):
        ss = routes.program_dashboard(seeded, acme.slug)["scope_summary"]
        assert ss["rule_in_count"] == 1
        assert ss["rule_out_count"] == 1

    def test_assets_in_count(self, seeded, acme):
        ss = routes.program_dashboard(seeded, acme.slug)["scope_summary"]
        # api.acme.com + auth.acme.com are in_scope.
        assert ss["assets_in"] == 2

    def test_assets_blocked_count(self, seeded, acme):
        ss = routes.program_dashboard(seeded, acme.slug)["scope_summary"]
        # careers.acme.com is out_of_scope.
        assert ss["assets_blocked"] == 1

    def test_assets_ambiguous_count(self, seeded, acme):
        ss = routes.program_dashboard(seeded, acme.slug)["scope_summary"]
        # www.other.org matches neither in nor out.
        assert ss["assets_ambiguous"] == 1


# ── recent_assets ────────────────────────────────────────────────
class TestRecentAssets:

    def test_only_in_scope_assets(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug)
        subs = {a["subdomain"] for a in out["recent_assets"]}
        assert "careers.acme.com" not in subs
        assert "www.other.org" not in subs
        assert "api.acme.com" in subs
        assert "auth.acme.com" in subs

    def test_carries_scope_status(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug)
        assert all(a["scope_status"] == "in" for a in out["recent_assets"])

    def test_limit_param(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug, limit=1)
        assert len(out["recent_assets"]) <= 1


# ── new_findings ──────────────────────────────────────────────────
class TestNewFindings:

    def test_filters_to_program_domain(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug)
        bug_ids = [f["bug_id"] for f in out["new_findings"]]
        # BUG-002 (other.org) excluded; BUG-003 (low conf) excluded.
        assert bug_ids == ["BUG-001"]

    def test_confidence_floor(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug)
        for f in out["new_findings"]:
            assert f["confidence"] >= 0.6


# ── active_jobs + tool_summary ────────────────────────────────────
class TestActiveAndTools:

    def test_active_jobs_present(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug)
        assert len(out["active_jobs"]) == 1
        assert out["active_jobs"][0]["status"] == "running"

    def test_tool_summary_present(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug)
        ts = out["tool_summary"]
        assert "total" in ts and "installed" in ts and "missing" in ts


# ── next_best_actions ─────────────────────────────────────────────
class TestNextBestActions:

    def test_unpacks_list_payload(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug)
        actions = out["next_best_actions"]
        assert len(actions) == 2
        assert any("Run passive recon" in a.get("text", "") for a in actions)
        assert any("Manually verify" in a.get("text", "") for a in actions)

    def test_empty_when_no_strategist_memory(self, db, acme):
        out = routes.program_dashboard(db, acme.slug)
        assert out["next_best_actions"] == []


# ── reports_ready ─────────────────────────────────────────────────
class TestReportsReady:

    def test_filters_unapproved_in_program(self, seeded, acme):
        out = routes.program_dashboard(seeded, acme.slug)
        drafts = out["reports_ready"]
        # The unapproved draft for BUG-001 is in; the approved one is out;
        # the BUG-002 (out-of-program) draft is out.
        assert len(drafts) == 1
        assert drafts[0]["bug_id"] == "BUG-001"
        assert drafts[0]["platform"] == "hackerone"


# ── dispatcher ───────────────────────────────────────────────────
class TestDashboardRoute:

    def test_dispatch_dashboard(self, seeded, acme):
        status, body = server.dispatch(
            "GET", f"/api/v2/programs/{acme.slug}/dashboard", {}, None, seeded,
        )
        assert status == 200
        assert body["program"]["slug"] == acme.slug

    def test_dispatch_404(self, db):
        status, body = server.dispatch(
            "GET", "/api/v2/programs/ghost/dashboard", {}, None, db,
        )
        assert status == 404

    def test_dispatch_limit_qs(self, seeded, acme):
        status, body = server.dispatch(
            "GET", f"/api/v2/programs/{acme.slug}/dashboard",
            {"limit": ["1"]}, None, seeded,
        )
        assert status == 200
        assert len(body["recent_assets"]) <= 1
