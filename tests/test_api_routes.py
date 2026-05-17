"""
Phase 10 — JSON API route functions.

Test every endpoint that the v2 SPA consumes, against an in-memory DB
seeded with realistic findings + drafts + attack_techniques.
"""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from api import routes
from db.migrations import runner as MIG


# ═══════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════
@pytest.fixture
def db(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    MIG.run_pending(conn)
    yield conn
    conn.close()


@pytest.fixture
def seeded_db(db):
    """Seed: 2 findings, 1 with ATT&CK + drafts, 1 dup."""
    db.execute("INSERT INTO subdomains(domain, subdomain) "
                "VALUES('acme.com','api.acme.com')")
    sid = db.execute("SELECT id FROM subdomains WHERE subdomain='api.acme.com'") \
            .fetchone()[0]
    # Real finding
    db.execute(
        "INSERT INTO findings(bug_id, job_id, domain, subdomain_id, vuln_class, "
        "title, description, evidence_json, confidence, cvss_vector, cvss_score, "
        "bounty_estimate_usd, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("BUG-001", "J1", "acme.com", sid, "ssrf",
         "SSRF reaches IMDS", "desc", json.dumps({"endpoint": "/webhook"}),
         0.9,
         "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N/E:P",
         9.0, 7500, "new"),
    )
    fid1 = db.execute("SELECT id FROM findings WHERE bug_id='BUG-001'").fetchone()[0]
    # Dup of BUG-001
    db.execute(
        "INSERT INTO findings(bug_id, job_id, domain, subdomain_id, vuln_class, "
        "title, description, evidence_json, confidence, cvss_score, "
        "status, parent_finding_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("BUG-002", "J1", "acme.com", sid, "ssrf",
         "SSRF dup", "desc", "{}", 0.7, 8.5, "dup", fid1),
    )
    # ATT&CK rows
    db.execute(
        "INSERT INTO attack_techniques(finding_id, tactic, technique_id, "
        "sub_technique_id, confidence, rationale) VALUES (?,?,?,?,?,?)",
        (fid1, "TA0001", "T1190", None, 0.90, "ssrf canonical"),
    )
    db.execute(
        "INSERT INTO attack_techniques(finding_id, tactic, technique_id, "
        "sub_technique_id, confidence, rationale) VALUES (?,?,?,?,?,?)",
        (fid1, "TA0006", "T1552", "T1552.005", 0.80, "IMDS keyword"),
    )
    # Drafts
    for plat in ("hackerone", "intigriti"):
        db.execute(
            "INSERT INTO submission_drafts(finding_id, platform, title, body_md, "
            "severity, weakness) VALUES (?,?,?,?,?,?)",
            (fid1, plat, "SSRF in webhook", "## Summary\n...",
             "Critical", "CWE-918"),
        )
    # Agent runs
    for (a, m, c) in [("scope_guard", None, 0.0),
                      ("strategist", "claude-opus-4-7", 0.05),
                      ("recon",      "claude-haiku-4-5-20251001", 0.03),
                      ("hunter",     "claude-haiku-4-5-20251001", 0.07),
                      ("analyst",    "claude-opus-4-7", 0.12),
                      ("reporter",   "claude-opus-4-7", 0.08)]:
        db.execute(
            "INSERT INTO agent_runs(job_id, agent, model, status, "
            "prompt_tokens, completion_tokens, cost_usd, "
            "started_at, completed_at) "
            "VALUES (?,?,?,?,?,?,?,datetime('now','-1 minutes'),datetime('now'))",
            ("J1", a, m, "completed", 100, 50, c),
        )
    db.commit()
    return db


# ═══════════════════════════════════════════════════════════
#  /api/attack/heatmap
# ═══════════════════════════════════════════════════════════
class TestHeatmap:

    def test_returns_14_tactics(self, seeded_db):
        out = routes.attack_heatmap(seeded_db, "J1")
        assert len(out["tactics"]) == 14
        assert "TA0001" in out["tactics"]
        assert out["tactics"]["TA0001"]["count"] >= 1

    def test_total_findings_count(self, seeded_db):
        out = routes.attack_heatmap(seeded_db, "J1")
        assert out["total_findings"] == 2

    def test_zero_fill_for_unhit_tactics(self, seeded_db):
        out = routes.attack_heatmap(seeded_db, "J1")
        for tid in ("TA0040", "TA0011"):
            assert out["tactics"][tid]["count"] == 0


# ═══════════════════════════════════════════════════════════
#  /api/findings
# ═══════════════════════════════════════════════════════════
class TestFindingsList:

    def test_excludes_dup_by_default(self, seeded_db):
        out = routes.findings_list(seeded_db, "J1")
        bug_ids = [f["bug_id"] for f in out["findings"]]
        assert "BUG-001" in bug_ids
        assert "BUG-002" not in bug_ids
        assert out["count"] == 1

    def test_include_dup_flag(self, seeded_db):
        out = routes.findings_list(seeded_db, "J1", include_dup=True,
                                    include_child=True)
        assert len(out["findings"]) == 2

    def test_filter_by_class(self, seeded_db):
        out = routes.findings_list(seeded_db, "J1", vuln_class="ssrf")
        assert all(f["vuln_class"] == "ssrf" for f in out["findings"])

    def test_attaches_techniques_and_draft_count(self, seeded_db):
        out = routes.findings_list(seeded_db, "J1")
        f = out["findings"][0]
        assert "T1190" in f["attack_techniques"]
        assert f["draft_count"] == 2


# ═══════════════════════════════════════════════════════════
#  /api/findings/<id>
# ═══════════════════════════════════════════════════════════
class TestFindingDetail:

    def test_full_payload(self, seeded_db):
        fid = seeded_db.execute(
            "SELECT id FROM findings WHERE bug_id='BUG-001'"
        ).fetchone()[0]
        out = routes.finding_detail(seeded_db, fid)
        assert out["bug_id"] == "BUG-001"
        assert out["cvss_score"] == 9.0
        assert isinstance(out["evidence"], dict)
        assert out["evidence"].get("endpoint") == "/webhook"
        assert len(out["attack_techniques"]) == 2
        assert len(out["drafts"]) == 2

    def test_missing_returns_none(self, seeded_db):
        assert routes.finding_detail(seeded_db, 9_999) is None


# ═══════════════════════════════════════════════════════════
#  /api/submissions/<id>
# ═══════════════════════════════════════════════════════════
class TestSubmissions:

    def test_detail(self, seeded_db):
        did = seeded_db.execute(
            "SELECT id FROM submission_drafts WHERE platform='hackerone'"
        ).fetchone()[0]
        out = routes.submission_detail(seeded_db, did)
        assert out["platform"] == "hackerone"
        assert out["bug_id"] == "BUG-001"
        assert out["cvss_vector"].startswith("CVSS:4.0/")
        assert out["human_approved"] is False

    def test_approve_toggle(self, seeded_db):
        did = seeded_db.execute(
            "SELECT id FROM submission_drafts WHERE platform='intigriti'"
        ).fetchone()[0]
        before = routes.submission_detail(seeded_db, did)
        assert before["human_approved"] is False
        routes.submission_approve(seeded_db, did, approved=True)
        after = routes.submission_detail(seeded_db, did)
        assert after["human_approved"] is True
        routes.submission_approve(seeded_db, did, approved=False)
        assert routes.submission_detail(seeded_db, did)["human_approved"] is False

    def test_missing_returns_none(self, seeded_db):
        assert routes.submission_detail(seeded_db, 9_999) is None


# ═══════════════════════════════════════════════════════════
#  /api/agents/runs
# ═══════════════════════════════════════════════════════════
class TestAgentRuns:

    def test_lists_all_six(self, seeded_db):
        out = routes.agent_runs(seeded_db, "J1")
        assert {r["agent"] for r in out["runs"]} == {
            "scope_guard", "strategist", "recon",
            "hunter", "analyst", "reporter",
        }
        assert out["total_cost_usd"] == pytest.approx(0.35, abs=1e-4)


# ═══════════════════════════════════════════════════════════
#  /api/job — combined snapshot
# ═══════════════════════════════════════════════════════════
class TestJobOverview:

    def test_returns_three_panels(self, seeded_db):
        out = routes.job_overview(seeded_db, "J1")
        assert "agents" in out and "heatmap" in out and "findings" in out
        assert out["agents"]["total_cost_usd"] > 0
        assert out["heatmap"]["total_findings"] == 2
        assert out["findings"]["count"] == 1


# ═══════════════════════════════════════════════════════════
#  Empty-job behavior
# ═══════════════════════════════════════════════════════════
class TestEmptyJob:

    def test_heatmap_zero_filled(self, db):
        out = routes.attack_heatmap(db, "missing")
        assert out["total_findings"] == 0
        assert all(t["count"] == 0 for t in out["tactics"].values())

    def test_findings_empty(self, db):
        out = routes.findings_list(db, "missing")
        assert out["count"] == 0

    def test_runs_empty(self, db):
        out = routes.agent_runs(db, "missing")
        assert out["runs"] == []
        assert out["total_cost_usd"] == 0.0
