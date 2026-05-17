"""Phase 19 — findings Kanban board + status state machine + manual checklists."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core import programs as P, findings as F
from api import routes, server
from db.migrations import runner as MIG


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
        db, name="ACME", platform="intigriti", platform_handle="grover",
        scope=[{"type": "wildcard", "value": "*.acme.com", "tier": 2}],
    )


@pytest.fixture
def seeded(db, acme):
    rows = [
        ("BUG-001", "api.acme.com",  "ssrf",      0.9, 9.1, "new"),
        ("BUG-002", "api.acme.com",  "idor",      0.7, 6.5, "needs_review"),
        ("BUG-003", "auth.acme.com", "xss",       0.6, 5.0, "confirmed"),
        ("BUG-004", "api.acme.com",  "graphql",   0.3, 0.0, "new"),
        ("BUG-005", "off.example",   "xss",       0.9, 7.0, "new"),  # not in program
    ]
    for bug, dom, vc, conf, cvss, st in rows:
        db.execute(
            "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, "
            "confidence, cvss_score, status) VALUES (?,?,?,?,?,?,?,?)",
            (bug, "J1", dom, vc, f"{vc} demo on {dom}", conf, cvss, st),
        )
    fid = db.execute("SELECT id FROM findings WHERE bug_id='BUG-001'").fetchone()[0]
    db.execute(
        "INSERT INTO submission_drafts(finding_id, platform, title, severity, "
        "human_approved) VALUES (?, 'hackerone', 'SSRF', 'Critical', 0)", (fid,),
    )
    db.commit()
    return db


# ── status state machine ─────────────────────────────────────────
class TestStatus:

    def test_allowed_statuses(self):
        assert "new" in F.ALLOWED_STATUSES
        assert "needs_review" in F.ALLOWED_STATUSES
        assert "draft_ready" in F.ALLOWED_STATUSES
        assert "submitted" in F.ALLOWED_STATUSES
        assert "retesting" in F.ALLOWED_STATUSES

    def test_is_forward(self):
        assert F.is_forward("new", "needs_review")
        assert F.is_forward("confirmed", "draft_ready")
        assert not F.is_forward("closed", "new")
        assert not F.is_forward("new", "submitted")  # skipping intermediate

    def test_set_status_updates_row(self, seeded):
        fid = seeded.execute(
            "SELECT id FROM findings WHERE bug_id='BUG-001'"
        ).fetchone()[0]
        out = F.set_status(seeded, fid, "needs_review", operator="grover")
        assert out["to"] == "needs_review"
        assert out["from"] == "new"
        assert out["is_forward"] is True

        row = seeded.execute(
            "SELECT status FROM findings WHERE id=?", (fid,)
        ).fetchone()
        assert row["status"] == "needs_review"

    def test_set_status_invalid(self, seeded):
        fid = seeded.execute(
            "SELECT id FROM findings WHERE bug_id='BUG-001'"
        ).fetchone()[0]
        with pytest.raises(F.InvalidStatus):
            F.set_status(seeded, fid, "totally_fake")

    def test_set_status_missing_finding(self, db):
        with pytest.raises(ValueError):
            F.set_status(db, 99999, "new")

    def test_consecutive_status_changes_persist_latest(self, seeded):
        fid = seeded.execute(
            "SELECT id FROM findings WHERE bug_id='BUG-001'"
        ).fetchone()[0]
        F.set_status(seeded, fid, "needs_review", operator="g1")
        F.set_status(seeded, fid, "confirmed",    operator="g2")
        row = seeded.execute(
            "SELECT status FROM findings WHERE id=?", (fid,),
        ).fetchone()
        assert row["status"] == "confirmed"


# ── manual checklists ────────────────────────────────────────────
class TestManualChecklists:

    def test_idor_checklist_present(self):
        text = F.manual_checklist("idor")
        assert text is not None
        assert "researcher-owned" in text.lower()

    def test_mass_assignment_checklist_present(self):
        text = F.manual_checklist("mass_assignment")
        assert text is not None
        assert "isAdmin" in text

    def test_xxe_checklist_present(self):
        assert F.manual_checklist("xxe") is not None

    def test_unknown_class_returns_none(self):
        assert F.manual_checklist("not_a_real_class") is None

    def test_list_checklists(self):
        out = F.list_checklists()
        assert "idor" in out and "ssrf" in out


# ── board endpoint ───────────────────────────────────────────────
class TestBoard:

    def test_buckets_by_status(self, seeded, acme):
        out = routes.program_findings_board(seeded, acme.slug)
        assert out["counts"]["new"] == 2          # BUG-001 + BUG-004
        assert out["counts"]["needs_review"] == 1 # BUG-002
        assert out["counts"]["confirmed"] == 1    # BUG-003
        # BUG-005 excluded (not in program scope).
        assert out["total"] == 4

    def test_card_carries_confidence_label(self, seeded, acme):
        out = routes.program_findings_board(seeded, acme.slug)
        labels = {c["bug_id"]: c["confidence_label"]
                   for col in out["columns"].values() for c in col}
        assert labels["BUG-001"] == "high"
        assert labels["BUG-002"] == "high"  # 0.7 is the boundary
        assert labels["BUG-003"] == "medium"
        assert labels["BUG-004"] == "low"

    def test_draft_count_attached(self, seeded, acme):
        out = routes.program_findings_board(seeded, acme.slug)
        card = next(c for col in out["columns"].values() for c in col
                    if c["bug_id"] == "BUG-001")
        assert card["draft_count"] == 1

    def test_missing_program_404(self, db):
        assert routes.program_findings_board(db, "ghost") is None


# ── detail v2 ────────────────────────────────────────────────────
class TestDetailV2:

    def test_detail_bundles(self, seeded):
        fid = seeded.execute(
            "SELECT id FROM findings WHERE bug_id='BUG-001'"
        ).fetchone()[0]
        out = routes.finding_detail_v2(seeded, fid)
        assert out["bug_id"] == "BUG-001"
        assert "evidence" in out
        assert "taxonomy" in out
        assert "readiness" in out
        assert "valid_statuses" in out
        assert "forward_transitions" in out

    def test_detail_includes_manual_checklist(self, seeded):
        fid = seeded.execute(
            "SELECT id FROM findings WHERE bug_id='BUG-001'"
        ).fetchone()[0]
        out = routes.finding_detail_v2(seeded, fid)
        # vuln_class='ssrf' has a checklist.
        assert out["manual_checklist_md"] is not None
        assert "SSRF" in out["manual_checklist_md"]

    def test_detail_missing(self, db):
        assert routes.finding_detail_v2(db, 9999) is None


# ── dispatch ─────────────────────────────────────────────────────
class TestDispatch:

    def test_board_route(self, seeded, acme):
        status, body = server.dispatch(
            "GET", f"/api/v2/programs/{acme.slug}/findings_board", {}, None, seeded,
        )
        assert status == 200
        assert body["total"] == 4

    def test_detail_route(self, seeded):
        fid = seeded.execute("SELECT id FROM findings WHERE bug_id='BUG-001'").fetchone()[0]
        status, body = server.dispatch(
            "GET", f"/api/v2/findings/{fid}", {}, None, seeded,
        )
        assert status == 200
        assert body["bug_id"] == "BUG-001"

    def test_set_status_route(self, seeded):
        fid = seeded.execute("SELECT id FROM findings WHERE bug_id='BUG-001'").fetchone()[0]
        status, body = server.dispatch(
            "POST", f"/api/v2/findings/{fid}/status", {},
            {"status": "needs_review", "operator": "grover"}, seeded,
        )
        assert status == 200
        assert body["ok"] is True
        assert body["to"] == "needs_review"

    def test_set_status_invalid_400(self, seeded):
        fid = seeded.execute("SELECT id FROM findings WHERE bug_id='BUG-001'").fetchone()[0]
        status, body = server.dispatch(
            "POST", f"/api/v2/findings/{fid}/status", {},
            {"status": "bogus"}, seeded,
        )
        assert status == 400
        assert body["ok"] is False

    def test_set_status_404(self, db):
        status, body = server.dispatch(
            "POST", "/api/v2/findings/99999/status", {},
            {"status": "new"}, db,
        )
        assert status == 404
