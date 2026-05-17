"""Phase 20 — report quality gate (10 checks) + secret detection."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core import programs as P, evidence as E, report_gate as G
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
def good_draft(db, acme):
    db.execute(
        "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, status) "
        "VALUES ('BUG-001','J1','api.acme.com','ssrf','SSRF in webhook handler','new')"
    )
    fid = db.execute("SELECT id FROM findings WHERE bug_id='BUG-001'").fetchone()[0]
    E.record_evidence(db, fid, "request", "GET /webhook?url=...", "observed",
                       source_ref="tool:httpx")
    body = (
        "## Summary\nThe webhook handler fetches user-supplied URLs without validation.\n\n"
        "## Affected Asset\n- URL: https://api.acme.com/webhook\n- Method: POST\n\n"
        "## Steps to Reproduce\n1. Authenticate.\n2. POST /webhook with url=...\n\n"
        "## Impact\nServer makes outbound request to user-controlled destination.\n\n"
        "## Remediation\nAllowlist destinations and reject private IPs.\n"
    )
    db.execute(
        "INSERT INTO submission_drafts(finding_id, platform, title, body_md, "
        "severity, weakness, human_approved) VALUES "
        "(?, 'hackerone', 'SSRF in webhook handler allows internal pivot', "
        "?, 'Critical', 'CWE-918', 0)",
        (fid, body),
    )
    db.commit()
    return db.execute(
        "SELECT id FROM submission_drafts ORDER BY id DESC LIMIT 1"
    ).fetchone()[0]


# ── secret detection ─────────────────────────────────────────────
class TestDetectSecrets:

    def test_aws_key_caught(self):
        hits = G.detect_secrets("Look at this key: AKIAABCDEFGHIJKLMNOP")
        assert any(h["kind"] == "aws_access_key" for h in hits)

    def test_github_token_caught(self):
        hits = G.detect_secrets("token = ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        assert any(h["kind"] == "github_token" for h in hits)

    def test_jwt_caught(self):
        hits = G.detect_secrets("Auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJ")
        assert any(h["kind"] == "jwt" for h in hits)

    def test_private_key_block_caught(self):
        hits = G.detect_secrets("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        assert any(h["kind"] == "private_key_block" for h in hits)

    def test_clean_body_no_hits(self):
        assert G.detect_secrets("Steps to Reproduce: send a GET request.") == []


# ── quality gate ─────────────────────────────────────────────────
class TestGate:

    def test_good_draft_passes_when_reviewed(self, good_draft, db):
        gate = routes.submission_quality_gate(db, good_draft, operator_reviewed=True)
        assert gate["passed_count"] == gate["total"]
        assert gate["passed"] is True

    def test_unreviewed_fails(self, good_draft, db):
        gate = routes.submission_quality_gate(db, good_draft, operator_reviewed=False)
        # 9 of 10 pass; the operator-reviewed check fails.
        assert gate["passed"] is False
        reviewed = next(c for c in gate["checks"] if c["id"] == "reviewed")
        assert reviewed["passed"] is False

    def test_missing_sections_fail(self, db, acme):
        db.execute(
            "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, status) "
            "VALUES ('BUG-002','J1','api.acme.com','xss','XSS demo','new')"
        )
        fid = db.execute("SELECT id FROM findings WHERE bug_id='BUG-002'").fetchone()[0]
        db.execute(
            "INSERT INTO submission_drafts(finding_id, platform, title, body_md) "
            "VALUES (?, 'hackerone', 'Stored XSS in profile bio admin', "
            "'just some text with no sections')", (fid,),
        )
        db.commit()
        did = db.execute("SELECT id FROM submission_drafts ORDER BY id DESC LIMIT 1").fetchone()[0]
        gate = routes.submission_quality_gate(db, did, operator_reviewed=True)
        # title check passes (length≥12 + descriptive enough), but summary /
        # asset / repro / impact / remediation all fail. Plus no evidence
        # row. So at least 6 should fail.
        failed = [c for c in gate["checks"] if not c["passed"]]
        assert len(failed) >= 6

    def test_secret_in_body_fails(self, db, acme):
        db.execute(
            "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, status) "
            "VALUES ('BUG-003','J1','api.acme.com','ssrf','SSRF demo','new')"
        )
        fid = db.execute("SELECT id FROM findings WHERE bug_id='BUG-003'").fetchone()[0]
        db.execute(
            "INSERT INTO submission_drafts(finding_id, platform, title, body_md) "
            "VALUES (?, 'hackerone', 'SSRF in webhook handler full', "
            "'## Summary\n...\n\nUsing AKIAABCDEFGHIJKLMNOP as evidence')", (fid,),
        )
        db.commit()
        did = db.execute("SELECT id FROM submission_drafts ORDER BY id DESC LIMIT 1").fetchone()[0]
        gate = routes.submission_quality_gate(db, did, operator_reviewed=True)
        no_secrets = next(c for c in gate["checks"] if c["id"] == "no_secrets")
        assert no_secrets["passed"] is False
        assert "aws_access_key" in no_secrets["reason"]

    def test_scope_check_passes_when_in_program(self, good_draft, db):
        gate = routes.submission_quality_gate(db, good_draft, operator_reviewed=True)
        scope = next(c for c in gate["checks"] if c["id"] == "scope")
        assert scope["passed"] is True

    def test_missing_evidence_fails(self, db, acme):
        db.execute(
            "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, status) "
            "VALUES ('BUG-004','J1','api.acme.com','idor','IDOR demo','new')"
        )
        fid = db.execute("SELECT id FROM findings WHERE bug_id='BUG-004'").fetchone()[0]
        db.execute(
            "INSERT INTO submission_drafts(finding_id, platform, title, body_md) "
            "VALUES (?, 'hackerone', 'IDOR in user endpoint allows access', "
            "'## Summary\nIDOR.\n## Affected Asset\n- URL: x\n"
            "## Steps to Reproduce\n1. x\n## Impact\nx\n## Remediation\nx')", (fid,),
        )
        db.commit()
        did = db.execute("SELECT id FROM submission_drafts ORDER BY id DESC LIMIT 1").fetchone()[0]
        gate = routes.submission_quality_gate(db, did, operator_reviewed=True)
        ev = next(c for c in gate["checks"] if c["id"] == "evidence")
        assert ev["passed"] is False


# ── per-class templates are vendored ─────────────────────────────
class TestTemplatesShipped:

    TEMPLATE_DIR = ROOT / "submissions" / "templates"

    def test_idor_template_present(self):
        path = self.TEMPLATE_DIR / "idor.md"
        assert path.exists()
        body = path.read_text(encoding="utf-8")
        assert "CWE-639" in body
        assert "A01:2021" in body

    def test_mass_assignment_template_present(self):
        path = self.TEMPLATE_DIR / "mass_assignment.md"
        assert path.exists()
        body = path.read_text(encoding="utf-8")
        assert "CWE-915" in body
        assert "Mass Assignment" in body or "mass-assignment" in body.lower()

    def test_xss_template_present(self):
        path = self.TEMPLATE_DIR / "xss.md"
        assert path.exists()
        assert "CWE-79" in path.read_text(encoding="utf-8")

    def test_xxe_template_present(self):
        path = self.TEMPLATE_DIR / "xxe.md"
        assert path.exists()
        assert "CWE-611" in path.read_text(encoding="utf-8")

    def test_ssrf_template_present(self):
        path = self.TEMPLATE_DIR / "ssrf.md"
        assert path.exists()
        assert "CWE-918" in path.read_text(encoding="utf-8")


# ── dispatcher ───────────────────────────────────────────────────
class TestDispatch:

    def test_quality_gate_route(self, good_draft, db):
        status, body = server.dispatch(
            "GET", f"/api/v2/submissions/{good_draft}/quality_gate",
            {"reviewed": ["1"]}, None, db,
        )
        assert status == 200
        assert body["passed"] is True

    def test_quality_gate_route_404(self, db):
        status, body = server.dispatch(
            "GET", "/api/v2/submissions/9999/quality_gate", {}, None, db,
        )
        assert status == 404
