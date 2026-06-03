"""
Phase 9 part 2 — Reporter + submission formatters + vault.write_finding.

Verifies:
  - Every platform formatter returns a non-empty Draft with severity + weakness
  - Intigriti draft mentions X-Intigriti-Username
  - Bugcrowd draft carries a VRT category
  - Reporter writes one draft per platform per eligible finding
  - Dup / child findings are skipped
  - BUG-XXX.md is written to the vault under 01-Programs/<program>/
  - submission_drafts rows exist with human_approved=0
"""
import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from agents.base import AgentContext
from agents.reporter import ReporterAgent, _parse_reporter_json
from db.migrations import runner as MIG
from vault import writer as vault_writer
from submissions import REGISTRY as FORMATTERS
from submissions.common import Draft


# ═══════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════
@pytest.fixture
def migrated_db(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    MIG.run_pending(conn)
    yield conn
    conn.close()


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    vroot = tmp_path / "Vault"
    monkeypatch.setattr(vault_writer, "vault_root", lambda: vroot)
    return vroot


def _seed_findings(db, job_id, items):
    """items: list of (bug_id, vuln_class, title, description, status, parent_id)."""
    db.execute("INSERT OR IGNORE INTO subdomains(domain, subdomain) "
                "VALUES('acme.com','www.acme.com')")
    sid = db.execute(
        "SELECT id FROM subdomains WHERE subdomain='www.acme.com'"
    ).fetchone()[0]
    ids = []
    for bug_id, vc, title, desc, status, parent in items:
        cur = db.execute(
            "INSERT INTO findings(bug_id, job_id, domain, subdomain_id, "
            "vuln_class, title, description, evidence_json, confidence, "
            "cvss_vector, cvss_score, bounty_estimate_usd, status, parent_finding_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (bug_id, job_id, "acme.com", sid, vc, title, desc,
             json.dumps({"endpoint": f"/{vc}", "poc": f"<poc-{bug_id}>"}),
             0.8,
             "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P",
             8.0, 5000, status, parent),
        )
        ids.append(cur.lastrowid)
    db.commit()
    return ids


_FINDING = {
    "bug_id": "BUG-001", "vuln_class": "ssrf",
    "title": "SSRF in webhook URL fetcher",
    "description": "Server fetches user-supplied URL → reaches IMDS at 169.254.169.254",
    "evidence": {"endpoint": "/api/webhook", "poc": "url=http://169.254.169.254"},
    "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N/E:P",
    "cvss_score": 9.0,
    "attack_techniques": ["T1190", "T1552", "T1552.005"],
}

_PROGRAM = {"name": "acme",
            "platforms": ["hackerone", "intigriti", "bugcrowd",
                          "yeswehack", "synack"],
            "platform_handle": "testhandle"}


# ═══════════════════════════════════════════════════════════
#  PLATFORM FORMATTERS
# ═══════════════════════════════════════════════════════════
class TestFormatters:

    @pytest.mark.parametrize("platform", list(FORMATTERS))
    def test_format_returns_nonempty_draft(self, platform):
        fmt = FORMATTERS[platform]
        d = fmt(_FINDING, _PROGRAM)
        assert isinstance(d, Draft)
        assert d.title
        assert d.body_md
        assert d.severity in ("Critical", "High", "Medium", "Low", "None", "Unknown")
        assert d.weakness

    def test_h1_mentions_summary_and_cvss(self):
        d = FORMATTERS["hackerone"](_FINDING, _PROGRAM)
        assert "## Summary" in d.body_md
        assert d.cvss_vector == _FINDING["cvss_vector"]
        assert "CVSS 4.0" in d.body_md or "CVSS" in d.body_md

    def test_intigriti_carries_header_reminder(self):
        d = FORMATTERS["intigriti"](_FINDING, _PROGRAM)
        assert "X-Intigriti-Username" in d.body_md
        assert d.extra.get("required_header", "").startswith("X-Intigriti-Username")

    def test_bugcrowd_includes_vrt(self):
        d = FORMATTERS["bugcrowd"](_FINDING, _PROGRAM)
        assert d.extra.get("vrt")
        assert "VRT" in d.body_md or "vrt" in d.body_md

    def test_yeswehack_includes_owasp_and_business_impact(self):
        d = FORMATTERS["yeswehack"](_FINDING, _PROGRAM)
        assert "OWASP" in d.body_md
        assert "Business Impact" in d.body_md

    def test_synack_body_is_json(self):
        d = FORMATTERS["synack"](_FINDING, _PROGRAM)
        parsed = json.loads(d.body_md)
        assert parsed["category"]
        assert parsed["severity"] == "Critical"

    def test_h1_alias(self):
        # "h1" maps to hackerone
        assert FORMATTERS["h1"] is FORMATTERS["hackerone"]

    def test_no_cvss_falls_back_gracefully(self):
        f = dict(_FINDING)
        f["cvss_vector"] = None
        f["cvss_score"] = None
        d = FORMATTERS["hackerone"](f, _PROGRAM)
        assert d.severity == "Unknown"
        assert d.title


# ═══════════════════════════════════════════════════════════
#  VAULT.write_finding
# ═══════════════════════════════════════════════════════════
class TestWriteFinding:

    def test_writes_bug_md_under_program(self, vault_dir):
        finding = dict(_FINDING, status="new")
        path = vault_writer.write_finding("acme", finding, drafts={
            "hackerone": FORMATTERS["hackerone"](finding, _PROGRAM)
        }, overwrite=True)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert content.startswith("---")  # frontmatter
        assert "# SSRF in webhook URL fetcher" in content
        assert "## Platform Drafts" in content
        assert "hackerone" in content.lower()

    def test_writes_into_sanitized_program_dir(self, vault_dir):
        path = vault_writer.write_finding("ACME Inc.", dict(_FINDING),
                                       drafts={}, overwrite=True)
        # Sanitized: lowercase, non-alnum → -
        assert "01-Programs" in str(path)
        # Program dir name is sanitized
        assert "acme-inc" in str(path).lower()


# ═══════════════════════════════════════════════════════════
#  ReporterAgent
# ═══════════════════════════════════════════════════════════
class TestReporterRun:

    def test_skips_dup_and_child(self, migrated_db, vault_dir):
        _seed_findings(migrated_db, "J", [
            ("BUG-A", "ssrf", "Real SSRF",         "imds", "new", None),
            ("BUG-B", "ssrf", "Duplicate of A",    "imds", "dup", None),
            ("BUG-C", "idor", "Child of A",        "idor", "new", 1),
        ])
        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        with patch.object(ReporterAgent, "call_llm",
                          return_value={"content": '{"polished": []}',
                                         "tool_calls": [],
                                         "prompt_tokens": 50, "completion_tokens": 20,
                                         "cost_usd": 0.0, "model": "mock"}):
            result = ReporterAgent(db=migrated_db).run(ctx)
        assert result.success
        assert result.output["findings_reported"] == 1
        # 5 platforms × 1 finding
        assert result.output["drafts_count"] == 5

    def test_writes_drafts_per_platform(self, migrated_db, vault_dir):
        _seed_findings(migrated_db, "J", [
            ("BUG-001", "ssrf", "SSRF", "imds", "new", None),
        ])
        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        with patch.object(ReporterAgent, "call_llm",
                          return_value={"content": '{"polished": []}',
                                         "tool_calls": [],
                                         "prompt_tokens": 50, "completion_tokens": 20,
                                         "cost_usd": 0.0, "model": "mock"}):
            ReporterAgent(db=migrated_db).run(ctx)
        rows = migrated_db.execute(
            "SELECT platform, human_approved FROM submission_drafts"
        ).fetchall()
        platforms = {r["platform"] for r in rows}
        assert platforms == {"hackerone", "intigriti", "bugcrowd",
                              "yeswehack", "synack"}
        assert all(r["human_approved"] == 0 for r in rows)

    def test_polish_applied_to_title(self, migrated_db, vault_dir):
        _seed_findings(migrated_db, "J", [
            ("BUG-001", "ssrf", "raw title", "imds", "new", None),
        ])
        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        polish = {"polished": [{
            "bug_id": "BUG-001",
            "polished_title": "Critical SSRF in webhook fetcher reaches IMDS",
            "executive_summary": "Two-sentence lead about the impact.",
            "preferred_platform": "hackerone",
        }]}
        with patch.object(ReporterAgent, "call_llm",
                          return_value={"content": json.dumps(polish),
                                         "tool_calls": [],
                                         "prompt_tokens": 50, "completion_tokens": 20,
                                         "cost_usd": 0.0, "model": "mock"}):
            ReporterAgent(db=migrated_db).run(ctx)
        titles = [r["title"] for r in migrated_db.execute(
            "SELECT title FROM submission_drafts"
        ).fetchall()]
        assert all("Critical SSRF" in t for t in titles)

    def test_writes_vault_note(self, migrated_db, vault_dir):
        _seed_findings(migrated_db, "J", [
            ("BUG-001", "ssrf", "SSRF", "imds", "new", None),
        ])
        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        with patch.object(ReporterAgent, "call_llm",
                          return_value={"content": '{"polished": []}',
                                         "tool_calls": [],
                                         "prompt_tokens": 50, "completion_tokens": 20,
                                         "cost_usd": 0.0, "model": "mock"}):
            result = ReporterAgent(db=migrated_db).run(ctx)
        notes = result.output["notes_written"]
        assert notes
        assert Path(notes[0]).exists()

    def test_polish_failure_falls_back_to_raw_titles(self, migrated_db, vault_dir):
        from agents.base import LLMError
        _seed_findings(migrated_db, "J", [
            ("BUG-001", "ssrf", "raw title", "imds", "new", None),
        ])
        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        with patch.object(ReporterAgent, "call_llm",
                          side_effect=LLMError("simulated")):
            result = ReporterAgent(db=migrated_db).run(ctx)
        assert result.success  # graceful fallback
        rows = migrated_db.execute(
            "SELECT title FROM submission_drafts WHERE platform='hackerone'"
        ).fetchall()
        assert "raw title" in rows[0]["title"]

    def test_no_eligible_findings(self, migrated_db, vault_dir):
        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        result = ReporterAgent(db=migrated_db).run(ctx)
        assert result.success is False
        assert "eligible" in result.error

    def test_no_platforms(self, migrated_db, vault_dir):
        _seed_findings(migrated_db, "J", [
            ("BUG-001", "ssrf", "SSRF", "imds", "new", None),
        ])
        ctx = AgentContext(job_id="J", db=migrated_db,
                            program={"name": "acme"})  # no platforms
        with patch.object(ReporterAgent, "call_llm",
                          return_value={"content": '{"polished": []}',
                                         "tool_calls": [],
                                         "prompt_tokens": 50, "completion_tokens": 20,
                                         "cost_usd": 0.0, "model": "mock"}):
            result = ReporterAgent(db=migrated_db).run(ctx)
        assert result.success is False
        assert "platforms" in result.error.lower()

    def test_summary_persisted(self, migrated_db, vault_dir):
        _seed_findings(migrated_db, "J", [
            ("BUG-001", "ssrf", "SSRF", "imds", "new", None),
        ])
        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        with patch.object(ReporterAgent, "call_llm",
                          return_value={"content": '{"polished": []}',
                                         "tool_calls": [],
                                         "prompt_tokens": 50, "completion_tokens": 20,
                                         "cost_usd": 0.0, "model": "mock"}):
            agent = ReporterAgent(db=migrated_db)
            agent.run(ctx)
            recalled = agent.recall(ctx, "reporter_summary")
        assert recalled["findings_reported"] == 1
        assert recalled["drafts_count"] == 5


# ═══════════════════════════════════════════════════════════
#  JSON parser
# ═══════════════════════════════════════════════════════════
class TestParse:

    def test_plain(self):
        assert _parse_reporter_json('{"polished": []}') == {"polished": []}

    def test_fenced(self):
        assert _parse_reporter_json('```json\n{"polished":[]}\n```') == {"polished": []}

    def test_garbage(self):
        assert _parse_reporter_json("nope") is None
