"""
Phase 9 part 1 — CVSS scorer + AnalystAgent.

CVSS tests: 12 vectors → score ranges.
Analyst tests: mocked Opus, fixture findings, verify cvss_score IS NOT NULL,
chain propagation, duplicate flagging, TF-IDF backup dedup, bounty clamp.
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
from agents.analyst import (
    AnalystAgent, BOUNTY_TABLE, _cosine_tfidf, _parse_analyst_json,
)
from core import cvss
from db.migrations import runner as MIG


# ═══════════════════════════════════════════════════════════
#  CVSS SCORER
# ═══════════════════════════════════════════════════════════
class TestCVSSParse:

    def test_valid_full_vector(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P"
        m = cvss.parse(v)
        assert m["AV"] == "N" and m["VC"] == "H" and m["E"] == "P"

    def test_omits_optional_threat(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
        m = cvss.parse(v)
        assert m["E"] == "X"   # default

    def test_unknown_metric_rejected(self):
        with pytest.raises(cvss.CVSSError):
            cvss.parse("CVSS:4.0/AV:N/XX:Y/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")

    def test_bad_value_rejected(self):
        with pytest.raises(cvss.CVSSError):
            cvss.parse("CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")

    def test_missing_required_rejected(self):
        with pytest.raises(cvss.CVSSError):
            cvss.parse("CVSS:4.0/AV:N/AC:L")

    def test_non_cvss_string_rejected(self):
        with pytest.raises(cvss.CVSSError):
            cvss.parse("not a cvss vector")

    def test_is_valid(self):
        good = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
        assert cvss.is_valid(good)
        assert not cvss.is_valid("xxx")


class TestCVSSScore:
    # 12 vectors with expected severity bucket. Score is approximated so
    # we assert ranges, not exact values.

    @pytest.mark.parametrize("vector, low, high, sev", [
        # Critical-class (worst case all-N PR, all-H impact)
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
         9.0, 10.0, "Critical"),
        # SSRF → cloud creds, both subsequent impacts
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N/E:P",
         8.0, 10.0, None),
        # Stored XSS in admin — user interaction passive
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P",
         6.5, 8.5, None),
        # IDOR data read — privileges required low
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:P",
         5.0, 7.0, "Medium"),
        # Open redirect — low integrity impact, user interaction required
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:P",
         1.5, 3.0, "Low"),
        # JWT alg=none → catastrophic
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P",
         9.0, 10.0, "Critical"),
        # Local privilege impact (AV:L)
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P",
         4.5, 6.5, "Medium"),
        # No impact = 0
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
         0.0, 0.0, "None"),
        # Unreported E lowers score
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U",
         6.5, 8.5, None),
        # High AC drops exploitability
        ("CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P",
         0.5, 2.5, "Low"),
        # Subsequent impact channel only
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N/E:P",
         3.0, 6.0, None),
        # CIA spread (boost from extra H)
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P",
         8.0, 10.0, None),
    ])
    def test_score_within_range(self, vector, low, high, sev):
        s = cvss.score(vector)
        assert low <= s <= high, f"vector={vector!r} got={s}"
        if sev is not None:
            assert cvss.severity(s) == sev

    def test_score_clamps_to_10(self):
        # Worst-case vector with every booster set
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A"
        assert cvss.score(v) <= 10.0

    def test_severity_buckets(self):
        assert cvss.severity(0.0) == "None"
        assert cvss.severity(3.9) == "Low"
        assert cvss.severity(4.0) == "Medium"
        assert cvss.severity(6.9) == "Medium"
        assert cvss.severity(7.0) == "High"
        assert cvss.severity(8.9) == "High"
        assert cvss.severity(9.0) == "Critical"
        assert cvss.severity(10.0) == "Critical"


# ═══════════════════════════════════════════════════════════
#  TF-IDF dedup
# ═══════════════════════════════════════════════════════════
class TestCosine:

    def test_identical_strings_score_1(self):
        a = "Stored XSS in /profile/bio enables admin session hijacking"
        assert _cosine_tfidf(a, a) == pytest.approx(1.0)

    def test_different_strings_low(self):
        a = "SSRF in webhook reaches IMDS"
        b = "Stored XSS in profile bio"
        assert _cosine_tfidf(a, b) < 0.5

    def test_near_duplicates_high(self):
        a = "Stored XSS in /profile/bio enables admin session hijacking"
        b = "Stored XSS in profile bio admin session hijacking via stored payload"
        assert _cosine_tfidf(a, b) > 0.5


class TestAnalystJsonParse:

    def test_plain(self):
        out = _parse_analyst_json('{"findings": [], "chains": [], "duplicates": []}')
        assert out == {"findings": [], "chains": [], "duplicates": []}

    def test_fenced(self):
        out = _parse_analyst_json('```json\n{"findings": []}\n```')
        assert out == {"findings": []}

    def test_garbage(self):
        assert _parse_analyst_json("hello") is None


# ═══════════════════════════════════════════════════════════
#  AnalystAgent
# ═══════════════════════════════════════════════════════════
@pytest.fixture
def migrated_db(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    MIG.run_pending(conn)
    yield conn
    conn.close()


def _seed_findings(db, job_id, items):
    """items: list of (bug_id, vuln_class, title, description)."""
    db.execute("INSERT OR IGNORE INTO subdomains(domain, subdomain) VALUES('acme.com','www.acme.com')")
    sid = db.execute(
        "SELECT id FROM subdomains WHERE subdomain='www.acme.com'"
    ).fetchone()[0]
    ids = []
    for bug_id, vc, title, desc in items:
        cur = db.execute(
            "INSERT INTO findings(bug_id, job_id, domain, subdomain_id, "
            "vuln_class, title, description, evidence_json, confidence, status) "
            "VALUES (?,?,?,?,?,?,?,?,?,'new')",
            (bug_id, job_id, "acme.com", sid, vc, title, desc, "{}", 0.7),
        )
        ids.append(cur.lastrowid)
    db.commit()
    return ids


def _mocked_llm(content_dict, ptok=1000, ctok=500):
    return {
        "content": json.dumps(content_dict),
        "tool_calls": [], "prompt_tokens": ptok,
        "completion_tokens": ctok, "cost_usd": 0.1, "model": "mock-opus",
    }


class TestAnalystRun:

    def test_scores_all_findings(self, migrated_db):
        _seed_findings(migrated_db, "J", [
            ("BUG-001", "ssrf", "SSRF in webhook",
             "Server fetches user URL → IMDS"),
            ("BUG-002", "idor", "Numeric IDOR in /api/users",
             "PR:L, data exposure"),
        ])
        llm_out = {
            "findings": [
                {"bug_id": "BUG-001",
                 "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N/E:P",
                 "bounty_estimate_usd": 7500, "rationale_short": "ssrf imds"},
                {"bug_id": "BUG-002",
                 "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:P",
                 "bounty_estimate_usd": 2000, "rationale_short": "idor read"},
            ],
            "chains": [], "duplicates": [],
        }
        ctx = AgentContext(job_id="J", db=migrated_db,
                            program={"name": "acme", "platform": "h1"})
        with patch.object(AnalystAgent, "call_llm", return_value=_mocked_llm(llm_out)):
            result = AnalystAgent(db=migrated_db).run(ctx)
        assert result.success
        rows = migrated_db.execute(
            "SELECT cvss_vector, cvss_score, bounty_estimate_usd FROM findings ORDER BY id"
        ).fetchall()
        assert all(r["cvss_score"] is not None and r["cvss_score"] > 0 for r in rows)
        assert all(r["cvss_vector"] is not None for r in rows)

    def test_invalid_vector_rejected(self, migrated_db):
        _seed_findings(migrated_db, "J", [("BUG-001", "ssrf", "x", "y")])
        llm_out = {
            "findings": [{"bug_id": "BUG-001",
                          "cvss_vector": "garbage", "bounty_estimate_usd": 5000}],
            "chains": [], "duplicates": [],
        }
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme"})
        with patch.object(AnalystAgent, "call_llm", return_value=_mocked_llm(llm_out)):
            result = AnalystAgent(db=migrated_db).run(ctx)
        # CVSS score stays NULL for the rejected finding; rejected list captures it.
        assert result.success
        assert "BUG-001" in result.output["rejected_vectors"][0]

    def test_chain_parent_applied(self, migrated_db):
        ids = _seed_findings(migrated_db, "J", [
            ("BUG-A", "ssrf", "A", "ssrf"),
            ("BUG-B", "idor", "B", "idor"),
        ])
        v_ok = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P"
        llm_out = {
            "findings": [
                {"bug_id": "BUG-A", "cvss_vector": v_ok, "bounty_estimate_usd": 1000},
                {"bug_id": "BUG-B", "cvss_vector": v_ok, "bounty_estimate_usd": 1000},
            ],
            "chains": [{"parent_bug_id": "BUG-A", "child_bug_ids": ["BUG-B"]}],
            "duplicates": [],
        }
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme"})
        with patch.object(AnalystAgent, "call_llm", return_value=_mocked_llm(llm_out)):
            AnalystAgent(db=migrated_db).run(ctx)
        b_row = migrated_db.execute(
            "SELECT parent_finding_id FROM findings WHERE bug_id='BUG-B'"
        ).fetchone()
        assert b_row["parent_finding_id"] == ids[0]

    def test_duplicate_marked(self, migrated_db):
        _seed_findings(migrated_db, "J", [
            ("BUG-A", "xss", "Stored XSS in /bio", "stored payload via bio field"),
            ("BUG-B", "xss", "Stored XSS via /bio",
             "stored payload through bio field — identical"),
        ])
        v_ok = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P"
        llm_out = {
            "findings": [
                {"bug_id": "BUG-A", "cvss_vector": v_ok, "bounty_estimate_usd": 2000},
                {"bug_id": "BUG-B", "cvss_vector": v_ok, "bounty_estimate_usd": 2000},
            ],
            "chains": [],
            "duplicates": [{"canonical_bug_id": "BUG-A",
                            "duplicate_bug_ids": ["BUG-B"]}],
        }
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme"})
        with patch.object(AnalystAgent, "call_llm", return_value=_mocked_llm(llm_out)):
            AnalystAgent(db=migrated_db).run(ctx)
        b_status = migrated_db.execute(
            "SELECT status FROM findings WHERE bug_id='BUG-B'"
        ).fetchone()["status"]
        assert b_status == "dup"

    def test_tfidf_dedup_catches_llm_miss(self, migrated_db):
        _seed_findings(migrated_db, "J", [
            ("BUG-A", "xss", "Stored XSS in profile bio admin session hijacking",
             "stored xss profile bio admin"),
            ("BUG-B", "xss", "Stored XSS in profile bio admin session hijacking",
             "stored xss profile bio admin"),
        ])
        v_ok = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P"
        llm_out = {
            "findings": [
                {"bug_id": "BUG-A", "cvss_vector": v_ok, "bounty_estimate_usd": 2000},
                {"bug_id": "BUG-B", "cvss_vector": v_ok, "bounty_estimate_usd": 2000},
            ],
            "chains": [], "duplicates": [],   # LLM missed it
        }
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme"})
        with patch.object(AnalystAgent, "call_llm", return_value=_mocked_llm(llm_out)):
            result = AnalystAgent(db=migrated_db).run(ctx)
        assert result.output["duplicates_marked"] >= 1

    def test_bounty_clamped_to_class_range(self, migrated_db):
        _seed_findings(migrated_db, "J", [
            ("BUG-A", "takeover", "Subdomain takeover", "github.io dangling"),
        ])
        v_ok = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:P"
        # LLM hallucinates a $100k bounty for a takeover (class high = $2k)
        llm_out = {
            "findings": [{"bug_id": "BUG-A", "cvss_vector": v_ok,
                          "bounty_estimate_usd": 100_000}],
            "chains": [], "duplicates": [],
        }
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme"})
        with patch.object(AnalystAgent, "call_llm", return_value=_mocked_llm(llm_out)):
            AnalystAgent(db=migrated_db).run(ctx)
        bounty = migrated_db.execute(
            "SELECT bounty_estimate_usd FROM findings WHERE bug_id='BUG-A'"
        ).fetchone()[0]
        high = BOUNTY_TABLE["takeover"][2]
        assert bounty <= high * 2

    def test_no_findings_fails(self, migrated_db):
        ctx = AgentContext(job_id="J", db=migrated_db)
        result = AnalystAgent(db=migrated_db).run(ctx)
        assert result.success is False
        assert "no findings" in result.error

    def test_summary_persisted(self, migrated_db):
        _seed_findings(migrated_db, "J", [("BUG-001", "ssrf", "x", "y")])
        v_ok = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P"
        llm_out = {
            "findings": [{"bug_id": "BUG-001", "cvss_vector": v_ok,
                          "bounty_estimate_usd": 5000}],
            "chains": [], "duplicates": [],
        }
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme"})
        with patch.object(AnalystAgent, "call_llm", return_value=_mocked_llm(llm_out)):
            agent = AnalystAgent(db=migrated_db)
            agent.run(ctx)
            recalled = agent.recall(ctx, "analyst_summary")
        assert recalled["findings_scored"] == 1
