"""
Phase 8 tests — HunterAgent + 8 playbooks.

All LLM calls are mocked. The deterministic takeover playbook needs no
mock. For each LLM playbook we verify:
  - it runs when the relevant signal is present
  - parsed candidates are written to findings with a bug_id
  - attack_techniques rows are auto-populated
  - confidence threshold drops low-conf candidates
  - evidence-validation drops candidates referencing non-existent subdomain_ids
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
from agents.hunter import (
    HunterAgent, FindingCandidate, PLAYBOOKS, TAKEOVER_FINGERPRINTS,
    select_playbooks, _parse_findings_json, _coerce_candidate,
)
from db.migrations import runner as MIG


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


def _seed_subs(db, domain, rows):
    """Insert subdomain rows. Each row: (subdomain, status, title, tech, ips)."""
    ids = []
    for sub, status, title, tech, ips in rows:
        cur = db.execute(
            "INSERT INTO subdomains(domain, subdomain, http_status, http_title, "
            "http_technologies, ip_addresses, dns_resolved) "
            "VALUES (?,?,?,?,?,?,1)",
            (domain, sub, status, title, json.dumps(tech), json.dumps(ips)),
        )
        ids.append(cur.lastrowid)
    db.commit()
    return ids


def _seed_recon(db, job_id, domain, signals=None, live_hosts=2):
    db.execute(
        "INSERT INTO agent_memory(job_id, agent, key, value_json, created_at, updated_at) "
        "VALUES (?,?,?,?,datetime('now'),datetime('now'))",
        (job_id, "recon", "recon_summary",
         json.dumps({
             "domain": domain,
             "signals": signals or {
                 "graphql_endpoints": [], "admin_panels": [], "login_pages": [],
                 "swagger_specs": [], "s3_buckets": [], "tech_stack": {},
                 "waf": None, "cdn": None, "cloud_provider": None,
             },
             "live_hosts": live_hosts,
             "subdomains_found": live_hosts + 2,
             "tools_used": ["subfinder", "httpx"],
         })),
    )
    db.commit()


@pytest.fixture
def ctx_with_recon(migrated_db):
    domain = "acme.com"
    ids = _seed_subs(migrated_db, domain, [
        ("api.acme.com", 200, "API",         ["express"], ["10.0.0.1"]),
        ("admin.acme.com", 200, "Admin",     ["nginx"],   ["10.0.0.2"]),
        ("www.acme.com", 200, "Acme Home",   ["nginx"],   ["10.0.0.3"]),
    ])
    _seed_recon(migrated_db, "J-HUNT", domain, signals={
        "graphql_endpoints": ["https://api.acme.com/graphql"],
        "admin_panels":      ["https://admin.acme.com/"],
        "login_pages":       ["https://acme.com/login"],
        "swagger_specs":     ["https://api.acme.com/swagger.json"],
        "s3_buckets":        [], "gcs_buckets": [], "azure_blobs": [],
        "tech_stack":        {"express": 2, "nginx": 1},
        "waf": None, "cdn": None, "cloud_provider": "aws",
        "interesting_urls": [],
    })
    ctx = AgentContext(job_id="J-HUNT", db=migrated_db, program={"name": domain})
    ctx._sub_ids = ids
    return ctx


def _mock_llm(content, ptok=400, ctok=200):
    return {
        "content": content, "tool_calls": [],
        "prompt_tokens": ptok, "completion_tokens": ctok,
        "cost_usd": 0.01, "model": "mock-haiku",
    }


def _llm_returning(findings_list):
    """Build a call_llm mock that always returns the given findings as JSON."""
    return lambda *a, **kw: _mock_llm(json.dumps(findings_list))


# ═══════════════════════════════════════════════════════════
#  PARSING
# ═══════════════════════════════════════════════════════════
class TestParseFindings:

    def test_plain_array(self):
        out = _parse_findings_json('[{"title":"x"}]')
        assert out == [{"title": "x"}]

    def test_fenced(self):
        out = _parse_findings_json('```json\n[{"title":"x"}]\n```')
        assert out == [{"title": "x"}]

    def test_single_object_wrapped(self):
        out = _parse_findings_json('{"title":"x"}')
        assert out == [{"title": "x"}]

    def test_garbage(self):
        assert _parse_findings_json("oops") is None
        assert _parse_findings_json("") is None

    def test_coerce_clamps_confidence(self):
        c = _coerce_candidate({"title": "t", "confidence": 5.0}, "idor", "idor")
        assert c.confidence == 1.0
        c = _coerce_candidate({"title": "t", "confidence": -0.5}, "idor", "idor")
        assert c.confidence == 0.0


# ═══════════════════════════════════════════════════════════
#  PLAYBOOK SELECTION
# ═══════════════════════════════════════════════════════════
class TestSelectPlaybooks:

    def test_no_signals_only_takeover(self):
        recon = {"signals": {}, "live_hosts": 0}
        assert select_playbooks(recon) == ["takeover"]

    def test_graphql_signal_adds_graphql(self):
        recon = {"signals": {"graphql_endpoints": ["x"]}, "live_hosts": 1}
        assert "graphql" in select_playbooks(recon)

    def test_login_signal_adds_jwt(self):
        recon = {"signals": {"login_pages": ["x"]}, "live_hosts": 1}
        assert "jwt" in select_playbooks(recon)

    def test_live_hosts_adds_general_set(self):
        recon = {"signals": {}, "live_hosts": 3}
        playbooks = select_playbooks(recon)
        for pb in ("idor", "ssrf", "xss", "bizlogic", "api_misconfig"):
            assert pb in playbooks

    def test_dedup(self):
        recon = {"signals": {"graphql_endpoints": ["x"], "login_pages": ["y"]},
                 "live_hosts": 1}
        out = select_playbooks(recon)
        assert len(out) == len(set(out))


# ═══════════════════════════════════════════════════════════
#  TAKEOVER (deterministic — no LLM)
# ═══════════════════════════════════════════════════════════
class TestTakeover:

    def test_github_pages_signature(self, migrated_db):
        _seed_subs(migrated_db, "acme.com", [
            ("blog.acme.com", 404,
             "There isn't a GitHub Pages site here.",
             [], ["blog-acme.github.io"]),
        ])
        _seed_recon(migrated_db, "J", "acme.com")
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme.com"})
        agent = HunterAgent(db=migrated_db)
        result = agent.run(ctx)
        assert result.success
        rows = migrated_db.execute(
            "SELECT * FROM findings WHERE vuln_class='takeover'"
        ).fetchall()
        assert len(rows) == 1
        assert "github_pages" in rows[0]["title"]
        assert rows[0]["confidence"] >= 0.90  # cname + title match

    def test_aws_s3_signature(self, migrated_db):
        _seed_subs(migrated_db, "acme.com", [
            ("assets.acme.com", 404, "NoSuchBucket - The specified bucket does not exist",
             [], ["acme-uploads.s3.amazonaws.com"]),
        ])
        _seed_recon(migrated_db, "J", "acme.com")
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme.com"})
        agent = HunterAgent(db=migrated_db)
        agent.run(ctx)
        rows = migrated_db.execute(
            "SELECT * FROM findings WHERE vuln_class='takeover'"
        ).fetchall()
        assert len(rows) == 1
        assert "aws_s3" in rows[0]["title"]

    def test_title_only_lowers_confidence(self, migrated_db):
        # No CNAME match — should still flag, but at confidence - 0.20.
        _seed_subs(migrated_db, "acme.com", [
            ("blog.acme.com", 404,
             "There isn't a GitHub Pages site here.",
             [], []),
        ])
        _seed_recon(migrated_db, "J", "acme.com")
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme.com"})
        agent = HunterAgent(db=migrated_db)
        agent.run(ctx)
        rows = migrated_db.execute(
            "SELECT confidence FROM findings WHERE vuln_class='takeover'"
        ).fetchall()
        assert rows[0]["confidence"] < 0.85
        assert rows[0]["confidence"] >= 0.40  # still above threshold

    def test_no_takeover_no_finding(self, migrated_db):
        _seed_subs(migrated_db, "acme.com", [
            ("api.acme.com", 200, "API", [], ["10.0.0.1"]),
        ])
        _seed_recon(migrated_db, "J", "acme.com")
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme.com"})
        agent = HunterAgent(db=migrated_db)
        result = agent.run(ctx)
        assert result.success
        assert result.output["findings_count"] == 0

    def test_attack_techniques_populated(self, migrated_db):
        _seed_subs(migrated_db, "acme.com", [
            ("blog.acme.com", 404, "There isn't a GitHub Pages site here.",
             [], ["blog-acme.github.io"]),
        ])
        _seed_recon(migrated_db, "J", "acme.com")
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme.com"})
        HunterAgent(db=migrated_db).run(ctx)
        techs = migrated_db.execute(
            "SELECT technique_id FROM attack_techniques"
        ).fetchall()
        ids = {r["technique_id"] for r in techs}
        # mapper's takeover rule maps to T1583, T1071, T1566 + keyword boosts
        assert "T1583" in ids


# ═══════════════════════════════════════════════════════════
#  LLM-DRIVEN PLAYBOOKS
# ═══════════════════════════════════════════════════════════
class TestLLMPlaybooks:

    def _candidate(self, ctx, vuln_class, title="Test finding", conf=0.7,
                   sid=None, **evi):
        """Build a JSON-compatible finding dict the playbook LLM would return."""
        if sid is None:
            sid = ctx._sub_ids[0]
        return {
            "vuln_class": vuln_class,
            "title": title,
            "description": "test description",
            "confidence": conf,
            "evidence": {"subdomain_id": sid, **evi},
        }

    def test_graphql_playbook_writes_finding(self, ctx_with_recon):
        ctx = ctx_with_recon
        # Restrict to only the graphql playbook by zeroing other signals.
        # Easier: patch select_playbooks for this test.
        cand = self._candidate(ctx, "graphql", title="GraphQL introspection on api.acme.com")
        with patch("agents.hunter.select_playbooks", return_value=["graphql"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([cand])):
            HunterAgent(db=ctx.db).run(ctx)
        rows = ctx.db.execute(
            "SELECT * FROM findings WHERE vuln_class='graphql'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["bug_id"].startswith("BUG-")

    def test_idor_playbook(self, ctx_with_recon):
        ctx = ctx_with_recon
        cand = self._candidate(ctx, "idor", title="Numeric IDOR in /api/users/{id}")
        with patch("agents.hunter.select_playbooks", return_value=["idor"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([cand])):
            HunterAgent(db=ctx.db).run(ctx)
        assert ctx.db.execute("SELECT COUNT(*) FROM findings "
                              "WHERE vuln_class='idor'").fetchone()[0] == 1

    def test_ssrf_playbook(self, ctx_with_recon):
        ctx = ctx_with_recon
        cand = self._candidate(ctx, "ssrf", title="SSRF in image fetcher",
                               cloud_signal="aws")
        with patch("agents.hunter.select_playbooks", return_value=["ssrf"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([cand])):
            HunterAgent(db=ctx.db).run(ctx)
        assert ctx.db.execute("SELECT COUNT(*) FROM findings "
                              "WHERE vuln_class='ssrf'").fetchone()[0] == 1

    def test_xss_playbook(self, ctx_with_recon):
        ctx = ctx_with_recon
        cand = self._candidate(ctx, "xss", title="Stored XSS in /profile/bio",
                               xss_type="stored", admin_visible=True)
        with patch("agents.hunter.select_playbooks", return_value=["xss"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([cand])):
            HunterAgent(db=ctx.db).run(ctx)
        assert ctx.db.execute("SELECT COUNT(*) FROM findings "
                              "WHERE vuln_class='xss'").fetchone()[0] == 1

    def test_jwt_playbook(self, ctx_with_recon):
        ctx = ctx_with_recon
        cand = self._candidate(ctx, "jwt", title="alg=none accepted",
                               attack_subtype="alg_none")
        with patch("agents.hunter.select_playbooks", return_value=["jwt"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([cand])):
            HunterAgent(db=ctx.db).run(ctx)
        assert ctx.db.execute("SELECT COUNT(*) FROM findings "
                              "WHERE vuln_class='jwt'").fetchone()[0] == 1

    def test_bizlogic_playbook(self, ctx_with_recon):
        ctx = ctx_with_recon
        cand = self._candidate(ctx, "bizlogic",
                                title="Negative-quantity bypass in checkout",
                                manipulation_type="negative_value")
        with patch("agents.hunter.select_playbooks", return_value=["bizlogic"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([cand])):
            HunterAgent(db=ctx.db).run(ctx)
        assert ctx.db.execute("SELECT COUNT(*) FROM findings "
                              "WHERE vuln_class='bizlogic'").fetchone()[0] == 1

    def test_api_misconfig_playbook(self, ctx_with_recon):
        ctx = ctx_with_recon
        cand = self._candidate(ctx, "api_misconfig",
                                title="Mass-assignment in /api/users",
                                misconfig_type="mass_assignment")
        with patch("agents.hunter.select_playbooks", return_value=["api_misconfig"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([cand])):
            HunterAgent(db=ctx.db).run(ctx)
        assert ctx.db.execute("SELECT COUNT(*) FROM findings "
                              "WHERE vuln_class='api_misconfig'").fetchone()[0] == 1


# ═══════════════════════════════════════════════════════════
#  CONFIDENCE GATE + EVIDENCE GUARD
# ═══════════════════════════════════════════════════════════
class TestGates:

    def test_low_confidence_dropped(self, ctx_with_recon):
        ctx = ctx_with_recon
        low = {"vuln_class": "idor", "title": "borderline",
               "description": "x", "confidence": 0.30,
               "evidence": {"subdomain_id": ctx._sub_ids[0]}}
        with patch("agents.hunter.select_playbooks", return_value=["idor"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([low])):
            result = HunterAgent(db=ctx.db).run(ctx)
        assert result.output["findings_count"] == 0
        assert result.output["dropped_low_conf"] == 1

    def test_evidence_missing_subdomain_id_dropped(self, ctx_with_recon):
        ctx = ctx_with_recon
        bad = {"vuln_class": "idor", "title": "no sid", "description": "x",
               "confidence": 0.9, "evidence": {}}
        with patch("agents.hunter.select_playbooks", return_value=["idor"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([bad])):
            result = HunterAgent(db=ctx.db).run(ctx)
        assert result.output["findings_count"] == 0
        assert result.output["dropped_bad_evidence"] == 1

    def test_evidence_phantom_subdomain_id_dropped(self, ctx_with_recon):
        ctx = ctx_with_recon
        # 999_999 doesn't exist in subdomains.
        bad = {"vuln_class": "idor", "title": "hallucinated host",
               "description": "x", "confidence": 0.9,
               "evidence": {"subdomain_id": 999_999}}
        with patch("agents.hunter.select_playbooks", return_value=["idor"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([bad])):
            result = HunterAgent(db=ctx.db).run(ctx)
        assert result.output["dropped_bad_evidence"] == 1


# ═══════════════════════════════════════════════════════════
#  BUG_ID SEQUENCING + ATT&CK PERSIST
# ═══════════════════════════════════════════════════════════
class TestPersistence:

    def test_bug_ids_increment(self, ctx_with_recon):
        ctx = ctx_with_recon
        cands = [
            {"vuln_class": "idor", "title": "A", "description": "", "confidence": 0.7,
             "evidence": {"subdomain_id": ctx._sub_ids[0]}},
            {"vuln_class": "idor", "title": "B", "description": "", "confidence": 0.7,
             "evidence": {"subdomain_id": ctx._sub_ids[1]}},
        ]
        with patch("agents.hunter.select_playbooks", return_value=["idor"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning(cands)):
            result = HunterAgent(db=ctx.db).run(ctx)
        bug_ids = result.output["bug_ids"]
        assert len(bug_ids) == 2
        assert bug_ids[0].endswith("-001")
        assert bug_ids[1].endswith("-002")

    def test_attack_techniques_per_finding(self, ctx_with_recon):
        ctx = ctx_with_recon
        cand = {"vuln_class": "ssrf",
                "title": "SSRF reaches 169.254.169.254 IMDS",
                "description": "Server fetches user URL",
                "confidence": 0.85,
                "evidence": {"subdomain_id": ctx._sub_ids[0]}}
        with patch("agents.hunter.select_playbooks", return_value=["ssrf"]), \
             patch.object(HunterAgent, "call_llm",
                          side_effect=_llm_returning([cand])):
            HunterAgent(db=ctx.db).run(ctx)
        techs = ctx.db.execute(
            "SELECT technique_id FROM attack_techniques"
        ).fetchall()
        ids = {r["technique_id"] for r in techs}
        # SSRF rules: T1190 + T1090 + T1552.005 (sub) → mapper canonicalizes
        assert "T1190" in ids
        # IMDS keyword should add T1552 family
        assert any(t.startswith("T1552") for t in ids)


# ═══════════════════════════════════════════════════════════
#  RUN-LEVEL CONTRACTS
# ═══════════════════════════════════════════════════════════
class TestRunContracts:

    def test_no_recon_summary(self, migrated_db):
        ctx = AgentContext(job_id="J", db=migrated_db, program={"name": "acme.com"})
        result = HunterAgent(db=migrated_db).run(ctx)
        assert result.success is False
        assert "recon_summary" in result.error

    def test_summary_persisted_to_memory(self, ctx_with_recon):
        ctx = ctx_with_recon
        with patch("agents.hunter.select_playbooks", return_value=["takeover"]):
            agent = HunterAgent(db=ctx.db)
            agent.run(ctx)
            recalled = agent.recall(ctx, "findings_summary")
        assert recalled is not None
        assert "playbooks_run" in recalled

    def test_emits_start_and_complete(self, ctx_with_recon):
        ctx = ctx_with_recon
        captured = []
        with patch("agents.hunter.select_playbooks", return_value=["takeover"]):
            agent = HunterAgent(db=ctx.db,
                                emit_fn=lambda k, d: captured.append((k, d)))
            agent.run(ctx)
        kinds = [k for k, _ in captured]
        assert "hunter.start" in kinds
        assert "hunter.complete" in kinds

    def test_llm_failure_is_isolated(self, ctx_with_recon):
        """If one playbook fails, hunter continues with others."""
        from agents.base import LLMError
        ctx = ctx_with_recon
        def call(system, messages, **kw):
            # idor playbook fails, ssrf returns one good finding
            if "IDOR" in system:
                raise LLMError("simulated")
            cand = {"vuln_class": "ssrf", "title": "ok",
                    "description": "", "confidence": 0.8,
                    "evidence": {"subdomain_id": ctx._sub_ids[0]}}
            return _mock_llm(json.dumps([cand]))
        with patch("agents.hunter.select_playbooks", return_value=["idor", "ssrf"]), \
             patch.object(HunterAgent, "call_llm", side_effect=call):
            result = HunterAgent(db=ctx.db).run(ctx)
        assert result.success is True
        assert result.output["findings_count"] == 1
        assert result.output["by_class"].get("ssrf") == 1


# ═══════════════════════════════════════════════════════════
#  PROMPT FILES EXIST
# ═══════════════════════════════════════════════════════════
class TestPromptFiles:

    @pytest.mark.parametrize("name", [
        "idor", "ssrf", "graphql", "xss", "jwt", "bizlogic", "api_misconfig",
    ])
    def test_prompt_exists_and_nonempty(self, name):
        path = ROOT / "agents" / "playbooks" / f"{name}.md"
        assert path.exists()
        body = path.read_text(encoding="utf-8")
        assert len(body) > 200
        assert "Output format" in body or "Output" in body

    def test_takeover_prompt_is_documentation(self):
        path = ROOT / "agents" / "playbooks" / "takeover.md"
        assert path.exists()
        # Takeover doc explicitly notes its deterministic nature.
        assert "deterministic" in path.read_text(encoding="utf-8").lower()
