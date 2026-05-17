"""Phase 14 — Evidence labels, CWE/OWASP taxonomy, tool health.

Covers:
  * Migration 006: finding_evidence + finding_taxonomy tables, completed_jobs.mode.
  * core.evidence: record/list/verify, immutability of observed/inferred,
    per-playbook source classification, report readiness.
  * attack.taxonomy: VULN_CLASS_TAXONOMY lookup + persist_taxonomy_for_finding.
  * api.routes: finding_evidence_list + finding_evidence_verify, tool_health
    caching, tool_install_plan shape.
  * api.server.dispatch routes for every Phase 14 endpoint.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core import evidence as E
from attack import taxonomy as T
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
def finding(db):
    db.execute(
        "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, status) "
        "VALUES ('BUG-001','J1','acme.com','ssrf','SSRF in /api/fetch','new')"
    )
    db.commit()
    return db.execute("SELECT id FROM findings WHERE bug_id='BUG-001'").fetchone()[0]


# ── migration 006 ────────────────────────────────────────────────
class TestMigration006:

    def test_finding_evidence_table_exists(self, db):
        row = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='finding_evidence'"
        ).fetchone()
        assert row is not None

    def test_finding_taxonomy_table_exists(self, db):
        row = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='finding_taxonomy'"
        ).fetchone()
        assert row is not None

    def test_completed_jobs_mode_column(self, db):
        cols = [r["name"] for r in db.execute(
            "PRAGMA table_info(completed_jobs)"
        ).fetchall()]
        assert "mode" in cols

    def test_source_check_constraint(self, db, finding):
        # CHECK constraint should reject unknown source values.
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO finding_evidence(finding_id, key, value, source) "
                "VALUES (?,?,?,?)", (finding, "k", "v", "bogus"),
            )
            db.commit()

    def test_re_run_is_idempotent(self, db):
        import importlib
        mod = importlib.import_module("db.migrations.006_evidence_modes_taxonomy")
        mod.up(db)  # second call should not raise


# ── core.evidence ────────────────────────────────────────────────
class TestRecord:

    def test_record_observed(self, db, finding):
        eid = E.record_evidence(db, finding, "http_status", 200, "observed",
                                 source_ref="subdomains:42")
        ev = E.get_evidence(db, eid)
        assert ev.source == "observed"
        assert ev.source_ref == "subdomains:42"
        assert ev.to_dict()["value"] == 200  # JSON round-trips back to int

    def test_record_invalid_source(self, db, finding):
        with pytest.raises(ValueError, match="invalid source"):
            E.record_evidence(db, finding, "k", "v", "bogus")

    def test_dict_value_roundtrip(self, db, finding):
        payload = {"endpoint": "/webhook", "params": ["url"]}
        eid = E.record_evidence(db, finding, "request", payload, "ai_hypothesis")
        assert E.get_evidence(db, eid).to_dict()["value"] == payload

    def test_string_value_kept_as_string(self, db, finding):
        eid = E.record_evidence(db, finding, "host", "api.acme.com", "observed")
        assert E.get_evidence(db, eid).to_dict()["value"] == "api.acme.com"


class TestClassification:

    def test_takeover_field_specific_sources(self):
        assert E.classify_source("takeover", "subdomain_id") == "observed"
        assert E.classify_source("takeover", "title")        == "observed"
        assert E.classify_source("takeover", "service")      == "inferred"
        assert E.classify_source("takeover", "cname_matched") == "inferred"

    def test_takeover_unknown_key_defaults_to_inferred(self):
        assert E.classify_source("takeover", "random_field") == "inferred"

    def test_llm_playbooks_default_ai_hypothesis(self):
        for pb in ("ssrf", "idor", "graphql", "xss", "jwt"):
            assert E.classify_source(pb, "anything") == "ai_hypothesis"


class TestRecordDict:

    def test_takeover_writes_observed_and_inferred(self, db, finding):
        ids = E.record_evidence_dict(
            db, finding,
            evidence={"subdomain_id": 1, "service": "github_pages",
                       "http_status": 404, "cname_matched": True},
            playbook="takeover",
        )
        assert len(ids) == 4
        grouped = E.list_evidence(db, finding)
        sources = {row["key"]: row["source"] for rows in grouped.values()
                                              for row in rows}
        assert sources["subdomain_id"] == "observed"
        assert sources["http_status"]   == "observed"
        assert sources["service"]       == "inferred"
        assert sources["cname_matched"] == "inferred"

    def test_ssrf_writes_all_ai_hypothesis(self, db, finding):
        E.record_evidence_dict(
            db, finding,
            evidence={"endpoint": "/webhook", "subdomain_id": 1},
            playbook="ssrf",
        )
        grouped = E.list_evidence(db, finding)
        assert grouped["ai_hypothesis"] and not grouped["observed"]

    def test_empty_dict_noop(self, db, finding):
        assert E.record_evidence_dict(db, finding, {}, playbook="ssrf") == []


class TestVerify:

    def test_promote_ai_hypothesis(self, db, finding):
        eid = E.record_evidence(db, finding, "guess", "x", "ai_hypothesis")
        updated = E.verify_evidence(db, eid, "grover")
        assert updated.source == "verified"
        assert updated.verified_by == "grover"
        assert updated.verified_at  # set

    def test_observed_is_immutable(self, db, finding):
        eid = E.record_evidence(db, finding, "k", "v", "observed")
        with pytest.raises(E.EvidenceImmutable):
            E.verify_evidence(db, eid, "grover")

    def test_inferred_is_immutable(self, db, finding):
        eid = E.record_evidence(db, finding, "k", "v", "inferred")
        with pytest.raises(E.EvidenceImmutable):
            E.verify_evidence(db, eid, "grover")

    def test_verified_is_idempotent(self, db, finding):
        eid = E.record_evidence(db, finding, "k", "v", "ai_hypothesis")
        first = E.verify_evidence(db, eid, "a")
        again = E.verify_evidence(db, eid, "b")
        assert first.verified_by == "a"
        assert again.verified_by == "a"  # second call did not overwrite

    def test_missing_id_raises(self, db):
        with pytest.raises(ValueError, match="not found"):
            E.verify_evidence(db, 9999, "x")


class TestListEvidence:

    def test_groups_always_have_all_four_keys(self, db, finding):
        grouped = E.list_evidence(db, finding)
        assert set(grouped.keys()) == set(E.VALID_SOURCES)
        assert all(isinstance(v, list) for v in grouped.values())


class TestReadiness:

    def test_required_fields_missing(self, db, finding):
        E.record_evidence(db, finding, "endpoint", "/foo", "ai_hypothesis")
        readiness = E.report_readiness(E.list_evidence(db, finding))
        assert readiness["affected_url"] is False
        assert readiness["impact"]        is False

    def test_required_fields_present(self, db, finding):
        for k in ("affected_url", "reproduction_steps", "impact",
                  "remediation", "screenshot_main"):
            E.record_evidence(db, finding, k, "x", "ai_hypothesis")
        readiness = E.report_readiness(E.list_evidence(db, finding))
        assert readiness["affected_url"]       is True
        assert readiness["reproduction_steps"] is True
        assert readiness["screenshot"]         is True  # matched by substring


# ── attack.taxonomy CWE/OWASP ────────────────────────────────────
class TestVulnClassTaxonomy:

    def test_ssrf_lookup(self):
        entries = T.lookup_taxonomy("ssrf")
        kinds = {kind for kind, _, _ in entries}
        codes = {code for _, code, _ in entries}
        assert kinds == {"cwe", "owasp"}
        assert "CWE-918" in codes
        assert "A10:2021" in codes

    def test_idor_includes_broken_access_control(self):
        codes = {code for _, code, _ in T.lookup_taxonomy("idor")}
        assert "A01:2021" in codes

    def test_unknown_class_returns_empty(self):
        assert T.lookup_taxonomy("nope") == []

    def test_case_insensitive(self):
        assert T.lookup_taxonomy("SSRF") == T.lookup_taxonomy("ssrf")

    def test_persist_writes_rows(self, db, finding):
        entries = T.persist_taxonomy_for_finding(db, finding, "ssrf")
        db.commit()
        rows = db.execute(
            "SELECT code, taxonomy FROM finding_taxonomy WHERE finding_id=?",
            (finding,),
        ).fetchall()
        assert len(rows) == len(entries)
        assert {r["code"] for r in rows} == {code for _, code, _ in entries}

    def test_persist_is_idempotent(self, db, finding):
        T.persist_taxonomy_for_finding(db, finding, "ssrf")
        T.persist_taxonomy_for_finding(db, finding, "ssrf")
        db.commit()
        count = db.execute(
            "SELECT COUNT(*) FROM finding_taxonomy WHERE finding_id=?",
            (finding,),
        ).fetchone()[0]
        assert count == len(T.lookup_taxonomy("ssrf"))

    def test_persist_does_not_touch_attack_rows(self, db, finding):
        db.execute(
            "INSERT INTO finding_taxonomy(finding_id, taxonomy, code, name) "
            "VALUES (?, 'attack', 'T1190', 'Exploit Public-Facing App')",
            (finding,),
        )
        T.persist_taxonomy_for_finding(db, finding, "ssrf")
        attack_count = db.execute(
            "SELECT COUNT(*) FROM finding_taxonomy "
            "WHERE finding_id=? AND taxonomy='attack'", (finding,),
        ).fetchone()[0]
        assert attack_count == 1


# ── api.routes evidence endpoints ────────────────────────────────
class TestEvidenceRoutes:

    def test_list_includes_grouped_and_taxonomy(self, db, finding):
        E.record_evidence(db, finding, "endpoint", "/x", "ai_hypothesis")
        T.persist_taxonomy_for_finding(db, finding, "ssrf")
        db.commit()
        out = routes.finding_evidence_list(db, finding)
        assert out["vuln_class"] == "ssrf"
        assert out["evidence"]["ai_hypothesis"]
        assert any(t["code"] == "CWE-918" for t in out["taxonomy"])
        assert "readiness" in out

    def test_list_missing_finding(self, db):
        assert routes.finding_evidence_list(db, 99999) is None

    def test_verify_route_ok(self, db, finding):
        eid = E.record_evidence(db, finding, "x", "y", "ai_hypothesis")
        out = routes.finding_evidence_verify(db, finding, eid, "grover")
        assert out["ok"] is True
        assert out["evidence"]["source"] == "verified"

    def test_verify_route_mismatched_finding(self, db, finding):
        # Insert a second finding + evidence for it, then try to verify it
        # via the first finding's URL.
        db.execute(
            "INSERT INTO findings(bug_id, job_id, domain, vuln_class, title, status) "
            "VALUES ('BUG-002','J1','acme.com','xss','x','new')"
        )
        db.commit()
        fid2 = db.execute(
            "SELECT id FROM findings WHERE bug_id='BUG-002'"
        ).fetchone()[0]
        eid = E.record_evidence(db, fid2, "x", "y", "ai_hypothesis")
        out = routes.finding_evidence_verify(db, finding, eid, "grover")
        assert out["ok"] is False
        assert "does not belong" in out["error"]

    def test_verify_route_immutable(self, db, finding):
        eid = E.record_evidence(db, finding, "x", "y", "observed")
        out = routes.finding_evidence_verify(db, finding, eid, "grover")
        assert out["ok"] is False


# ── api.routes tool_health (cached) ──────────────────────────────
class TestToolHealth:

    def test_payload_shape(self):
        # Force refresh so the cache from a previous test doesn't mask shape bugs.
        out = routes.tool_health(refresh=True)
        assert "tools" in out and "summary" in out
        assert isinstance(out["tools"], list)
        assert out["summary"]["total"] == len(out["tools"])

    def test_cached_payload_returns_same_object(self):
        a = routes.tool_health(refresh=True)
        b = routes.tool_health()
        # cache hit returns same dict object
        assert a is b

    def test_install_plan_shape(self):
        out = routes.tool_install_plan()
        assert "plan" in out and "human" in out
        assert isinstance(out["plan"], list)


# ── api.server.dispatch routes ───────────────────────────────────
class TestDispatchPhase14:

    def test_evidence_list_route(self, db, finding):
        E.record_evidence(db, finding, "k", "v", "ai_hypothesis")
        status, body = server.dispatch(
            "GET", f"/api/v2/findings/{finding}/evidence", {}, None, db,
        )
        assert status == 200
        assert body["evidence"]["ai_hypothesis"]

    def test_evidence_list_404(self, db):
        status, body = server.dispatch(
            "GET", "/api/v2/findings/9999/evidence", {}, None, db,
        )
        assert status == 404

    def test_evidence_verify_route(self, db, finding):
        eid = E.record_evidence(db, finding, "k", "v", "ai_hypothesis")
        status, body = server.dispatch(
            "POST", f"/api/v2/findings/{finding}/evidence/{eid}/verify", {},
            {"operator": "grover"}, db,
        )
        assert status == 200
        assert body["ok"] is True

    def test_evidence_verify_immutable_returns_409(self, db, finding):
        eid = E.record_evidence(db, finding, "k", "v", "observed")
        status, body = server.dispatch(
            "POST", f"/api/v2/findings/{finding}/evidence/{eid}/verify", {},
            {"operator": "grover"}, db,
        )
        assert status == 409

    def test_evidence_verify_not_found_returns_404(self, db, finding):
        status, _ = server.dispatch(
            "POST", f"/api/v2/findings/{finding}/evidence/99999/verify", {},
            {}, db,
        )
        assert status == 404

    def test_tool_health_route(self, db):
        status, body = server.dispatch(
            "GET", "/api/v2/tools/health", {"refresh": ["1"]}, None, db,
        )
        assert status == 200
        assert "tools" in body

    def test_tool_install_plan_route(self, db):
        status, body = server.dispatch(
            "POST", "/api/v2/tools/install_plan", {}, None, db,
        )
        assert status == 200
        assert "plan" in body


# ── hunter integration: structured evidence + taxonomy ──────────
class TestHunterIntegration:
    """Hunter must write structured evidence + CWE/OWASP rows alongside the
    legacy evidence_json + attack_techniques persistence."""

    def test_hunter_persist_writes_evidence_and_taxonomy(self, db):
        # Build the minimum context Hunter._persist_finding needs.
        from agents.hunter import HunterAgent, FindingCandidate
        from agents.base import AgentContext

        # A subdomain row so the finding has somewhere to anchor.
        db.execute(
            "INSERT INTO subdomains(domain, subdomain, http_status, http_title) "
            "VALUES ('acme.com', 'api.acme.com', 200, 'demo')"
        )
        db.commit()
        sid = db.execute(
            "SELECT id FROM subdomains WHERE subdomain='api.acme.com'"
        ).fetchone()[0]

        # Pretend Recon has run so _next_bug_id picks the right job slug.
        db.execute(
            "INSERT INTO agent_memory(job_id, agent, key, value_json) "
            "VALUES ('J1','recon','recon_summary', ?)",
            (json.dumps({"domain": "acme.com"}),),
        )
        db.commit()

        hunter = HunterAgent(db=db)
        ctx = AgentContext(job_id="J1",
                           program={"name": "acme.com"},
                           inputs={"domain": "acme.com"},
                           db=db)
        cand = FindingCandidate(
            vuln_class="ssrf", title="SSRF demo",
            description="webhook fetches user URL", confidence=0.8,
            evidence={"subdomain_id": sid, "endpoint": "/webhook"},
            playbook="ssrf",
        )
        row = hunter._persist_finding(ctx, cand)

        fid = row["id"]
        grouped = E.list_evidence(db, fid)
        # ssrf playbook → everything ai_hypothesis.
        assert grouped["ai_hypothesis"]
        keys = {r["key"] for r in grouped["ai_hypothesis"]}
        assert keys == {"subdomain_id", "endpoint"}

        # CWE + OWASP rows.
        tax = db.execute(
            "SELECT taxonomy, code FROM finding_taxonomy WHERE finding_id=?",
            (fid,),
        ).fetchall()
        codes = {r["code"] for r in tax}
        assert "CWE-918" in codes
        assert "A10:2021" in codes

        # Legacy attack_techniques still populated by mapper.
        att = db.execute(
            "SELECT COUNT(*) FROM attack_techniques WHERE finding_id=?",
            (fid,),
        ).fetchone()[0]
        assert att >= 1
