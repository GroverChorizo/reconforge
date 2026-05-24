"""Tests for core.manifest_emitter — the vault contract emitter.

Schema source of truth is the CyberBrain vault. A pinned copy is vendored
at tests/fixtures/reconforge-manifest.schema.json — keep it in sync when
the vault bumps schema_version.
"""
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.manifest_emitter import (  # noqa: E402
    SCHEMA_VERSION, emit_run,
    _severity_from_cvss, _fp_likelihood, _slug, _to_iso,
)
from db.migrations import runner as MIG  # noqa: E402

SCHEMA_FILE = Path(__file__).parent / "fixtures" / "reconforge-manifest.schema.json"


# ── fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def migrated_db(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "rf.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    MIG.run_pending(conn)
    yield conn
    conn.close()


@pytest.fixture
def output_root(tmp_path, monkeypatch):
    root = tmp_path / "rf-out"
    monkeypatch.setenv("RECONFORGE_OUTPUT_DIR", str(root))
    return root


@pytest.fixture
def basic_ctx_result(migrated_db):
    program = {
        "slug": "rivian",
        "name": "Rivian",
        "in_scope": [{"type": "domain", "value": "rivian.com"},
                     {"type": "wildcard", "value": "*.rivian.com"}],
        "out_of_scope": [{"type": "domain", "value": "careers.rivian.com"}],
    }
    ctx = SimpleNamespace(
        job_id="J-TEST-1",
        program=program,
        inputs={"domain": "rivian.com", "mode": "passive_recon"},
        db=migrated_db,
    )
    result = SimpleNamespace(
        job_id="J-TEST-1",
        domain="rivian.com",
        status="completed",
        started_at="2026-05-24T01:00:00-05:00",
        completed_at="2026-05-24T01:05:00-05:00",
        agents={
            "scope_guard": SimpleNamespace(success=True, cost_usd=0.0),
            "recon": SimpleNamespace(success=True, cost_usd=0.42),
        },
        errors={},
        total_cost_usd=0.42,
    )
    return ctx, result


# ── pure helpers ─────────────────────────────────────────────────────

class TestHelpers:

    def test_severity_critical(self):
        assert _severity_from_cvss(9.5) == "critical"

    def test_severity_high(self):
        assert _severity_from_cvss(7.0) == "high"

    def test_severity_medium(self):
        assert _severity_from_cvss(5.5) == "medium"

    def test_severity_low(self):
        assert _severity_from_cvss(1.0) == "low"

    def test_severity_none(self):
        assert _severity_from_cvss(None) == "info"

    def test_severity_bad_input(self):
        assert _severity_from_cvss("not-a-number") == "info"

    def test_fp_low(self):
        assert _fp_likelihood(0.95) == "low"

    def test_fp_medium(self):
        assert _fp_likelihood(0.7) == "medium"

    def test_fp_high(self):
        assert _fp_likelihood(0.3) == "high"

    def test_slug(self):
        assert _slug("My Program Name!") == "my-program-name"
        assert _slug("") == "unknown"

    def test_to_iso_sqlite(self):
        out = _to_iso("2026-05-19 14:30:00")
        assert "2026-05-19" in out
        assert "T" in out

    def test_to_iso_passthrough(self):
        s = "2026-05-19T14:30:00+00:00"
        assert _to_iso(s) == s


# ── emit_run end-to-end ─────────────────────────────────────────────

class TestEmitRun:

    def test_empty_db_emits_valid_manifest(self, basic_ctx_result, output_root):
        ctx, result = basic_ctx_result
        run_dir = emit_run(ctx, result)
        assert run_dir.is_dir()
        assert (run_dir / "_manifest.json").is_file()
        assert (run_dir / "hosts.jsonl").is_file()
        assert (run_dir / "endpoints.jsonl").is_file()
        assert (run_dir / "findings.jsonl").is_file()
        assert (run_dir / "raw").is_dir()
        assert (run_dir / "screenshots").is_dir()

    def test_manifest_validates_against_schema(self, basic_ctx_result, output_root):
        jsonschema = pytest.importorskip("jsonschema")
        ctx, result = basic_ctx_result
        run_dir = emit_run(ctx, result)
        manifest = json.loads((run_dir / "_manifest.json").read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        jsonschema.validate(instance=manifest, schema=schema)

    def test_manifest_fields(self, basic_ctx_result, output_root):
        ctx, result = basic_ctx_result
        run_dir = emit_run(ctx, result)
        manifest = json.loads((run_dir / "_manifest.json").read_text(encoding="utf-8"))
        assert manifest["schema_version"] == SCHEMA_VERSION
        assert manifest["run_id"] == "rf-J-TEST-1"
        assert manifest["program"] == "rivian"
        assert manifest["started_at"] == "2026-05-24T01:00:00-05:00"
        assert manifest["completed_at"] == "2026-05-24T01:05:00-05:00"
        assert "rivian.com" in manifest["scope"]["in_scope"]
        assert "*.rivian.com" in manifest["scope"]["in_scope"]
        assert "careers.rivian.com" in manifest["scope"]["out_of_scope"]
        assert manifest["counts"] == {"hosts": 0, "endpoints": 0, "findings": 0}
        names = [t["name"] for t in manifest["tools"]]
        assert "agent.scope_guard" in names
        assert "agent.recon" in names
        assert manifest["notes"] == "passive_recon"

    def test_with_subdomains(self, migrated_db, basic_ctx_result, output_root):
        ctx, result = basic_ctx_result
        migrated_db.execute(
            "INSERT INTO subdomains (domain, subdomain, http_status, http_title, "
            "http_technologies, ip_addresses, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("rivian.com", "api.rivian.com", 200, "Rivian API",
             json.dumps(["nginx", "react"]), json.dumps(["52.84.12.4"]),
             "2026-05-24 01:01:00"),
        )
        migrated_db.execute(
            "INSERT INTO subdomains (domain, subdomain, http_status, http_title, "
            "http_technologies, ip_addresses, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("rivian.com", "basecamp.rivian.com", 200, "Basecamp",
             json.dumps(["cloudfront"]), json.dumps([]),
             "2026-05-24 01:02:00"),
        )
        migrated_db.commit()
        run_dir = emit_run(ctx, result)
        hosts = [json.loads(l) for l in
                 (run_dir / "hosts.jsonl").read_text(encoding="utf-8").splitlines() if l]
        assert len(hosts) == 2
        api = next(h for h in hosts if h["host"] == "api.rivian.com")
        assert api["status_code"] == 200
        assert "react" in api["tech"]
        assert api["ip"] == ["52.84.12.4"]
        endpoints = [json.loads(l) for l in
                     (run_dir / "endpoints.jsonl").read_text(encoding="utf-8").splitlines() if l]
        assert len(endpoints) == 2
        assert all(e["url"].startswith("https://") for e in endpoints)
        manifest = json.loads((run_dir / "_manifest.json").read_text(encoding="utf-8"))
        assert manifest["counts"]["hosts"] == 2
        assert manifest["counts"]["endpoints"] == 2

    def test_with_findings(self, migrated_db, basic_ctx_result, output_root):
        ctx, result = basic_ctx_result
        migrated_db.execute(
            "INSERT INTO findings (bug_id, job_id, domain, vuln_class, title, "
            "description, evidence_json, confidence, cvss_score, cvss_vector, "
            "bounty_estimate_usd, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("RF-001", "J-TEST-1", "api.rivian.com", "idor",
             "IDOR in /orders/{id}", "Sequential numeric IDs unprotected.",
             json.dumps({"url": "https://api.rivian.com/orders/1234", "tool": "manual"}),
             0.92, 8.5, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
             3500, "confirmed", "2026-05-24 01:04:00"),
        )
        migrated_db.commit()
        run_dir = emit_run(ctx, result)
        findings = [json.loads(l) for l in
                    (run_dir / "findings.jsonl").read_text(encoding="utf-8").splitlines() if l]
        assert len(findings) == 1
        f = findings[0]
        assert f["id"] == "RF-001"
        assert f["severity"] == "high"
        assert f["category"] == "idor"
        assert f["host"] == "api.rivian.com"
        assert f["url"] == "https://api.rivian.com/orders/1234"
        assert f["false_positive_likelihood"] == "low"
        assert f["_rf"]["status"] == "confirmed"
        manifest = json.loads((run_dir / "_manifest.json").read_text(encoding="utf-8"))
        assert manifest["counts"]["findings"] == 1

    def test_idempotent_overwrite(self, migrated_db, basic_ctx_result, output_root):
        ctx, result = basic_ctx_result
        run_dir_1 = emit_run(ctx, result)
        first_mtime = (run_dir_1 / "_manifest.json").stat().st_mtime
        # Insert a finding, re-emit. Same started_at → same dir.
        migrated_db.execute(
            "INSERT INTO findings (bug_id, job_id, domain, vuln_class, title, "
            "evidence_json, confidence, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            ("RF-002", "J-TEST-1", "rivian.com", "ssrf", "SSRF in /webhook",
             json.dumps({}), 0.7, "needs_review", "2026-05-24 01:06:00"),
        )
        migrated_db.commit()
        run_dir_2 = emit_run(ctx, result)
        assert run_dir_1 == run_dir_2
        manifest = json.loads((run_dir_2 / "_manifest.json").read_text(encoding="utf-8"))
        assert manifest["counts"]["findings"] == 1
        # File replaced atomically, not appended.
        findings = [json.loads(l) for l in
                    (run_dir_2 / "findings.jsonl").read_text(encoding="utf-8").splitlines() if l]
        assert len(findings) == 1
        assert findings[0]["id"] == "RF-002"
        # mtime should have changed.
        assert (run_dir_2 / "_manifest.json").stat().st_mtime >= first_mtime

    def test_no_db_does_not_crash(self, output_root):
        # Defensive: caller forgets to attach db.
        ctx = SimpleNamespace(job_id="J", program={"slug": "p"}, inputs={}, db=None)
        result = SimpleNamespace(
            job_id="J", domain="x.example", status="completed",
            started_at="2026-05-24T02:00:00-05:00",
            completed_at="2026-05-24T02:01:00-05:00",
            agents={}, errors={}, total_cost_usd=0.0,
        )
        run_dir = emit_run(ctx, result)
        manifest = json.loads((run_dir / "_manifest.json").read_text(encoding="utf-8"))
        assert manifest["counts"] == {"hosts": 0, "endpoints": 0, "findings": 0}

    def test_program_slug_fallback(self, migrated_db, output_root):
        # Program without a slug — falls back to name, then domain, then "unknown".
        ctx = SimpleNamespace(job_id="J", program={"name": "Foo Co"},
                              inputs={"domain": "foo.example"}, db=migrated_db)
        result = SimpleNamespace(
            job_id="J", domain="foo.example", status="completed",
            started_at="2026-05-24T03:00:00-05:00",
            completed_at="2026-05-24T03:01:00-05:00",
            agents={}, errors={}, total_cost_usd=0.0,
        )
        run_dir = emit_run(ctx, result)
        manifest = json.loads((run_dir / "_manifest.json").read_text(encoding="utf-8"))
        assert manifest["program"] == "foo-co"

    def test_output_dir_uses_env(self, basic_ctx_result, tmp_path, monkeypatch):
        ctx, result = basic_ctx_result
        custom = tmp_path / "custom-out"
        monkeypatch.setenv("RECONFORGE_OUTPUT_DIR", str(custom))
        run_dir = emit_run(ctx, result)
        assert str(custom) in str(run_dir.resolve())
