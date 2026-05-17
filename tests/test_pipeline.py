"""
Phase 9 part 3 — agentic pipeline orchestrator.

End-to-end fixture: ScopeGuard → Strategist → Recon → Hunter → Analyst → Reporter.
All LLM calls + tool dispatches are stubbed. We verify:

  - All 6 agents run in order on a happy path
  - ScopeGuard refusal short-circuits with status='rejected'
  - One agent failure marks 'degraded' (not 'failed')
  - Pipeline result captures per-agent success/cost
  - The final state has: findings rows with cvss_score, attack_techniques rows,
    submission_drafts rows per platform, BUG-XXX.md in the vault
"""
import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from agents.base import AgentContext, AgentResult, BaseAgent
from core.pipeline import run_agentic_pipeline, PipelineResult
from db.migrations import runner as MIG
from obsidian import vault as obsvault
from tools import registry as toolreg


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
    monkeypatch.setattr(obsvault, "vault_root", lambda: vroot)
    return vroot


_PROGRAM = {
    "name": "acme",
    "platforms": ["hackerone", "intigriti"],
    "in_scope": [{"type": "domain", "value": "acme.com"}],
    "out_of_scope": [],
}


# ═══════════════════════════════════════════════════════════
#  END-TO-END HAPPY PATH
# ═══════════════════════════════════════════════════════════
class TestPipelineHappy:

    def test_full_six_agent_run(self, migrated_db, vault_dir):
        """One synthetic domain through every agent, all LLMs mocked."""
        ctx = AgentContext(job_id="J-E2E", db=migrated_db, program=_PROGRAM)

        # Mock Recon dispatch to return one live subdomain.
        def fake_dispatch(name, args, dctx):
            from core import signals as sig
            from tools.registry import ToolResult
            if name == "subfinder":
                # Insert the discovered subdomain for downstream agents.
                dctx.db.execute(
                    "INSERT OR IGNORE INTO subdomains(domain, subdomain, "
                    "http_status, http_title) VALUES(?,?,?,?)",
                    ("acme.com", "api.acme.com", 200, "API"),
                )
                dctx.db.commit()
                return ToolResult(tool=name, ok=True, summary="ok",
                                   items=["api.acme.com"],
                                   signals_delta=sig.empty_bundle())
            return ToolResult(tool=name, ok=True, summary="ok", items=[],
                               signals_delta=sig.empty_bundle())

        # Mock per-agent LLM responses.
        responses = {
            "strategist": json.dumps({
                "program": "acme", "platform": "hackerone",
                "tiers": {"1": [{"value": "acme.com", "type": "domain",
                                  "tier": 1, "rationale": "primary",
                                  "signals": [], "estimated_bounty_usd": 5000}]},
                "reasoning": "primary surface",
                "recommended_starting_tier": 1, "opsec_notes": "",
                "version": "v1",
            }),
            "recon": [
                # First call → ask for subfinder
                {"content": "",
                 "tool_calls": [{"id": "1", "name": "subfinder",
                                  "input": {"domain": "acme.com"}}]},
                # Second call → done
                {"content": "all done", "tool_calls": []},
            ],
            "hunter": json.dumps([
                {"vuln_class": "ssrf",
                 "title": "SSRF reaches IMDS",
                 "description": "Server fetches user URL",
                 "confidence": 0.85,
                 "evidence": {"subdomain_id": None}},   # filled below
            ]),
            "analyst": json.dumps({
                "findings": [{
                    "bug_id": "PLACEHOLDER",
                    "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:P",
                    "bounty_estimate_usd": 5000,
                    "rationale_short": "ssrf",
                }],
                "chains": [], "duplicates": [],
            }),
            "reporter": json.dumps({"polished": []}),
        }

        def llm_router(agent_name):
            """Return a call_llm replacement keyed by agent name."""
            calls = {"n": 0}
            def call(system, messages, **kw):
                calls["n"] += 1
                # Strategist / hunter / analyst / reporter — one-shot
                if agent_name in ("strategist", "hunter", "analyst", "reporter"):
                    content = responses[agent_name]
                    # For hunter we need to inject the real subdomain_id
                    # after subfinder seeded the row.
                    if agent_name == "hunter":
                        sid = migrated_db.execute(
                            "SELECT id FROM subdomains WHERE subdomain='api.acme.com'"
                        ).fetchone()
                        if sid:
                            content = content.replace('"subdomain_id": null',
                                                       f'"subdomain_id": {sid[0]}')
                    if agent_name == "analyst":
                        # Replace placeholder bug_id with whatever Hunter wrote.
                        row = migrated_db.execute(
                            "SELECT bug_id FROM findings ORDER BY id ASC LIMIT 1"
                        ).fetchone()
                        if row:
                            content = content.replace("PLACEHOLDER", row[0])
                    return {"content": content, "tool_calls": [],
                            "prompt_tokens": 100, "completion_tokens": 50,
                            "cost_usd": 0.01, "model": "mock"}
                # Recon — multi-turn
                if agent_name == "recon":
                    resp = responses["recon"][min(calls["n"] - 1,
                                                   len(responses["recon"]) - 1)]
                    return {**resp, "prompt_tokens": 100, "completion_tokens": 50,
                            "cost_usd": 0.01, "model": "mock"}
                return {"content": "", "tool_calls": [],
                        "prompt_tokens": 0, "completion_tokens": 0,
                        "cost_usd": 0.0, "model": "mock"}
            return call

        # Patch each agent class's call_llm individually so the routing
        # is unambiguous.
        from agents import strategist, recon, hunter, analyst, reporter
        with patch.object(strategist.StrategistAgent, "call_llm",
                          side_effect=llm_router("strategist")), \
             patch.object(recon.ReconAgent, "call_llm",
                          side_effect=llm_router("recon")), \
             patch.object(hunter.HunterAgent, "call_llm",
                          side_effect=llm_router("hunter")), \
             patch.object(analyst.AnalystAgent, "call_llm",
                          side_effect=llm_router("analyst")), \
             patch.object(reporter.ReporterAgent, "call_llm",
                          side_effect=llm_router("reporter")), \
             patch.object(toolreg, "dispatch", side_effect=fake_dispatch), \
             patch("agents.hunter.select_playbooks", return_value=["ssrf"]):
            result = run_agentic_pipeline(ctx)

        assert isinstance(result, PipelineResult)
        assert result.status == "completed", result.errors
        # All 6 agents ran successfully.
        assert all(result.agents[name].success
                   for name in ("scope_guard", "strategist", "recon",
                                "hunter", "analyst", "reporter")), result.errors
        # Findings with CVSS score exist.
        f_rows = migrated_db.execute(
            "SELECT cvss_score, cvss_vector FROM findings"
        ).fetchall()
        assert len(f_rows) >= 1
        assert all(r["cvss_score"] is not None for r in f_rows)
        # attack_techniques populated.
        techs = migrated_db.execute(
            "SELECT COUNT(*) FROM attack_techniques"
        ).fetchone()[0]
        assert techs >= 1
        # submission_drafts: 1 finding × 2 platforms
        drafts = migrated_db.execute(
            "SELECT platform FROM submission_drafts"
        ).fetchall()
        assert len(drafts) == 2
        assert {d["platform"] for d in drafts} == {"hackerone", "intigriti"}
        # BUG-XXX.md note exists.
        program_dir = vault_dir / "01-Programs" / "acme"
        assert program_dir.exists()
        notes = list(program_dir.glob("BUG-*.md"))
        assert notes, list(program_dir.iterdir())


# ═══════════════════════════════════════════════════════════
#  SCOPE GUARD REFUSAL
# ═══════════════════════════════════════════════════════════
class TestScopeRefusal:

    def test_out_of_scope_short_circuits(self, migrated_db, vault_dir):
        prog = dict(_PROGRAM)
        prog["out_of_scope"] = [{"type": "domain", "value": "acme.com"}]
        ctx = AgentContext(job_id="J", db=migrated_db, program=prog)
        result = run_agentic_pipeline(ctx)
        assert result.status == "rejected"
        # Only scope_guard ran.
        assert "scope_guard" in result.agents
        assert len(result.agents) == 1
        # No findings, no drafts.
        assert migrated_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


# ═══════════════════════════════════════════════════════════
#  DEGRADED MODE
# ═══════════════════════════════════════════════════════════
class TestDegraded:

    def test_failed_agent_marks_degraded_not_failed(self, migrated_db, vault_dir):
        """Strategist fails → pipeline keeps going, status='degraded'."""

        class BoomStrategist(BaseAgent):
            name = "strategist"
            default_model = "opus"
            def run(self, ctx):
                return AgentResult(self.name, False, None, error="simulated")

        # Stub all later agents to return success but no-op.
        class _NoopAgent(BaseAgent):
            name = "noop"
            default_model = None
            def run(self, ctx):
                return AgentResult(self.name, True, output={})

        class _NoRecon(_NoopAgent):  name = "recon"
        class _NoHunter(_NoopAgent): name = "hunter"
        class _NoAnalyst(_NoopAgent): name = "analyst"
        class _NoReporter(_NoopAgent): name = "reporter"

        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        result = run_agentic_pipeline(ctx, agents={
            "strategist": BoomStrategist,
            "recon":      _NoRecon,
            "hunter":     _NoHunter,
            "analyst":    _NoAnalyst,
            "reporter":   _NoReporter,
        })
        assert result.status == "degraded"
        assert "strategist" in result.errors
        # Downstream agents still ran.
        assert result.agents["recon"].success
        assert result.agents["reporter"].success


# ═══════════════════════════════════════════════════════════
#  CONTRACT
# ═══════════════════════════════════════════════════════════
class TestContract:

    def test_target_inferred_from_program(self, migrated_db, vault_dir):
        """When ctx.inputs has no target, it's pulled from in_scope."""
        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        # Stub all agents to succeed and capture the ctx they receive.
        seen = {}
        class _Cap(BaseAgent):
            name = "x"
            default_model = None
            def run(self, ctx):
                seen["target"] = (ctx.inputs or {}).get("target")
                seen["domain"] = (ctx.inputs or {}).get("domain")
                return AgentResult(self.name, True, output={})

        run_agentic_pipeline(ctx, agents={
            "scope_guard": _Cap, "strategist": _Cap, "recon": _Cap,
            "hunter": _Cap, "analyst": _Cap, "reporter": _Cap,
        })
        assert seen["target"] == "acme.com"
        assert seen["domain"] == "acme.com"

    def test_total_cost_aggregated(self, migrated_db, vault_dir):
        class _Cost(BaseAgent):
            name = "x"
            default_model = None
            def run(self, ctx):
                return AgentResult(self.name, True, output={}, cost_usd=0.5)

        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        result = run_agentic_pipeline(ctx, agents={
            n: _Cost for n in ("scope_guard", "strategist", "recon",
                                "hunter", "analyst", "reporter")
        })
        assert result.total_cost_usd == pytest.approx(3.0)  # 6 × 0.5

    def test_emit_pipeline_events(self, migrated_db, vault_dir):
        captured = []
        class _S(BaseAgent):
            name = "x"
            default_model = None
            def run(self, ctx):
                return AgentResult(self.name, True, output={})

        ctx = AgentContext(job_id="J", db=migrated_db, program=_PROGRAM)
        run_agentic_pipeline(ctx, agents={
            n: _S for n in ("scope_guard", "strategist", "recon",
                             "hunter", "analyst", "reporter")
        }, emit_fn=lambda k, d: captured.append((k, d)))
        kinds = [k for k, _ in captured]
        assert "pipeline.agent_start" in kinds
        assert "pipeline.completed" in kinds
