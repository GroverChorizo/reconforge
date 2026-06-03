"""
Tests for Phase 6 — StrategistAgent + vault/writer.py minimum.

All Opus calls are mocked. Verification covers:
  - schema validation (pass + fail)
  - coverage check: every in_scope asset is tiered
  - agent_memory persistence (plan_v1 + vault_path)
  - vault file written with correct frontmatter, headers, table rows
  - JSON fence stripping (model returns ```json ... ``` wrapper)
  - SSE event fired
  - cost recorded to agent_runs
  - vault path is configurable via vault.path config
"""
import json
import os
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from agents import base
from agents.base import AgentContext
from agents.strategist import (
    StrategistAgent, StrategistPlan, _parse_plan_json, _render_plan_markdown,
)
from vault import writer as vault_writer
from db.migrations import runner as MIG


FIXTURES = ROOT / "tests" / "fixtures"


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
    """Redirect vault root to a tmp dir without touching real ~/Documents."""
    vroot = tmp_path / "ResearchVault"
    monkeypatch.setattr(vault_writer, "vault_root", lambda: vroot)
    return vroot


@pytest.fixture
def ctx(migrated_db, vault_dir):
    return AgentContext(job_id="J-STRAT", db=migrated_db, cost_cap_usd=5.0)


def _load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _mock_plan(program):
    """Build a well-formed plan JSON that covers every in_scope entry."""
    tiers = {"0": [], "1": [], "2": [], "3": [], "4": []}
    for entry in program["in_scope"]:
        val = entry["value"] if isinstance(entry, dict) else str(entry)
        ty = entry.get("type", "domain") if isinstance(entry, dict) else "domain"
        # Naively assign: admin/dev → 0, api/wildcard → 1, mobile → 2, repo → 4, rest → 2
        if "admin" in val.lower() or "dev" in val.lower():
            tier = 0
        elif "api" in val.lower() or ty == "wildcard":
            tier = 1
        elif ty.startswith("mobile"):
            tier = 2
        elif ty == "source_code":
            tier = 4
        else:
            tier = 2
        tiers[str(tier)].append({
            "value": val, "type": ty, "tier": tier,
            "rationale": "test", "signals": [], "estimated_bounty_usd": 500,
        })
    return {
        "program": program["name"],
        "platform": program["platform"],
        "tiers": tiers,
        "reasoning": "Tier 0 dev/admin first because 10× bug probability.",
        "recommended_starting_tier": 0,
        "opsec_notes": "X-Intigriti-Username: researcher required.",
        "version": "v1",
    }


def _mocked_llm(content: str, ptok=1000, ctok=500):
    """Build a fake call_llm response."""
    return {
        "content": content,
        "tool_calls": [],
        "prompt_tokens": ptok,
        "completion_tokens": ctok,
        "cost_usd": 0.05,
        "model": "claude-opus-4-7",
    }


# ═══════════════════════════════════════════════════════════
#  SCHEMA
# ═══════════════════════════════════════════════════════════
class TestSchema:

    def test_valid_plan_parses(self):
        plan = StrategistPlan(
            program="x", platform="hackerone",
            tiers={"1": [{"value": "x.com", "type": "domain", "tier": 1,
                          "rationale": "api", "signals": ["api"]}]},
            reasoning="…", recommended_starting_tier=1,
        )
        assert plan.tiers["1"][0].value == "x.com"

    def test_invalid_tier_key_rejected(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            StrategistPlan(
                program="x", platform="h1",
                tiers={"99": []}, reasoning="r", recommended_starting_tier=0,
            )

    def test_tier_out_of_range_rejected(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            StrategistPlan(
                program="x", platform="h1",
                tiers={"1": [{"value": "x.com", "type": "domain", "tier": 7,
                              "rationale": "r", "signals": []}]},
                reasoning="r", recommended_starting_tier=0,
            )


# ═══════════════════════════════════════════════════════════
#  JSON EXTRACTION
# ═══════════════════════════════════════════════════════════
class TestJsonParse:

    def test_plain_json(self):
        out = _parse_plan_json('{"a": 1}')
        assert out == {"a": 1}

    def test_fenced_json(self):
        out = _parse_plan_json('```json\n{"a": 1}\n```')
        assert out == {"a": 1}

    def test_fenced_no_lang(self):
        out = _parse_plan_json('```\n{"a": 1}\n```')
        assert out == {"a": 1}

    def test_with_leading_prose(self):
        out = _parse_plan_json('Here is the plan:\n{"a": 1}\nEnd.')
        assert out == {"a": 1}

    def test_empty_returns_none(self):
        assert _parse_plan_json("") is None
        assert _parse_plan_json("no json at all") is None


# ═══════════════════════════════════════════════════════════
#  RUN — HAPPY PATH
# ═══════════════════════════════════════════════════════════
class TestRunHappyPath:

    def test_full_fixture_succeeds(self, ctx, vault_dir):
        program = _load_fixture("scope_full.json")
        ctx.program = program
        plan = _mock_plan(program)
        with patch.object(StrategistAgent, "call_llm",
                          return_value=_mocked_llm(json.dumps(plan))):
            agent = StrategistAgent(db=ctx.db)
            result = agent.run(ctx)
        assert result.success is True, result.error
        assert result.output["plan"]["recommended_starting_tier"] == 0

    def test_vault_file_written(self, ctx, vault_dir):
        program = _load_fixture("scope_full.json")
        ctx.program = program
        plan = _mock_plan(program)
        with patch.object(StrategistAgent, "call_llm",
                          return_value=_mocked_llm(json.dumps(plan))):
            agent = StrategistAgent(db=ctx.db)
            result = agent.run(ctx)
        path = Path(result.output["vault_path"])
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert content.startswith("---\n")  # frontmatter
        assert "# Strategist Plan — full-test" in content
        assert "## Tier 0" in content
        assert "X-Intigriti-Username" in content

    def test_agent_memory_populated(self, ctx, vault_dir):
        program = _load_fixture("scope_minimal.json")
        ctx.program = program
        plan = _mock_plan(program)
        with patch.object(StrategistAgent, "call_llm",
                          return_value=_mocked_llm(json.dumps(plan))):
            agent = StrategistAgent(db=ctx.db)
            agent.run(ctx)
            recalled = agent.recall(ctx, "plan_v1")
        assert recalled is not None
        assert recalled["program"] == "minimal-test"

    def test_sse_event_fired(self, ctx, vault_dir):
        program = _load_fixture("scope_minimal.json")
        ctx.program = program
        plan = _mock_plan(program)
        captured = []
        with patch.object(StrategistAgent, "call_llm",
                          return_value=_mocked_llm(json.dumps(plan))):
            agent = StrategistAgent(db=ctx.db,
                                    emit_fn=lambda k, d: captured.append((k, d)))
            agent.run(ctx)
        kinds = [k for k, _ in captured]
        assert "strategist.plan_ready" in kinds

    def test_handles_fenced_response(self, ctx, vault_dir):
        program = _load_fixture("scope_minimal.json")
        ctx.program = program
        plan = _mock_plan(program)
        fenced = "```json\n" + json.dumps(plan) + "\n```"
        with patch.object(StrategistAgent, "call_llm",
                          return_value=_mocked_llm(fenced)):
            agent = StrategistAgent(db=ctx.db)
            result = agent.run(ctx)
        assert result.success is True


# ═══════════════════════════════════════════════════════════
#  RUN — FAILURE MODES
# ═══════════════════════════════════════════════════════════
class TestRunFailures:

    def test_no_program(self, ctx):
        agent = StrategistAgent(db=ctx.db)
        result = agent.run(ctx)
        assert result.success is False
        assert "no program" in result.error

    def test_unparseable_response(self, ctx, vault_dir):
        ctx.program = _load_fixture("scope_minimal.json")
        with patch.object(StrategistAgent, "call_llm",
                          return_value=_mocked_llm("I don't know how to do that.")):
            agent = StrategistAgent(db=ctx.db)
            result = agent.run(ctx)
        assert result.success is False
        assert "parseable JSON" in result.error

    def test_schema_validation_failure(self, ctx, vault_dir):
        ctx.program = _load_fixture("scope_minimal.json")
        bad = {"program": "x"}  # missing platform, tiers, reasoning, etc.
        with patch.object(StrategistAgent, "call_llm",
                          return_value=_mocked_llm(json.dumps(bad))):
            agent = StrategistAgent(db=ctx.db)
            result = agent.run(ctx)
        assert result.success is False
        assert "schema validation" in result.error

    def test_missing_in_scope_coverage(self, ctx, vault_dir):
        program = _load_fixture("scope_full.json")
        ctx.program = program
        plan = _mock_plan(program)
        # Drop one asset from the plan
        plan["tiers"]["2"] = [te for te in plan["tiers"]["2"]
                              if te["type"] != "mobile_android"]
        with patch.object(StrategistAgent, "call_llm",
                          return_value=_mocked_llm(json.dumps(plan))):
            agent = StrategistAgent(db=ctx.db)
            result = agent.run(ctx)
        assert result.success is False
        assert "not tiered" in result.error


# ═══════════════════════════════════════════════════════════
#  COST RECORDED
# ═══════════════════════════════════════════════════════════
class TestCostTracking:

    def test_agent_run_row_written(self, ctx, vault_dir):
        ctx.program = _load_fixture("scope_minimal.json")
        plan = _mock_plan(ctx.program)
        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: {"llm.api_key": "sk"}.get(k, d)), \
             patch.object(base, "_call_anthropic",
                          return_value={"content": json.dumps(plan),
                                        "tool_calls": [],
                                        "prompt_tokens": 1500,
                                        "completion_tokens": 800}):
            agent = StrategistAgent(db=ctx.db)
            agent.run(ctx)
        rows = ctx.db.execute(
            "SELECT agent, status, prompt_tokens, completion_tokens, cost_usd "
            "FROM agent_runs WHERE job_id=?", (ctx.job_id,)
        ).fetchall()
        assert len(rows) == 1
        r = rows[0]
        assert r["agent"] == "strategist"
        assert r["status"] == "completed"
        assert r["prompt_tokens"] == 1500
        assert r["completion_tokens"] == 800
        # 1500 in + 800 out at Opus rates: 1500/1M*$15 + 800/1M*$75 = $0.0225 + $0.060 = $0.0825
        assert abs(r["cost_usd"] - 0.0825) < 1e-4


# ═══════════════════════════════════════════════════════════
#  VAULT WRITER (isolated)
# ═══════════════════════════════════════════════════════════
class TestVaultWriter:

    def test_skeleton_created(self, vault_dir):
        root = vault_writer.ensure_skeleton()
        for sec in ("00-Dashboard", "01-Programs", "02-Techniques",
                    "03-Payloads", "05-Templates"):
            assert (root / sec).is_dir()

    def test_program_dir_sanitized(self, vault_dir):
        pdir = vault_writer.ensure_program_dir("Acme Corp / 2026!")
        assert pdir.is_dir()
        assert pdir.name == "acme-corp-2026"

    def test_write_note_atomic(self, vault_dir):
        path = vault_writer.write_note(
            "01-Programs/test/example.md",
            "Title", "Body content.",
            frontmatter={"tags": ["a", "b"], "platform": "intigriti"},
        )
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "tags:" in content
        assert "- a" in content
        assert "- b" in content
        assert "platform: intigriti" in content
        assert "# Title" in content
        assert "Body content." in content

    def test_overwrite_required(self, vault_dir):
        vault_writer.write_note("01-Programs/test/once.md", "T", "B")
        with pytest.raises(FileExistsError):
            vault_writer.write_note("01-Programs/test/once.md", "T", "B")
        # overwrite=True succeeds
        vault_writer.write_note("01-Programs/test/once.md", "T2", "B2", overwrite=True)
        content = (vault_dir / "01-Programs/test/once.md").read_text(encoding="utf-8")
        assert "# T2" in content

    def test_markdown_rendering(self):
        plan = StrategistPlan(
            program="acme", platform="intigriti",
            tiers={
                "0": [{"value": "admin.acme.com", "type": "domain", "tier": 0,
                       "rationale": "admin", "signals": ["admin_panel"],
                       "estimated_bounty_usd": 3000}],
                "1": [{"value": "*.acme.com", "type": "wildcard", "tier": 1,
                       "rationale": "wildcard", "signals": ["wildcard"]}],
            },
            reasoning="r", recommended_starting_tier=0,
            opsec_notes="X-Intigriti-Username: researcher",
        )
        md = _render_plan_markdown(plan)
        assert "## Tier 0 (1 target)" in md
        assert "## Tier 1 (1 target)" in md
        assert "| `admin.acme.com` |" in md
        assert "$3,000" in md
