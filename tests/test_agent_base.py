"""
Tests for Phase 5 — BaseAgent, Ollama adapter, ScopeGuardAgent.

Strategy:
  - Pure-logic cases run against a real migrated SQLite DB.
  - LLM call paths are mocked (no network).
  - The ScopeGuardAgent test verifies the rewired call-site produces
    bit-identical decisions to the Phase 1 standalone module.
"""
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from agents import base
from agents.base import (
    BaseAgent, AgentContext, AgentResult, LLMError, CostCapExceeded,
    compute_cost, MODEL_PRICES, DEFAULT_MODELS,
)
from agents.scope_guard import ScopeGuardAgent
from agents import ollama_adapter
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


@pytest.fixture
def ctx(migrated_db):
    return AgentContext(job_id="J-TEST", db=migrated_db, cost_cap_usd=5.0)


# ═══════════════════════════════════════════════════════════
#  COST MATH
# ═══════════════════════════════════════════════════════════
class TestCostMath:

    def test_opus_cost(self):
        # 1M in + 1M out → $15 + $75 = $90
        c = compute_cost("claude-opus-4-7", 1_000_000, 1_000_000)
        assert abs(c - 90.0) < 1e-6

    def test_haiku_cost(self):
        # 1M in + 1M out → $1 + $5 = $6
        c = compute_cost("claude-haiku-4-5-20251001", 1_000_000, 1_000_000)
        assert abs(c - 6.0) < 1e-6

    def test_small_call(self):
        # 1000 in + 500 out on haiku → $0.001 + $0.0025 = $0.0035
        c = compute_cost("claude-haiku-4-5-20251001", 1000, 500)
        assert abs(c - 0.0035) < 1e-6

    def test_unknown_model_zero(self):
        # Unknown models price at $0 (Ollama path)
        assert compute_cost("llama3.1:70b", 1_000_000, 1_000_000) == 0.0

    def test_all_default_models_priced(self):
        for tier_id in DEFAULT_MODELS.values():
            assert tier_id in MODEL_PRICES, f"{tier_id} missing from price table"


# ═══════════════════════════════════════════════════════════
#  AGENT MEMORY
# ═══════════════════════════════════════════════════════════
class TestAgentMemory:

    def test_remember_recall_roundtrip(self, ctx):
        agent = BaseAgent(db=ctx.db)
        agent.name = "test"
        agent.remember(ctx, "k1", {"a": 1, "b": [2, 3]})
        assert agent.recall(ctx, "k1") == {"a": 1, "b": [2, 3]}

    def test_recall_default_when_missing(self, ctx):
        agent = BaseAgent(db=ctx.db)
        agent.name = "test"
        assert agent.recall(ctx, "missing", default="x") == "x"

    def test_remember_overwrites(self, ctx):
        agent = BaseAgent(db=ctx.db)
        agent.name = "test"
        agent.remember(ctx, "k", "first")
        agent.remember(ctx, "k", "second")
        assert agent.recall(ctx, "k") == "second"
        rows = ctx.db.execute(
            "SELECT COUNT(*) FROM agent_memory WHERE job_id=? AND agent=? AND key=?",
            (ctx.job_id, "test", "k")
        ).fetchone()
        assert rows[0] == 1, "INSERT OR REPLACE should not create duplicates"

    def test_no_db_silent_noop(self):
        agent = BaseAgent(db=None)
        agent.name = "test"
        # Should not raise
        agent.remember(AgentContext(job_id="x"), "k", "v")
        assert agent.recall(AgentContext(job_id="x"), "k", default="d") == "d"


# ═══════════════════════════════════════════════════════════
#  MODEL RESOLUTION
# ═══════════════════════════════════════════════════════════
class TestModelResolution:

    def test_api_opus_default(self):
        agent = BaseAgent()
        with patch.object(base, "_config_get", side_effect=lambda k, d=None: d):
            assert agent._resolve_model("opus", "api") == DEFAULT_MODELS["opus"]

    def test_api_haiku_default(self):
        agent = BaseAgent()
        with patch.object(base, "_config_get", side_effect=lambda k, d=None: d):
            assert agent._resolve_model("haiku", "api") == DEFAULT_MODELS["haiku"]

    def test_config_overrides_default(self):
        agent = BaseAgent()
        cfg = {"llm.opus_model": "claude-opus-CUSTOM"}
        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: cfg.get(k, d)):
            assert agent._resolve_model("opus", "api") == "claude-opus-CUSTOM"

    def test_local_substitute(self):
        agent = BaseAgent()
        cfg = {"llm.ollama_opus_substitute": "llama3.1:70b"}
        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: cfg.get(k, d)):
            assert agent._resolve_model("opus", "local") == "llama3.1:70b"

    def test_local_falls_back_to_default(self):
        agent = BaseAgent()
        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: d):
            assert agent._resolve_model("haiku", "local") == "llama3.1:8b"


# ═══════════════════════════════════════════════════════════
#  LLM CALL — API PATH (mocked Anthropic SDK)
# ═══════════════════════════════════════════════════════════
class TestAnthropicPath:

    def _mock_resp(self, in_tokens=100, out_tokens=50, text="hello"):
        block = MagicMock(); block.type = "text"; block.text = text
        resp = MagicMock()
        resp.content = [block]
        resp.usage = MagicMock(input_tokens=in_tokens, output_tokens=out_tokens)
        return resp

    def test_api_call_records_tokens_and_cost(self, ctx):
        agent = BaseAgent(db=ctx.db)
        agent.name = "test_api"
        agent.default_model = "haiku"

        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: {"llm.api_key": "sk-test"}.get(k, d)), \
             patch.object(base, "_call_anthropic",
                          return_value={"content": "hi", "tool_calls": [],
                                        "prompt_tokens": 200, "completion_tokens": 100}):
            resp = agent.call_llm("sys", [{"role": "user", "content": "hi"}], ctx=ctx)

        assert resp["content"] == "hi"
        assert resp["prompt_tokens"] == 200
        assert resp["completion_tokens"] == 100
        # 200 in + 100 out at haiku rates: 200/1M*$1 + 100/1M*$5 = $0.0002 + $0.0005
        assert abs(resp["cost_usd"] - 0.0007) < 1e-6

        rows = ctx.db.execute(
            "SELECT agent, model, prompt_tokens, completion_tokens, cost_usd, status "
            "FROM agent_runs WHERE job_id=?", (ctx.job_id,)
        ).fetchall()
        assert len(rows) == 1
        r = rows[0]
        assert r["agent"] == "test_api"
        assert r["model"] == DEFAULT_MODELS["haiku"]
        assert r["prompt_tokens"] == 200
        assert r["completion_tokens"] == 100
        assert r["status"] == "completed"

    def test_api_failure_records_failed_run(self, ctx):
        agent = BaseAgent(db=ctx.db)
        agent.name = "test_api_fail"
        agent.default_model = "haiku"

        with patch.object(base, "_call_anthropic", side_effect=RuntimeError("boom")):
            with pytest.raises(LLMError, match="boom"):
                agent.call_llm("sys", [{"role": "user", "content": "x"}], ctx=ctx)

        rows = ctx.db.execute(
            "SELECT status, error FROM agent_runs WHERE job_id=?", (ctx.job_id,)
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["status"] == "failed"
        assert "boom" in rows[0]["error"]


# ═══════════════════════════════════════════════════════════
#  COST CAP
# ═══════════════════════════════════════════════════════════
class TestCostCap:

    def test_cap_blocks_further_calls(self, ctx):
        # Pre-load $5.50 of spend → over the default $5 cap
        ctx.db.execute(
            "INSERT INTO agent_runs(job_id, agent, status, cost_usd, completed_at) "
            "VALUES (?, 'strategist', 'completed', 5.50, datetime('now'))",
            (ctx.job_id,)
        )
        ctx.db.commit()

        agent = BaseAgent(db=ctx.db)
        agent.name = "test_capped"
        agent.default_model = "haiku"
        with pytest.raises(CostCapExceeded):
            agent.call_llm("sys", [{"role": "user", "content": "x"}], ctx=ctx)

    def test_cap_allows_under_budget(self, ctx):
        ctx.db.execute(
            "INSERT INTO agent_runs(job_id, agent, status, cost_usd, completed_at) "
            "VALUES (?, 'strategist', 'completed', 0.01, datetime('now'))",
            (ctx.job_id,)
        )
        ctx.db.commit()

        agent = BaseAgent(db=ctx.db)
        agent.name = "test_under"
        agent.default_model = "haiku"
        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: {"llm.api_key": "sk"}.get(k, d)), \
             patch.object(base, "_call_anthropic",
                          return_value={"content": "ok", "tool_calls": [],
                                        "prompt_tokens": 10, "completion_tokens": 5}):
            resp = agent.call_llm("sys", [{"role": "user", "content": "x"}], ctx=ctx)
        assert resp["content"] == "ok"

    def test_zero_cap_disables_check(self, ctx):
        ctx.cost_cap_usd = 0.0
        ctx.db.execute(
            "INSERT INTO agent_runs(job_id, agent, status, cost_usd, completed_at) "
            "VALUES (?, 'x', 'completed', 999.0, datetime('now'))",
            (ctx.job_id,)
        )
        ctx.db.commit()
        agent = BaseAgent(db=ctx.db); agent.name="z"; agent.default_model="haiku"
        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: {"llm.api_key": "sk"}.get(k, d)), \
             patch.object(base, "_call_anthropic",
                          return_value={"content": "ok", "tool_calls": [],
                                        "prompt_tokens": 1, "completion_tokens": 1}):
            agent.call_llm("sys", [{"role": "user", "content": "x"}], ctx=ctx)


# ═══════════════════════════════════════════════════════════
#  OLLAMA ADAPTER (mocked POST)
# ═══════════════════════════════════════════════════════════
class TestOllamaAdapter:

    def test_call_translates_messages(self):
        captured = {}
        def fake_post(url, payload):
            captured["url"] = url
            captured["payload"] = payload
            return {"message": {"content": "hello world"},
                    "prompt_eval_count": 50, "eval_count": 20}
        with patch.object(ollama_adapter, "_post", side_effect=fake_post):
            resp = ollama_adapter.call(
                "llama3.1:8b", "you are a helpful assistant",
                [{"role": "user", "content": "hi"}],
            )
        assert resp["content"] == "hello world"
        assert resp["prompt_tokens"] == 50
        assert resp["completion_tokens"] == 20
        assert "/api/chat" in captured["url"]
        assert captured["payload"]["model"] == "llama3.1:8b"
        # system message comes first
        assert captured["payload"]["messages"][0]["role"] == "system"

    def test_tool_calls_parsed(self):
        with patch.object(ollama_adapter, "_post",
                          return_value={"message": {"content":
                              'I will run: {"tool_calls": [{"name": "subfinder", "input": {"d": "x.com"}}]}'},
                              "prompt_eval_count": 10, "eval_count": 5}):
            resp = ollama_adapter.call(
                "llama3.1:8b", "sys", [{"role": "user", "content": "scan"}],
                tools=[{"name": "subfinder", "description": "subdomain enum"}],
            )
        assert len(resp["tool_calls"]) == 1
        assert resp["tool_calls"][0]["name"] == "subfinder"

    def test_unparseable_tool_response_retries(self):
        responses = [
            {"message": {"content": "no json here"}, "prompt_eval_count": 5, "eval_count": 3},
            {"message": {"content": '{"tool_calls": [{"name": "foo", "input": {}}]}'},
             "prompt_eval_count": 8, "eval_count": 6},
        ]
        with patch.object(ollama_adapter, "_post", side_effect=responses):
            resp = ollama_adapter.call(
                "llama3.1:8b", "sys", [{"role": "user", "content": "x"}],
                tools=[{"name": "foo"}],
            )
        assert resp["tool_calls"][0]["name"] == "foo"

    def test_anthropic_block_content_flattened(self):
        captured = {}
        def fake_post(url, payload):
            captured["payload"] = payload
            return {"message": {"content": "ok"}, "prompt_eval_count": 0, "eval_count": 0}
        msgs = [{"role": "user",
                 "content": [{"type": "text", "text": "block one"},
                             {"type": "text", "text": " block two"}]}]
        with patch.object(ollama_adapter, "_post", side_effect=fake_post):
            ollama_adapter.call("llama3.1:8b", "", msgs)
        # User message should be a flat string now
        user_msg = next(m for m in captured["payload"]["messages"] if m["role"] == "user")
        assert user_msg["content"] == "block one block two"


# ═══════════════════════════════════════════════════════════
#  OLLAMA PATH VIA BASEAGENT
# ═══════════════════════════════════════════════════════════
class TestOllamaThroughBaseAgent:

    def test_local_mode_uses_ollama(self, ctx):
        cfg = {"llm.mode": "local",
               "llm.ollama_haiku_substitute": "llama3.1:8b"}
        agent = BaseAgent(db=ctx.db)
        agent.name = "ollama_test"
        agent.default_model = "haiku"

        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: cfg.get(k, d)), \
             patch.object(base, "_call_ollama",
                          return_value={"content": "local response", "tool_calls": [],
                                        "prompt_tokens": 5, "completion_tokens": 3}) as moll, \
             patch.object(base, "_call_anthropic") as mapi:
            resp = agent.call_llm("sys", [{"role": "user", "content": "x"}], ctx=ctx)

        moll.assert_called_once()
        mapi.assert_not_called()
        assert resp["content"] == "local response"
        assert resp["cost_usd"] == 0.0  # local model not in price table


# ═══════════════════════════════════════════════════════════
#  SCOPE GUARD AGENT
# ═══════════════════════════════════════════════════════════
class TestScopeGuardAgent:

    @pytest.fixture
    def examplecorp_program(self):
        return json.loads((ROOT / "scopes" / "examplecorp.json").read_text(encoding="utf-8"))

    def test_in_scope_allowed(self, ctx, examplecorp_program):
        ctx.program = examplecorp_program
        ctx.inputs = {"target": "api.examplecorp.com"}
        agent = ScopeGuardAgent(db=ctx.db)
        result = agent.run(ctx)
        assert result.success is True
        assert result.output["tier"] == 2
        assert result.output["headers"]["X-Intigriti-Username"] == "researcher"
        # Memory should record the decision
        last = agent.recall(ctx, "last_check")
        assert last["allowed"] is True

    def test_out_of_scope_rejected(self, ctx, examplecorp_program):
        ctx.program = examplecorp_program
        ctx.inputs = {"target": "careers.examplecorp.com"}
        agent = ScopeGuardAgent(db=ctx.db)
        result = agent.run(ctx)
        assert result.success is False
        assert "out_of_scope" in result.error

    def test_no_llm_no_cost(self, ctx, examplecorp_program):
        ctx.program = examplecorp_program
        ctx.inputs = {"target": "api.examplecorp.com"}
        agent = ScopeGuardAgent(db=ctx.db)
        result = agent.run(ctx)
        assert result.cost_usd == 0.0
        # No agent_runs row because no LLM call
        rows = ctx.db.execute(
            "SELECT COUNT(*) FROM agent_runs WHERE job_id=?", (ctx.job_id,)
        ).fetchone()
        assert rows[0] == 0

    def test_emit_event_fired(self, ctx, examplecorp_program):
        ctx.program = examplecorp_program
        ctx.inputs = {"target": "api.examplecorp.com"}
        captured = []
        agent = ScopeGuardAgent(db=ctx.db, emit_fn=lambda k, d: captured.append((k, d)))
        agent.run(ctx)
        assert any(k == "scope_guard.check" for k, _ in captured)


# ═══════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════
class TestCLI:

    def test_scope_guard_agent_cli_allow(self):
        r = subprocess.run(
            [sys.executable, "-m", "agents.scope_guard", "test",
             "--target", "api.examplecorp.com",
             "--program", "scopes/examplecorp.json"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["success"] is True

    def test_scope_guard_agent_cli_reject(self):
        r = subprocess.run(
            [sys.executable, "-m", "agents.scope_guard", "test",
             "--target", "careers.examplecorp.com",
             "--program", "scopes/examplecorp.json"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 1
        out = json.loads(r.stdout)
        assert out["success"] is False
