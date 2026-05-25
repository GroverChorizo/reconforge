"""
Phase 7 tests — Recon agent (adaptive) + signals + registry.

Strategy: mock the LLM call so a scripted decision tree drives the loop,
mock ``registry.dispatch`` with canned ToolResults so no subprocess
runs, and verify:
  - signal extraction is correct on representative fixtures
  - the agent picks adaptive tools when signals surface
  - the step budget halts a runaway loop
  - the cost cap is honored
  - the Ollama mode falls back to the legacy linear pipeline
  - agent_memory[recon_summary] is populated and consumable by Hunter
"""
import json
import sqlite3
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from agents import base, recon
from agents.base import AgentContext
from agents.recon import ReconAgent
from core import signals as signals_mod
from db.migrations import runner as MIG
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
def ctx(migrated_db, tmp_path):
    program = {
        "name": "acme",
        "platform": "hackerone",
        "in_scope": [{"type": "domain", "value": "acme.com"}],
    }
    return AgentContext(
        job_id="J-RECON",
        program=program,
        inputs={"domain": "acme.com"},
        db=migrated_db,
        cost_cap_usd=5.0,
    )


def _result(tool, *, items=None, signals=None, ok=True, summary="ok"):
    return toolreg.ToolResult(
        tool=tool, ok=ok, summary=summary,
        items=items or [],
        signals_delta=signals or {},
    )


class _ScriptedLLM:
    """Callable that returns one canned LLM response per invocation."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []      # captured (system, messages, tools) per call

    def __call__(self, system, messages, tools=None, ctx=None, max_tokens=4096,
                 model_tier=None):
        self.calls.append({"messages": messages, "tools": tools})
        if not self.responses:
            return {"content": "", "tool_calls": [],
                    "prompt_tokens": 0, "completion_tokens": 0,
                    "cost_usd": 0.0, "model": "mock"}
        text, tool_calls = self.responses.pop(0)
        return {
            "content": text, "tool_calls": tool_calls,
            "prompt_tokens": 100, "completion_tokens": 50,
            "cost_usd": 0.001, "model": "mock-haiku",
        }


# ═══════════════════════════════════════════════════════════
#  SIGNAL EXTRACTION (pure)
# ═══════════════════════════════════════════════════════════
class TestSignalsHttpx:

    def test_graphql_endpoint(self):
        lines = [
            json.dumps({"url": "https://api.acme.com/graphql",
                        "status_code": 200, "title": "GraphQL"}),
        ]
        b = signals_mod.extract_from_httpx_jsonl(lines)
        assert "https://api.acme.com/graphql" in b["graphql_endpoints"]

    def test_admin_panel(self):
        lines = [json.dumps({"url": "https://admin.acme.com/",
                              "status_code": 200, "title": "Admin"})]
        b = signals_mod.extract_from_httpx_jsonl(lines)
        assert any("admin.acme.com" in u for u in b["admin_panels"])

    def test_swagger(self):
        lines = [json.dumps({"url": "https://acme.com/swagger.json",
                              "status_code": 200, "title": "swagger"})]
        b = signals_mod.extract_from_httpx_jsonl(lines)
        assert b["swagger_specs"]

    def test_login(self):
        lines = [json.dumps({"url": "https://acme.com/login",
                              "status_code": 200, "title": "Sign in"})]
        b = signals_mod.extract_from_httpx_jsonl(lines)
        assert b["login_pages"]

    def test_tech_rollup(self):
        lines = [
            json.dumps({"url": "https://acme.com/", "tech": ["React", "Express"]}),
            json.dumps({"url": "https://api.acme.com/", "tech": ["Express"]}),
        ]
        b = signals_mod.extract_from_httpx_jsonl(lines)
        assert b["tech_stack"]["express"] == 2
        assert b["tech_stack"]["react"] == 1

    def test_cdn_via_server_header(self):
        lines = [json.dumps({"url": "https://acme.com/",
                              "headers": {"Server": "cloudflare"}})]
        b = signals_mod.extract_from_httpx_jsonl(lines)
        assert b["cdn"] == "cloudflare"

    def test_skips_malformed_lines(self):
        lines = ["not json", "", json.dumps({"url": "https://acme.com/login"})]
        b = signals_mod.extract_from_httpx_jsonl(lines)
        assert b["login_pages"]


class TestSignalsNuclei:

    def test_graphql_template_hit(self):
        lines = [json.dumps({"template-id": "graphql-detect",
                              "host": "https://api.acme.com/graphql"})]
        b = signals_mod.extract_from_nuclei_jsonl(lines)
        assert b["graphql_endpoints"]

    def test_s3_bucket(self):
        lines = [json.dumps({"template-id": "s3-bucket-detect",
                              "matched-at": "https://acme-uploads.s3.amazonaws.com/"})]
        b = signals_mod.extract_from_nuclei_jsonl(lines)
        assert "acme-uploads" in b["s3_buckets"]
        assert b["cloud_provider"] == "aws"


class TestSignalsUrlList:

    def test_admin_host(self):
        b = signals_mod.extract_from_url_list(["admin.acme.com", "www.acme.com"])
        assert any("admin.acme.com" in u for u in b["admin_panels"])

    def test_cloud_buckets(self):
        urls = [
            "https://acme.s3.us-east-1.amazonaws.com/x",
            "https://storage.googleapis.com/acme-gcs-bucket",
            "https://acmestorage.blob.core.windows.net/data",
        ]
        b = signals_mod.extract_from_url_list(urls)
        assert "acme" in b["s3_buckets"]
        assert "acme-gcs-bucket" in b["gcs_buckets"]
        assert "acmestorage" in b["azure_blobs"]


class TestSignalsMerge:

    def test_dedup_lists(self):
        a = {"graphql_endpoints": ["x"], "admin_panels": [], "login_pages": [],
             "swagger_specs": [], "s3_buckets": [], "gcs_buckets": [],
             "azure_blobs": [], "interesting_urls": [], "tech_stack": {"a": 1},
             "waf": None, "cdn": None, "cloud_provider": None}
        b = {"graphql_endpoints": ["x", "y"], "admin_panels": [], "login_pages": [],
             "swagger_specs": [], "s3_buckets": [], "gcs_buckets": [],
             "azure_blobs": [], "interesting_urls": [], "tech_stack": {"a": 2, "b": 1},
             "waf": None, "cdn": None, "cloud_provider": None}
        m = signals_mod.merge(a, b)
        assert m["graphql_endpoints"] == ["x", "y"]
        assert m["tech_stack"] == {"a": 3, "b": 1}

    def test_scalar_takes_first_non_null(self):
        a = signals_mod.empty_bundle()
        b = signals_mod.empty_bundle()
        a["waf"] = "cloudflare"
        m = signals_mod.merge(a, b)
        assert m["waf"] == "cloudflare"


class TestSignalsRecommendations:

    def test_graphql_recommends_graphw00f_first(self):
        b = signals_mod.empty_bundle()
        b["graphql_endpoints"] = ["x"]
        recs = signals_mod.recommended_tools(b)
        assert recs[0] == "graphw00f"
        assert "clairvoyance" in recs and "inql" in recs

    def test_s3_recommends_s3scanner(self):
        b = signals_mod.empty_bundle()
        b["s3_buckets"] = ["bucket"]
        assert "s3scanner" in signals_mod.recommended_tools(b)

    def test_no_signals_no_recs(self):
        assert signals_mod.recommended_tools(signals_mod.empty_bundle()) == []


# ═══════════════════════════════════════════════════════════
#  REGISTRY
# ═══════════════════════════════════════════════════════════
class TestRegistry:

    def test_claude_tool_specs_shape(self):
        specs = toolreg.claude_tool_specs()
        assert specs and all(
            {"name", "description", "input_schema"} <= set(s.keys()) for s in specs
        )

    def test_broad_tools_subset(self):
        # Every broad tool must be in the registry.
        for name in toolreg.BROAD_TOOLS:
            assert name in toolreg.REGISTRY

    def test_adaptive_tools_listed(self):
        # graphw00f / s3scanner / wafw00f among adaptives
        assert "graphw00f" in toolreg.ADAPTIVE_TOOLS
        assert "s3scanner" in toolreg.ADAPTIVE_TOOLS
        assert "wafw00f" in toolreg.ADAPTIVE_TOOLS

    def test_dispatch_unknown_tool(self):
        ctx = toolreg.DispatchContext(job_id="j", domain="acme.com",
                                      workdir="/tmp/x")
        r = toolreg.dispatch("nope", {}, ctx)
        assert r.ok is False
        assert "unknown tool" in r.summary

    def test_dispatch_handler_isolation(self, tmp_path, migrated_db):
        # Forge a registry entry that raises; dispatch must trap.
        bad = toolreg.ToolSpec(
            name="boom", description="d", category="enum", technique="T1596",
            input_schema={"type": "object", "properties": {}},
            handler="enum_stdout", cmd_template="bin-that-does-not-exist $DOMAIN$",
        )
        with patch.dict(toolreg.REGISTRY, {"boom": bad}):
            ctx = toolreg.DispatchContext(
                job_id="j", domain="acme.com",
                workdir=str(tmp_path), db=migrated_db,
            )
            r = toolreg.dispatch("boom", {"domain": "acme.com"}, ctx)
        # binary missing path → ok=False, error="missing" or rc=-1
        assert r.ok is False

    def test_dispatch_tactic_gate_no_longer_blocks(self):
        """Phase B: tactic gate was neutralized. Even with a non-recon
        tactic the dispatch proceeds to the handler. The handler may
        still fail (e.g. subfinder binary missing in the test env), but
        NOT with 'boundary'. Real refusals now come from scope_guard
        upstream, not from tactic classification."""
        with patch.object(toolreg.opsec, "is_execution_allowed", return_value=False), \
             patch.object(toolreg.opsec, "get_technique",
                          return_value={"name": "x", "tactics": ["TA0001"]},
                          create=True):
            ctx = toolreg.DispatchContext(job_id="j", domain="acme.com",
                                          workdir="/tmp/x")
            r = toolreg.dispatch("subfinder", {"domain": "acme.com"}, ctx)
        # We only assert the refusal isn't the tactic boundary. The
        # handler may legitimately fail for unrelated reasons.
        assert "boundary" not in (r.summary or "")
        assert "boundary" not in (r.error or "")


# ═══════════════════════════════════════════════════════════
#  RECON AGENT — adaptive loop
# ═══════════════════════════════════════════════════════════
class TestReconAdaptive:

    def test_final_message_stops_loop(self, ctx, tmp_path, monkeypatch):
        # 1 tool call then a no-tool-call final assistant message.
        script = _ScriptedLLM([
            ("", [{"id": "tu1", "name": "subfinder",
                   "input": {"domain": "acme.com"}}]),
            ("All done.", []),
        ])
        dispatched = []
        def fake_dispatch(name, args, dctx):
            dispatched.append((name, args))
            return _result(name, items=["acme.com", "www.acme.com"])

        with patch.object(ReconAgent, "call_llm", script), \
             patch.object(toolreg, "dispatch", side_effect=fake_dispatch):
            agent = ReconAgent(db=ctx.db, workdir=str(tmp_path))
            result = agent.run(ctx)

        assert result.success is True
        assert result.output["steps"] == 1
        assert dispatched == [("subfinder", {"domain": "acme.com"})]
        assert result.output["mode"] == "adaptive"

    def test_signals_drive_adaptive_tool_choice(self, ctx, tmp_path):
        """Httpx surfaces graphql_endpoints → agent picks graphw00f next.

        The scripted LLM blindly follows the script, but we verify that
        the third LLM call sees the merged signal bundle in its tool
        results — i.e. the agent properly fed adapted state forward.
        """
        script = _ScriptedLLM([
            ("", [{"id": "1", "name": "subfinder",
                   "input": {"domain": "acme.com"}}]),
            ("", [{"id": "2", "name": "httpx", "input": {}}]),
            ("", [{"id": "3", "name": "graphw00f",
                   "input": {"target": "https://api.acme.com/graphql"}}]),
            ("done", []),
        ])

        def fake_dispatch(name, args, dctx):
            if name == "httpx":
                return _result("httpx", signals={
                    **signals_mod.empty_bundle(),
                    "graphql_endpoints": ["https://api.acme.com/graphql"],
                })
            return _result(name)

        with patch.object(ReconAgent, "call_llm", script), \
             patch.object(toolreg, "dispatch", side_effect=fake_dispatch):
            agent = ReconAgent(db=ctx.db, workdir=str(tmp_path))
            result = agent.run(ctx)

        assert result.success is True
        assert "graphw00f" in result.output["summary"]["tools_used"]
        # Third LLM call's last user message should carry the graphql signal.
        third_call_msgs = script.calls[2]["messages"]
        last_user = third_call_msgs[-1]
        assert last_user["role"] == "user"
        tr_payload = last_user["content"][0]
        assert tr_payload["type"] == "tool_result"
        body = json.loads(tr_payload["content"])
        assert body["signals"]["counts"]["graphql_endpoints"] == 1

    def test_step_budget_halts_runaway(self, ctx, tmp_path):
        # Infinite-tool-call script; budget = 3 must stop us.
        loop_resp = ("", [{"id": "1", "name": "subfinder",
                            "input": {"domain": "acme.com"}}])
        script = _ScriptedLLM([loop_resp] * 50)
        with patch.object(ReconAgent, "call_llm", script), \
             patch.object(toolreg, "dispatch", return_value=_result("subfinder")):
            agent = ReconAgent(db=ctx.db, workdir=str(tmp_path), step_budget=3)
            result = agent.run(ctx)
        assert result.output["steps"] == 3
        # Summary still persisted, even on budget halt.
        assert result.output["summary"]["tools_used"]

    def test_cost_cap_halts(self, ctx, tmp_path):
        # Make call_llm raise CostCapExceeded on second call.
        class Capper:
            def __init__(self):
                self.n = 0
            def __call__(self, *a, **kw):
                self.n += 1
                if self.n == 1:
                    return {"content": "",
                            "tool_calls": [{"id": "1", "name": "subfinder",
                                             "input": {"domain": "acme.com"}}],
                            "prompt_tokens": 1, "completion_tokens": 1,
                            "cost_usd": 0.0, "model": "m"}
                raise base.CostCapExceeded("$5 cap hit")

        with patch.object(ReconAgent, "call_llm", Capper()), \
             patch.object(toolreg, "dispatch", return_value=_result("subfinder")):
            agent = ReconAgent(db=ctx.db, workdir=str(tmp_path))
            result = agent.run(ctx)
        assert result.success is False
        assert "cost cap" in result.error
        # The one tool that ran before the cap is still recorded.
        assert result.output["summary"]["tools_used"] == ["subfinder"]

    def test_recon_summary_persisted_for_hunter(self, ctx, tmp_path):
        script = _ScriptedLLM([
            ("", [{"id": "1", "name": "subfinder",
                   "input": {"domain": "acme.com"}}]),
            ("ok", []),
        ])
        with patch.object(ReconAgent, "call_llm", script), \
             patch.object(toolreg, "dispatch",
                          return_value=_result("subfinder",
                                                items=["acme.com", "www.acme.com"])):
            agent = ReconAgent(db=ctx.db, workdir=str(tmp_path))
            agent.run(ctx)
            recalled = agent.recall(ctx, "recon_summary")
        assert recalled is not None
        assert recalled["domain"] == "acme.com"
        assert "signals" in recalled
        assert "subfinder" in recalled["tools_used"]

    def test_emits_recon_complete_event(self, ctx, tmp_path):
        captured = []
        script = _ScriptedLLM([("done", [])])
        with patch.object(ReconAgent, "call_llm", script):
            agent = ReconAgent(db=ctx.db, workdir=str(tmp_path),
                               emit_fn=lambda k, d: captured.append((k, d)))
            agent.run(ctx)
        assert any(k == "recon.complete" for k, _ in captured)


# ═══════════════════════════════════════════════════════════
#  RECON AGENT — Ollama fallback (legacy linear)
# ═══════════════════════════════════════════════════════════
class TestReconLegacy:

    def test_local_mode_runs_legacy(self, ctx, tmp_path):
        called = {"llm": 0}
        def boom(*a, **kw):  # pragma: no cover — defensive
            called["llm"] += 1
            raise AssertionError("LLM must not be called in local mode")
        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: "local" if k == "llm.mode" else d), \
             patch.object(ReconAgent, "call_llm", boom), \
             patch.object(toolreg, "dispatch",
                          return_value=_result("any", items=["acme.com"])):
            agent = ReconAgent(db=ctx.db, workdir=str(tmp_path))
            result = agent.run(ctx)
        assert called["llm"] == 0
        assert result.output["mode"] == "legacy"
        assert result.output["summary"]["fallback"] == "legacy_linear"
        # Legacy walks all broad tools in order.
        assert result.output["summary"]["tools_used"][:4] == [
            "subfinder", "assetfinder", "findomain", "crtsh",
        ]

    def test_legacy_triggers_adaptive_on_signals(self, ctx, tmp_path):
        def dispatcher(name, args, dctx):
            if name == "httpx":
                return _result("httpx", signals={
                    **signals_mod.empty_bundle(),
                    "graphql_endpoints": ["https://api.acme.com/graphql"],
                })
            return _result(name)

        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: "local" if k == "llm.mode" else d), \
             patch.object(toolreg, "dispatch", side_effect=dispatcher):
            agent = ReconAgent(db=ctx.db, workdir=str(tmp_path))
            result = agent.run(ctx)
        used = result.output["summary"]["tools_used"]
        assert "graphw00f" in used
        assert "inql" in used  # all recommended graphql tools

    def test_legacy_emits_fallback_banner(self, ctx, tmp_path):
        captured = []
        with patch.object(base, "_config_get",
                          side_effect=lambda k, d=None: "local" if k == "llm.mode" else d), \
             patch.object(toolreg, "dispatch", return_value=_result("x")):
            agent = ReconAgent(db=ctx.db, workdir=str(tmp_path),
                               emit_fn=lambda k, d: captured.append((k, d)))
            agent.run(ctx)
        kinds = [k for k, _ in captured]
        assert "recon.fallback_banner" in kinds


# ═══════════════════════════════════════════════════════════
#  CONTRACT: domain resolution
# ═══════════════════════════════════════════════════════════
class TestDomainResolution:

    def test_no_domain_no_program(self, migrated_db):
        ctx = AgentContext(job_id="J", db=migrated_db)
        agent = ReconAgent(db=migrated_db)
        result = agent.run(ctx)
        assert result.success is False
        assert "no domain" in result.error

    def test_domain_from_program_wildcard_strip(self, migrated_db):
        prog = {"name": "x", "platform": "h1",
                "in_scope": [{"type": "wildcard", "value": "*.acme.com"}]}
        ctx = AgentContext(job_id="J", db=migrated_db, program=prog,
                           inputs={})
        script = _ScriptedLLM([("done", [])])
        with patch.object(ReconAgent, "call_llm", script):
            agent = ReconAgent(db=migrated_db)
            result = agent.run(ctx)
        assert result.output["summary"]["domain"] == "acme.com"
