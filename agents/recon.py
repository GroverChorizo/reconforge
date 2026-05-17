"""
Recon agent — Haiku 4.5, adaptive.

Replaces the legacy linear pipeline (``main.run_pipeline``) with an
agent-driven loop. The agent picks tools from the registry; the runtime
dispatches them, extracts signals, and feeds the next turn.

Flow per job
------------
1. Seed: surface the Strategist's plan + scope to Claude as the first
   user message.
2. Loop: model emits ``tool_use`` blocks → runtime dispatches via
   ``tools.registry.dispatch`` → result + cumulative signal bundle is
   fed back as ``tool_result`` content.
3. Stop conditions (whichever first):
   * Model emits an assistant message with no tool calls.
   * Step budget (default 40 tool calls) exhausted.
   * Cost cap exceeded (raised by BaseAgent).
4. Return: ``recon_summary`` dict written to ``agent_memory`` for Hunter.

Fallback
--------
When ``llm.mode == "local"``, Ollama tool-use fidelity is too low for an
adaptive loop. The agent emits a banner and runs ``run_legacy_recon``,
which calls each broad tool once in dependency order via the same
``tools.registry.dispatch`` (no LLM). All resulting signals are still
captured in ``agent_memory``.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional

from agents import base
from agents.base import (
    BaseAgent, AgentContext, AgentResult, LLMError, CostCapExceeded,
)
from core import signals as signals_mod
from tools import registry as toolreg


_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "prompts", "recon.md")
_MEMORY_KEY_SIGNALS = "signals"
_MEMORY_KEY_SUMMARY = "recon_summary"
_DEFAULT_STEP_BUDGET = 40
_DEFAULT_MAX_TOKENS = 4096


# Dependency hints for the legacy linear fallback. Same intent as
# ``main._PIPELINE_STEPS`` but using the new registry names.
_LEGACY_BROAD_ORDER = (
    "subfinder", "assetfinder", "findomain", "crtsh",
    "dnsx", "httpx", "gowitness", "nuclei",
)


class ReconAgent(BaseAgent):
    name = "recon"
    default_model = "haiku"

    def __init__(self, db=None, emit_fn=None, *,
                 step_budget: int = _DEFAULT_STEP_BUDGET,
                 workdir: Optional[str] = None,
                 cancel_event: Optional[threading.Event] = None) -> None:
        super().__init__(db=db, emit_fn=emit_fn)
        self.step_budget = step_budget
        self.workdir = workdir
        self.cancel_event = cancel_event

    # ── orchestration ──────────────────────────────────────────────
    def run(self, ctx: AgentContext) -> AgentResult:
        program = ctx.program or {}
        domain = (ctx.inputs or {}).get("domain") or _domain_from_program(program)
        if not domain:
            return AgentResult(self.name, False, None,
                               error="no domain in AgentContext.inputs.domain "
                                     "and program has no resolvable in_scope root")

        mode = base._config_get("llm.mode", "api")
        if mode == "local":
            self.emit_event("recon.fallback_banner", {
                "reason": "Ollama tool-use fidelity insufficient for adaptive loop; "
                          "running legacy linear pipeline.",
            })
            return self._run_legacy(ctx, domain)

        return self._run_adaptive(ctx, domain)

    # ── adaptive (API) ─────────────────────────────────────────────
    def _run_adaptive(self, ctx: AgentContext, domain: str) -> AgentResult:
        with open(_PROMPT_PATH, "r", encoding="utf-8") as f:
            system = f.read()

        tool_specs = toolreg.claude_tool_specs()
        bundle: Dict[str, Any] = signals_mod.empty_bundle()
        tools_used: List[str] = []
        seed = _seed_user_message(ctx, domain)
        messages: List[Dict[str, Any]] = [{"role": "user", "content": seed}]

        dctx = toolreg.DispatchContext(
            job_id=ctx.job_id, domain=domain,
            workdir=self.workdir or _default_workdir(ctx.job_id, domain),
            db=ctx.db, cancel_event=self.cancel_event,
            mode=(ctx.inputs or {}).get("mode", "passive_recon"),
        )

        steps = 0
        final_text = ""
        last_error: Optional[str] = None

        while steps < self.step_budget:
            try:
                resp = self.call_llm(
                    system=system, messages=messages,
                    tools=tool_specs, ctx=ctx,
                    max_tokens=_DEFAULT_MAX_TOKENS,
                )
            except CostCapExceeded as e:
                last_error = f"cost cap exceeded: {e}"
                self.emit_event("recon.cost_cap", {"reason": str(e)})
                break
            except LLMError as e:
                last_error = f"LLM call failed: {e}"
                break

            tool_calls = resp.get("tool_calls") or []
            content = resp.get("content") or ""
            if not tool_calls:
                # Final assistant message — recon is done.
                final_text = content
                break

            # Record the assistant turn so the conversation stays valid.
            messages.append({
                "role": "assistant",
                "content": _assistant_blocks(content, tool_calls),
            })
            tool_result_blocks: List[Dict[str, Any]] = []

            for call in tool_calls:
                if steps >= self.step_budget:
                    break
                steps += 1
                tools_used.append(call["name"])
                result = toolreg.dispatch(call["name"], call.get("input") or {}, dctx)
                bundle = signals_mod.merge(bundle, result.signals_delta or {})
                self.remember(ctx, _MEMORY_KEY_SIGNALS, bundle)
                self.emit_event("recon.tool", {
                    "tool": result.tool, "ok": result.ok,
                    "summary": result.summary, "step": steps,
                })
                tool_result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": call["id"],
                    "content": json.dumps(_tool_result_payload(result, bundle),
                                          default=str),
                    "is_error": (not result.ok),
                })

            messages.append({"role": "user", "content": tool_result_blocks})

        summary = _build_summary(ctx.db, domain, bundle, tools_used, final_text)
        self.remember(ctx, _MEMORY_KEY_SUMMARY, summary)
        self.emit_event("recon.complete", {
            "tools_used": tools_used, "steps": steps,
            "subdomains_found": summary["subdomains_found"],
        })

        success = last_error is None and steps > 0
        return AgentResult(
            agent=self.name, success=success,
            output={"summary": summary, "steps": steps, "mode": "adaptive"},
            error=last_error,
        )

    # ── legacy linear (no LLM) ─────────────────────────────────────
    def _run_legacy(self, ctx: AgentContext, domain: str) -> AgentResult:
        dctx = toolreg.DispatchContext(
            job_id=ctx.job_id, domain=domain,
            workdir=self.workdir or _default_workdir(ctx.job_id, domain),
            db=ctx.db, cancel_event=self.cancel_event,
            mode=(ctx.inputs or {}).get("mode", "passive_recon"),
        )
        bundle: Dict[str, Any] = signals_mod.empty_bundle()
        tools_used: List[str] = []

        for tool_name in _LEGACY_BROAD_ORDER:
            if self.cancel_event is not None and self.cancel_event.is_set():
                break
            spec = toolreg.REGISTRY[tool_name]
            args: Dict[str, Any] = {"domain": domain} if spec.input_schema.get(
                "required", []) == ["domain"] else {}
            result = toolreg.dispatch(tool_name, args, dctx)
            tools_used.append(tool_name)
            bundle = signals_mod.merge(bundle, result.signals_delta or {})
            self.remember(ctx, _MEMORY_KEY_SIGNALS, bundle)
            self.emit_event("recon.tool", {
                "tool": result.tool, "ok": result.ok,
                "summary": result.summary, "step": len(tools_used),
                "mode": "legacy",
            })

        # In legacy mode we also run any adaptive tools recommended by
        # accumulated signals — but only once each, no LLM in the loop.
        for tool_name in signals_mod.recommended_tools(bundle):
            spec = toolreg.REGISTRY.get(tool_name)
            if spec is None or tool_name in tools_used:
                continue
            target = _adaptive_target(bundle, tool_name)
            if not target:
                continue
            result = toolreg.dispatch(tool_name, {"target": target}, dctx)
            tools_used.append(tool_name)
            bundle = signals_mod.merge(bundle, result.signals_delta or {})
            self.remember(ctx, _MEMORY_KEY_SIGNALS, bundle)

        summary = _build_summary(ctx.db, domain, bundle, tools_used,
                                 notes="Legacy linear pipeline (Ollama mode).")
        summary["fallback"] = "legacy_linear"
        self.remember(ctx, _MEMORY_KEY_SUMMARY, summary)
        self.emit_event("recon.complete", {
            "tools_used": tools_used, "mode": "legacy",
            "subdomains_found": summary["subdomains_found"],
        })
        return AgentResult(
            agent=self.name, success=True,
            output={"summary": summary, "steps": len(tools_used), "mode": "legacy"},
        )


# ── helpers ───────────────────────────────────────────────────────
def _domain_from_program(program: Dict[str, Any]) -> Optional[str]:
    for entry in program.get("in_scope") or []:
        if isinstance(entry, dict):
            t, v = entry.get("type", "domain"), entry.get("value", "")
        else:
            t, v = "domain", str(entry)
        v = v.strip()
        if t in ("domain", "wildcard") and v:
            return v.lstrip("*.")
    return None


def _seed_user_message(ctx: AgentContext, domain: str) -> str:
    program = ctx.program or {}
    plan_hint: Dict[str, Any] = {}
    if ctx.db is not None:
        row = ctx.db.execute(
            "SELECT value_json FROM agent_memory "
            "WHERE job_id=? AND agent='strategist' AND key='plan_v1'",
            (ctx.job_id,),
        ).fetchone()
        if row:
            try:
                plan_hint = json.loads(row[0])
            except (TypeError, json.JSONDecodeError):
                pass
    return json.dumps({
        "domain": domain,
        "program_platform": program.get("platform"),
        "tier_plan": {k: [te.get("value") for te in v]
                      for k, v in (plan_hint.get("tiers") or {}).items()},
        "starting_tier": plan_hint.get("recommended_starting_tier"),
        "instruction": "Start broad recon on this domain. Adapt based on signals.",
    }, indent=2, default=str)


def _assistant_blocks(text: str, tool_calls: List[Dict]) -> List[Dict]:
    blocks: List[Dict[str, Any]] = []
    if text:
        blocks.append({"type": "text", "text": text})
    for call in tool_calls:
        blocks.append({
            "type": "tool_use",
            "id": call["id"], "name": call["name"],
            "input": call.get("input") or {},
        })
    return blocks


def _tool_result_payload(result: toolreg.ToolResult,
                         bundle: Dict[str, Any]) -> Dict[str, Any]:
    """What we feed back to Claude as tool_result content.

    Kept small — Claude doesn't need the raw output, only the summary,
    cumulative signals (compact form), and items count.
    """
    return {
        "tool": result.tool,
        "ok": result.ok,
        "summary": result.summary,
        "item_count": len(result.items or []),
        "error": result.error,
        "signals": signals_mod.summary(bundle),
    }


def _default_workdir(job_id: str, domain: str) -> str:
    """Per-job working dir, mirroring main.JOBS_DIR layout without the import."""
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in domain)
    base = os.environ.get("RECONFORGE_JOBS_DIR", "/tmp/reconforge-jobs")
    return os.path.join(base, f"{safe}__{job_id}")


def _build_summary(db: Any, domain: str, bundle: Dict[str, Any],
                   tools_used: List[str], notes: str = "") -> Dict[str, Any]:
    subs_found = 0
    live = 0
    if db is not None:
        try:
            subs_found = db.execute(
                "SELECT COUNT(*) FROM subdomains WHERE domain=?", (domain,)
            ).fetchone()[0]
            live = db.execute(
                "SELECT COUNT(*) FROM subdomains "
                "WHERE domain=? AND http_status IS NOT NULL", (domain,)
            ).fetchone()[0]
        except Exception:
            pass
    return {
        "domain": domain,
        "subdomains_found": subs_found,
        "live_hosts": live,
        "signals": bundle,
        "tools_used": tools_used,
        "notes": notes,
    }


def _adaptive_target(bundle: Dict[str, Any], tool_name: str) -> Optional[str]:
    """Pick the first relevant target from the bundle for an adaptive tool."""
    if tool_name in ("graphw00f", "clairvoyance", "inql"):
        eps = bundle.get("graphql_endpoints") or []
        return eps[0] if eps else None
    if tool_name == "s3scanner":
        for k in ("s3_buckets", "gcs_buckets", "azure_blobs"):
            vals = bundle.get(k) or []
            if vals:
                return vals[0]
        return None
    if tool_name == "wafw00f":
        admins = bundle.get("admin_panels") or []
        return admins[0] if admins else None
    return None
