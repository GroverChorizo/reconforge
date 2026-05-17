"""
Agentic pipeline orchestrator.

Chains all six agents:

    ScopeGuard → Strategist → Recon → Hunter → Analyst → Reporter

State is carried via ``agent_memory`` (each agent writes its own slot;
the next reads from it). Per-agent cost lands in ``agent_runs``. A
single ``$5/job`` cost cap is enforced by ``BaseAgent.call_llm`` —
``CostCapExceeded`` raised from any agent marks the job ``degraded``
(not ``failed``); partial output is preserved.

Failure model
-------------
A *single* agent failure does NOT abort the run; downstream agents skip
their work and the job ends in ``degraded`` with a per-agent error map.
The exception is ScopeGuard — its job is to gate, so a ScopeGuard refusal
ends the pipeline cleanly with status ``rejected``.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from agents.base import AgentContext, AgentResult


# ── result type ───────────────────────────────────────────────────
@dataclass
class PipelineResult:
    job_id: str
    domain: str
    status: str = "completed"        # completed | degraded | rejected | failed
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    agents: Dict[str, AgentResult] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    total_cost_usd: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id, "domain": self.domain,
            "status": self.status,
            "started_at": self.started_at, "completed_at": self.completed_at,
            "agents": {k: {"success": v.success, "error": v.error,
                            "cost_usd": v.cost_usd}
                       for k, v in self.agents.items()},
            "errors": self.errors,
            "total_cost_usd": round(self.total_cost_usd, 4),
        }


# ── orchestrator ──────────────────────────────────────────────────
_AGENT_ORDER = ("scope_guard", "strategist", "recon", "hunter", "analyst", "reporter")


def run_agentic_pipeline(
    ctx: AgentContext,
    *,
    agents: Optional[Dict[str, Any]] = None,
    emit_fn: Optional[Callable] = None,
) -> PipelineResult:
    """Run the six-agent chain.

    ``agents`` may be a dict overriding default agent classes — tests use
    this to inject stubs. Production callers pass nothing.
    """
    from datetime import datetime, timezone

    emit = emit_fn or (lambda kind, data: None)
    result = PipelineResult(job_id=ctx.job_id,
                            domain=(ctx.inputs or {}).get("domain")
                                   or _domain_from_program(ctx.program or {})
                                   or "",
                            started_at=datetime.now(timezone.utc).isoformat())

    classes = _resolve_agents(agents)

    # Bridge naming: ScopeGuard reads ``inputs.target``; Recon reads
    # ``inputs.domain``. Populate whichever is missing so the same ctx
    # serves every agent.
    ctx.inputs = ctx.inputs or {}
    if "target" not in ctx.inputs and result.domain:
        ctx.inputs["target"] = result.domain
    if "domain" not in ctx.inputs and result.domain:
        ctx.inputs["domain"] = result.domain

    # ── 1. ScopeGuard ──
    sg_result = _run_agent(classes["scope_guard"], ctx, emit)
    result.agents["scope_guard"] = sg_result
    result.total_cost_usd += sg_result.cost_usd
    if not sg_result.success:
        result.status = "rejected"
        result.errors["scope_guard"] = sg_result.error or "scope guard refused"
        result.completed_at = datetime.now(timezone.utc).isoformat()
        emit("pipeline.completed", result.to_dict())
        return result

    # ── 2-6. Remaining agents — degrade on failure, don't abort. ──
    for name in _AGENT_ORDER[1:]:
        ag_cls = classes[name]
        ar = _run_agent(ag_cls, ctx, emit)
        result.agents[name] = ar
        result.total_cost_usd += ar.cost_usd
        if not ar.success:
            result.errors[name] = ar.error or f"{name} returned no output"
            result.status = "degraded"
            emit("pipeline.agent_degraded", {"agent": name, "error": ar.error})
            # Downstream agents typically can't run without this one's output;
            # but try anyway — they'll cleanly fail with informative errors.

    result.completed_at = datetime.now(timezone.utc).isoformat()
    emit("pipeline.completed", result.to_dict())
    return result


# ── helpers ───────────────────────────────────────────────────────
def _resolve_agents(overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    from agents.scope_guard import ScopeGuardAgent
    from agents.strategist import StrategistAgent
    from agents.recon import ReconAgent
    from agents.hunter import HunterAgent
    from agents.analyst import AnalystAgent
    from agents.reporter import ReporterAgent
    defaults = {
        "scope_guard": ScopeGuardAgent,
        "strategist":  StrategistAgent,
        "recon":       ReconAgent,
        "hunter":      HunterAgent,
        "analyst":     AnalystAgent,
        "reporter":    ReporterAgent,
    }
    if overrides:
        defaults.update(overrides)
    return defaults


def _run_agent(agent_cls: Any, ctx: AgentContext,
               emit: Callable) -> AgentResult:
    """Instantiate, run, isolate. Any unhandled exception → AgentResult(False)."""
    name = getattr(agent_cls, "name", "agent")
    emit("pipeline.agent_start", {"agent": name})
    try:
        agent = agent_cls(db=ctx.db, emit_fn=emit)
        return agent.run(ctx)
    except Exception as e:
        return AgentResult(agent=name, success=False, output=None,
                           error=f"{type(e).__name__}: {e}")


def _domain_from_program(program: Dict[str, Any]) -> Optional[str]:
    for entry in program.get("in_scope") or []:
        if isinstance(entry, dict):
            t = entry.get("type", "domain")
            v = entry.get("value", "")
        else:
            t, v = "domain", str(entry)
        v = (v or "").strip()
        if t in ("domain", "wildcard") and v:
            return v.lstrip("*.")
    return None
