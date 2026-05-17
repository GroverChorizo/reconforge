"""
ScopeGuardAgent — BaseAgent wrapper around the Phase 1 pure-logic
``scope_guard.check``. No LLM, zero cost. Standardizes the call site
so the orchestrator (Phase 9) drives every agent through the same API.

Also wires Mapper into the agent layer so subsequent agents can reuse it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

import scope_guard as _sg

from .base import BaseAgent, AgentContext, AgentResult


class ScopeGuardAgent(BaseAgent):
    name = "scope_guard"
    default_model = None  # never calls an LLM

    def run(self, ctx: AgentContext) -> AgentResult:
        target = (ctx.inputs or {}).get("target", "")
        program = ctx.program or {}
        result = _sg.check(target, program)

        # Persist for later agents (Strategist reads program/scope context).
        self.remember(ctx, "last_check", result)
        self.emit_event("scope_guard.check",
                        {"target": target, "allowed": result["allowed"],
                         "reason":  result["reason"], "tier": result["tier"]})

        return AgentResult(
            agent=self.name,
            success=result["allowed"],
            output=result,
            error=None if result["allowed"] else result["reason"],
            cost_usd=0.0,
        )


# ── CLI smoke ─────────────────────────────────────────────────────
def _cli(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="agents.scope_guard")
    sub = p.add_subparsers(dest="cmd", required=True)
    tp = sub.add_parser("test", help="Run the agent end-to-end against a scope JSON.")
    tp.add_argument("--target", required=True)
    tp.add_argument("--program", required=True)
    tp.add_argument("--job-id", default="cli-test")

    args = p.parse_args(argv)
    if args.cmd == "test":
        program = json.loads(Path(args.program).read_text(encoding="utf-8"))
        agent = ScopeGuardAgent()
        result = agent.run(AgentContext(
            job_id=args.job_id, program=program, inputs={"target": args.target},
        ))
        print(json.dumps({
            "success": result.success,
            "output":  result.output,
            "error":   result.error,
        }, indent=2, default=str))
        return 0 if result.success else 1
    return 2


if __name__ == "__main__":
    sys.exit(_cli())
