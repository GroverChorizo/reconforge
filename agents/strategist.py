"""
Strategist agent — Opus 4.7.

Input:  scope JSON (validated by ScopeGuard upstream)
Output: Tier 0–4 ranked attack plan, persisted to:
          - agent_memory[(job_id, strategist, "plan_v1")]
          - ResearchVault/01-Programs/<program>/strategist_plan.md
        Emits SSE event 'strategist.plan_ready'.

Coverage check: every in_scope entry MUST appear in some tier. Plans that
omit assets are rejected (AgentResult.success=False) so the operator can
re-run with a better prompt.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator

from .base import BaseAgent, AgentContext, AgentResult, LLMError


# ── output schema (versioned) ────────────────────────────────────
class TargetEntry(BaseModel):
    value: str
    type: str
    tier: int = Field(ge=0, le=4)
    rationale: str
    signals: List[str] = Field(default_factory=list)
    estimated_bounty_usd: int = 0


class StrategistPlan(BaseModel):
    program: str
    platform: str
    tiers: Dict[str, List[TargetEntry]] = Field(default_factory=dict)
    reasoning: str
    recommended_starting_tier: int = Field(ge=0, le=4)
    opsec_notes: str = ""
    version: str = "v1"

    @field_validator("tiers")
    @classmethod
    def _tier_keys_in_range(cls, v):
        for k in v.keys():
            if str(k) not in {"0", "1", "2", "3", "4"}:
                raise ValueError(f"invalid tier key: {k}")
        return {str(k): val for k, val in v.items()}


_PROMPT_PATH = Path(__file__).parent / "prompts" / "strategist.md"
_MAX_TOKENS = 30_000  # plan section 6 risk: cap completion to control cost
_MEMORY_KEY = "plan_v1"


class StrategistAgent(BaseAgent):
    name = "strategist"
    default_model = "opus"

    def run(self, ctx: AgentContext) -> AgentResult:
        program = ctx.program or {}
        if not program:
            return AgentResult(self.name, False, None,
                               error="no program in AgentContext")

        system = _PROMPT_PATH.read_text(encoding="utf-8")
        user_msg = _build_user_message(program)

        try:
            resp = self.call_llm(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                ctx=ctx,
                max_tokens=_MAX_TOKENS,
            )
        except LLMError as e:
            return AgentResult(self.name, False, None, error=f"LLM call failed: {e}")

        plan_dict = _parse_plan_json(resp.get("content", ""))
        if plan_dict is None:
            return AgentResult(self.name, False, None,
                               error="strategist did not return parseable JSON")

        try:
            plan = StrategistPlan(**plan_dict)
        except ValidationError as e:
            return AgentResult(self.name, False, plan_dict,
                               error=f"plan failed schema validation: {e}")

        # Coverage check — every in_scope entry MUST be tiered.
        # Key on (type, value) so e.g. mobile_ios + mobile_android sharing a
        # bundle ID are treated as distinct assets.
        tiered = {(te.type, te.value) for tier_list in plan.tiers.values() for te in tier_list}
        missing = [
            _entry_key(e) for e in program.get("in_scope", [])
            if _entry_key(e) not in tiered
        ]
        if missing:
            return AgentResult(
                self.name, False, plan.model_dump(),
                error=f"{len(missing)} in-scope asset(s) not tiered: {missing[:5]}",
            )

        plan_d = plan.model_dump()
        self.remember(ctx, _MEMORY_KEY, plan_d)
        vault_path = _write_vault_plan(program, plan)
        self.remember(ctx, "vault_path", str(vault_path))
        self.emit_event("strategist.plan_ready", {
            "tier_counts": {k: len(v) for k, v in plan_d["tiers"].items()},
            "recommended_starting_tier": plan_d["recommended_starting_tier"],
            "vault_path": str(vault_path),
        })

        return AgentResult(
            agent=self.name,
            success=True,
            output={"plan": plan_d, "vault_path": str(vault_path)},
            cost_usd=resp.get("cost_usd", 0.0),
            prompt_tokens=resp.get("prompt_tokens", 0),
            completion_tokens=resp.get("completion_tokens", 0),
        )


# ── helpers ──────────────────────────────────────────────────────
def _entry_value(e: Any) -> str:
    return e["value"] if isinstance(e, dict) else str(e)


def _entry_key(e: Any) -> tuple[str, str]:
    if isinstance(e, dict):
        return (e.get("type", "domain"), e["value"])
    return ("domain", str(e))


def _build_user_message(program: Dict) -> str:
    return json.dumps({
        "scope": program,
        "instruction": (
            "Produce the Tier 0–4 plan. Every in_scope entry must be tiered. "
            "Respond with ONE JSON object matching the schema in the system prompt. "
            "No prose, no markdown fences, just the JSON."
        ),
    }, indent=2, default=str)


def _parse_plan_json(content: str) -> Optional[Dict]:
    """Extract the first balanced JSON object from the model's response."""
    if not content:
        return None
    s = content.strip()
    if s.startswith("```"):
        # strip a leading fence (optionally with 'json' tag) and the trailing fence
        s = s[3:]
        if s.lower().startswith("json"):
            s = s[4:].lstrip("\r\n")
        if s.endswith("```"):
            s = s[:-3]
        s = s.strip()
    start = s.find("{")
    end = s.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(s[start:end + 1])
    except json.JSONDecodeError:
        return None


def _write_vault_plan(program: Dict, plan: StrategistPlan) -> Path:
    from vault.writer import ensure_program_dir, vault_root, write_note

    program_name = program.get("name", "unknown")
    pdir = ensure_program_dir(program_name)
    rel = pdir.relative_to(vault_root()) / "strategist_plan.md"

    body = _render_plan_markdown(plan)
    fm = {
        "tags": ["reconforge", "strategist", program_name],
        "platform": plan.platform,
        "program": plan.program,
        "version": plan.version,
        "starting_tier": plan.recommended_starting_tier,
    }
    return write_note(
        str(rel), f"Strategist Plan — {plan.program}",
        body, frontmatter=fm, overwrite=True,
    )


def _render_plan_markdown(plan: StrategistPlan) -> str:
    lines: List[str] = []
    lines.append(f"## Recommended Starting Tier\n\n**Tier {plan.recommended_starting_tier}**\n")
    lines.append(f"## Reasoning\n\n{plan.reasoning}\n")
    lines.append(f"## OPSEC Notes\n\n{plan.opsec_notes}\n")

    for tier_id in sorted(plan.tiers.keys(), key=int):
        tier_entries = plan.tiers[tier_id]
        if not tier_entries:
            continue
        plural = "s" if len(tier_entries) != 1 else ""
        lines.append(f"## Tier {tier_id} ({len(tier_entries)} target{plural})\n")
        lines.append("| Asset | Type | Rationale | Signals | Est. Bounty |")
        lines.append("|---|---|---|---|---|")
        for te in tier_entries:
            sig = ", ".join(te.signals) or "—"
            lines.append(
                f"| `{te.value}` | {te.type} | {te.rationale} | {sig} | ${te.estimated_bounty_usd:,} |"
            )
        lines.append("")
    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────
def _cli(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="agents.strategist")
    sub = p.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("run", help="Run strategist against a scope JSON. Requires Claude API key.")
    rp.add_argument("--program", required=True)
    rp.add_argument("--job-id", default="cli-strategist")
    args = p.parse_args(argv)
    if args.cmd == "run":
        program = json.loads(Path(args.program).read_text(encoding="utf-8"))
        agent = StrategistAgent()
        result = agent.run(AgentContext(job_id=args.job_id, program=program))
        print(json.dumps({
            "success": result.success,
            "error": result.error,
            "cost_usd": result.cost_usd,
            "output": result.output,
        }, indent=2, default=str))
        return 0 if result.success else 1
    return 2


if __name__ == "__main__":
    sys.exit(_cli())
