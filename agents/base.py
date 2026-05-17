"""
BaseAgent — the runtime substrate every ReconForge agent inherits from.

Responsibilities:
  - Model resolution (Opus 4.7 / Haiku 4.5 / Ollama substitute) from config table
  - LLM call with cost tracking → agent_runs
  - Shared scratchpad I/O → agent_memory (UNIQUE(job_id, agent, key))
  - SSE emit hook for SPA agent panel (Phase 10)
  - Per-job cost cap enforcement (default $5; aborts with CostCapExceeded)

The Anthropic SDK (``anthropic`` package) is the API call site. The Ollama
adapter (agents/ollama_adapter.py) provides the local fallback when
``llm.mode == "local"``. Both code paths return the same dict shape so
agents don't branch on backend.

Phase 5 ships:
  - BaseAgent class
  - Cost/price table for current Claude + Ollama models
  - ScopeGuardAgent (no-LLM wrapper around scope_guard.check)

Later phases (6-9) inherit from BaseAgent for Strategist, Recon, Hunter,
Analyst, Reporter.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# ── pricing table (USD per 1M tokens, input / output) ────────────────
# Update when Anthropic changes pricing.
MODEL_PRICES: Dict[str, tuple[float, float]] = {
    "claude-opus-4-7":          (15.00, 75.00),
    "claude-sonnet-4-6":        ( 3.00, 15.00),
    "claude-haiku-4-5-20251001":( 1.00,  5.00),
    # local models cost nothing
}

# Tier → default model ID (overridable via config).
DEFAULT_MODELS = {
    "opus":  "claude-opus-4-7",
    "haiku": "claude-haiku-4-5-20251001",
}


# ── public types ─────────────────────────────────────────────────────
@dataclass
class AgentContext:
    """Carried by the orchestrator across an agent run."""
    job_id: str
    program: Optional[Dict] = None
    inputs:  Dict           = field(default_factory=dict)
    db:      Any            = None        # sqlite3.Connection
    cost_cap_usd: float     = 5.0


@dataclass
class AgentResult:
    agent:   str
    success: bool
    output:  Any
    error:   Optional[str] = None
    cost_usd: float        = 0.0
    prompt_tokens:     int = 0
    completion_tokens: int = 0


class LLMError(RuntimeError):
    """Any failure from the LLM backend (API or Ollama)."""


class CostCapExceeded(RuntimeError):
    """Raised before an LLM call when the job's cost cap is already met."""


# ── BaseAgent ────────────────────────────────────────────────────────
class BaseAgent:
    name: str = "base"
    # tier hint resolved against config; None means this agent never calls an LLM
    default_model: Optional[str] = None  # "opus" | "haiku" | None

    def __init__(self, db: Any = None, emit_fn: Optional[Callable] = None) -> None:
        self.db = db
        self._emit = emit_fn or (lambda kind, data: None)

    # ── subclass surface ────────────────────────────────────────────
    def run(self, ctx: AgentContext) -> AgentResult:
        raise NotImplementedError(f"{self.name}.run() must be overridden")

    # ── LLM ─────────────────────────────────────────────────────────
    def call_llm(
        self,
        system: str,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        model_tier: Optional[str] = None,
        ctx: Optional[AgentContext] = None,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        """One LLM call.

        Returns a dict with:
            content (str), tool_calls (list), prompt_tokens (int),
            completion_tokens (int), cost_usd (float), model (str)

        Records the call in agent_runs (running → completed | failed).
        Raises CostCapExceeded if the job is already over budget; LLMError
        on any backend failure.
        """
        tier = model_tier or self.default_model
        if tier is None:
            raise LLMError(f"{self.name}: no model tier configured")

        mode = _config_get("llm.mode", "api")
        model_id = self._resolve_model(tier, mode)

        # Cost cap: refuse new calls once the budget is gone.
        if ctx is not None and ctx.cost_cap_usd > 0 and self.db is not None:
            spent = _job_cost_so_far(self.db, ctx.job_id)
            if spent >= ctx.cost_cap_usd:
                raise CostCapExceeded(
                    f"job {ctx.job_id} cost cap reached: ${spent:.4f} >= ${ctx.cost_cap_usd:.2f}"
                )

        run_id = self._begin_run(ctx, model_id) if ctx else None
        try:
            if mode == "local":
                resp = _call_ollama(model_id, system, messages, tools, max_tokens)
            else:
                resp = _call_anthropic(model_id, system, messages, tools, max_tokens)
        except Exception as e:
            self._end_run(run_id, status="failed", error=str(e))
            raise LLMError(str(e)) from e

        cost = compute_cost(model_id, resp["prompt_tokens"], resp["completion_tokens"])
        resp["cost_usd"] = cost
        resp["model"]    = model_id
        self._end_run(
            run_id, status="completed", model=model_id,
            prompt_tokens=resp["prompt_tokens"],
            completion_tokens=resp["completion_tokens"],
            cost_usd=cost,
        )
        return resp

    # ── memory ──────────────────────────────────────────────────────
    def remember(self, ctx: AgentContext, key: str, value: Any) -> None:
        if self.db is None:
            return
        self.db.execute(
            "INSERT OR REPLACE INTO agent_memory"
            "(job_id, agent, key, value_json, created_at, updated_at) "
            "VALUES (?,?,?,?,datetime('now'),datetime('now'))",
            (ctx.job_id, self.name, key, json.dumps(value, default=str)),
        )
        self.db.commit()

    def recall(self, ctx: AgentContext, key: str, default: Any = None) -> Any:
        if self.db is None:
            return default
        row = self.db.execute(
            "SELECT value_json FROM agent_memory "
            "WHERE job_id=? AND agent=? AND key=?",
            (ctx.job_id, self.name, key),
        ).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row[0])
        except (TypeError, json.JSONDecodeError):
            return default

    # ── SSE emit ────────────────────────────────────────────────────
    def emit_event(self, kind: str, data: Dict) -> None:
        try:
            self._emit(kind, data)
        except Exception:
            pass  # SSE is best-effort

    # ── internals ───────────────────────────────────────────────────
    def _resolve_model(self, tier: str, mode: str) -> str:
        if mode == "local":
            sub = _config_get(f"llm.ollama_{tier}_substitute")
            return sub or _config_get("llm.ollama_default_model", "llama3.1:8b")
        if tier == "opus":
            return _config_get("llm.opus_model", DEFAULT_MODELS["opus"])
        if tier == "haiku":
            return _config_get("llm.haiku_model", DEFAULT_MODELS["haiku"])
        return tier  # passthrough for explicit model IDs

    def _begin_run(self, ctx: Optional[AgentContext], model_id: str) -> Optional[int]:
        if self.db is None or ctx is None:
            return None
        c = self.db.execute(
            "INSERT INTO agent_runs(job_id, agent, model, status) "
            "VALUES (?,?,?,'running')",
            (ctx.job_id, self.name, model_id),
        )
        self.db.commit()
        return c.lastrowid

    def _end_run(
        self,
        run_id: Optional[int],
        status: str = "completed",
        model: Optional[str] = None,
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        cost_usd: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        if self.db is None or run_id is None:
            return
        self.db.execute(
            "UPDATE agent_runs SET status=?, "
            "model=COALESCE(?, model), "
            "prompt_tokens=?, completion_tokens=?, cost_usd=?, "
            "completed_at=datetime('now'), error=? "
            "WHERE id=?",
            (status, model, prompt_tokens, completion_tokens, cost_usd, error, run_id),
        )
        self.db.commit()


# ── helpers (module-level so tests can monkeypatch) ──────────────────
def compute_cost(model_id: str, prompt_tokens: int, completion_tokens: int) -> float:
    prices = MODEL_PRICES.get(model_id, (0.0, 0.0))
    return (prompt_tokens / 1_000_000.0) * prices[0] \
         + (completion_tokens / 1_000_000.0) * prices[1]


def _config_get(key: str, default: Any = None) -> Any:
    """Read from main.py's config helper. Tolerant of import failure
    (lets the agent code import in environments where main hasn't bootstrapped)."""
    try:
        import main as M
        return M.get_config(key, default)
    except Exception:
        return default


def _job_cost_so_far(db: Any, job_id: str) -> float:
    row = db.execute(
        "SELECT COALESCE(SUM(cost_usd), 0) FROM agent_runs "
        "WHERE job_id=? AND status='completed'",
        (job_id,),
    ).fetchone()
    return float(row[0]) if row else 0.0


def _call_anthropic(
    model_id: str,
    system: str,
    messages: List[Dict],
    tools: Optional[List[Dict]],
    max_tokens: int,
) -> Dict:
    try:
        from anthropic import Anthropic
    except ImportError as e:
        raise LLMError("anthropic SDK not installed (pip install anthropic)") from e
    api_key = _config_get("llm.api_key")
    if not api_key:
        raise LLMError("no Claude API key set (config llm.api_key); "
                       "either set one or switch to llm.mode=local for Ollama")
    client = Anthropic(api_key=api_key)
    kwargs = {
        "model": model_id,
        "max_tokens": max_tokens,
        "system": system,
        "messages": messages,
    }
    if tools:
        kwargs["tools"] = tools
    resp = client.messages.create(**kwargs)
    content = ""
    tool_calls: List[Dict] = []
    for block in resp.content:
        btype = getattr(block, "type", None)
        if btype == "text":
            content += block.text
        elif btype == "tool_use":
            tool_calls.append({"id": block.id, "name": block.name, "input": block.input})
    return {
        "content": content,
        "tool_calls": tool_calls,
        "prompt_tokens": resp.usage.input_tokens,
        "completion_tokens": resp.usage.output_tokens,
    }


def _call_ollama(
    model_id: str,
    system: str,
    messages: List[Dict],
    tools: Optional[List[Dict]],
    max_tokens: int,
) -> Dict:
    from .ollama_adapter import call as ollama_call
    return ollama_call(model_id, system, messages, tools, max_tokens=max_tokens)
