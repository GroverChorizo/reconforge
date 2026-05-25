"""
OPSEC primitives. Phase 3 shipped the tactic-execution boundary; Phase 7
will extend this module with the shared rate-limiter, proxy gate, and
kill-switch hooks.

GUARDRAIL POLICY (post-Phase-B build-out, 2026-05-25):
  This module previously refused tool execution outside TA0043/TA0042 and
  refused tools whose safety_class was not allowed in the operator's mode.
  Both refusals are now neutralized — agents pick tools by job context,
  scope_guard is the only execution gate that remains.

  The classification metadata stays: safety_class on every tool spec,
  EXEC_ALLOWED_TACTICS as the "natural recon set", MODE_ALLOWLISTS for the
  per-mode default toolsets. These are advisory — they drive UI signals
  (modal warnings, default playbooks) but never block.

  Scope is enforced by ``scope_guard.check`` / ``programs.scope_check``.
  That is the only thing standing between an in-scope test and a program
  ban; it is NOT neutralized.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from attack import taxonomy


EXEC_ALLOWED_TACTICS: frozenset[str] = frozenset({"TA0043", "TA0042"})


# ── default per-mode rate ceilings (req/s) ────────────────────────
# Used by preflight() when the program's scope rule does not provide a
# rate_limit_rps_hint. Conservative — operator can lower further but not
# bypass.
DEFAULT_MODE_RATE_LIMITS: Dict[str, int] = {
    "passive_recon":       0,    # no requests to target
    "active_recon":        10,
    "content_discovery":   25,   # halved from mod_active default
    "vuln_triage":         25,
    "evidence_collection": 50,
    "report_drafting":     0,
    "retest":              5,
}


class ExecutionBoundaryError(RuntimeError):
    """Legacy: was raised when a tool action fell outside TA0043/TA0042.
    Retained for backwards compatibility with callers that catch it; the
    gate functions below no longer raise this."""


class ModeViolation(RuntimeError):
    """Legacy: was raised when a tool invocation did not match the active
    operator mode. Retained for backwards compatibility with callers that
    catch it; the gate functions below no longer raise this."""


def is_execution_allowed(technique_id: str) -> bool:  # informational
    """True iff the technique maps to at least one tactic in the natural
    recon set. This is *advisory* now — call sites no longer refuse
    execution based on this. Useful for UI badges ("this is exploitation,
    not recon") but not for refusal.

    Unknown technique IDs return True.
    """
    tech = taxonomy.get_technique(technique_id)
    if tech is None:
        return True
    tactics = tech.get("tactics", [])
    return any(t in EXEC_ALLOWED_TACTICS for t in tactics)


def assert_execution_allowed(technique_id: str, context: Optional[str] = None) -> None:
    """No-op kept for API stability. Previously raised
    ExecutionBoundaryError; now returns without effect because tool
    execution is no longer fenced to TA0043/TA0042. Scope is enforced by
    ``scope_guard.check`` upstream of any tool dispatch.
    """
    return None


def filter_executable(technique_ids: Iterable[str]) -> list[str]:
    """No-op filter kept for API stability. Returns the input unchanged
    because execution is no longer fenced by tactic."""
    return list(technique_ids)


# ── Phase 15: operator-mode gate (now advisory only) ──────────────
def assert_tool_allowed(tool_name: str, mode: str) -> None:
    """No-op kept for API stability. Previously raised ModeViolation when
    ``tool_name``'s safety_class fell outside ``mode``'s allowlist; now
    returns without effect because agents pick tools by job context. The
    classification is still available via
    ``tools.registry.safety_class_of`` and
    ``tools.registry.is_tool_allowed_in_mode`` for UI badges and default
    toolset suggestions.
    """
    return None


def preflight(
    tool_name: str,
    mode: str,
    *,
    rate_limit_hint: Optional[int] = None,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    """Compute the safety envelope for a single tool invocation.

    Returns the structure surfaced by ``POST /api/v2/jobs/preflight`` —
    ``allowed`` plus the traffic class, the effective rate-limit (the
    smaller of the program hint and the default ceiling), and an
    advisory ``reason`` describing the decision. Does NOT execute anything;
    the caller chains it with ``programs.scope_check`` for end-to-end gating.
    """
    from tools import registry as _registry
    spec = _registry.REGISTRY.get(tool_name)
    safety = _registry.safety_class_of(tool_name)
    mode_default = DEFAULT_MODE_RATE_LIMITS.get(mode, 5)
    # Effective rate is the minimum of all available ceilings (mode + program
    # hint). Mode default = 0 means "this mode forbids requests" — it is a
    # hard ceiling, not a fallback. A program hint can lower the cap further
    # but never raise it.
    if rate_limit_hint and rate_limit_hint > 0:
        effective_rps = min(rate_limit_hint, mode_default)
    else:
        effective_rps = mode_default

    # Mode gating is now advisory. Surface the classification in the
    # reason field so the modal still shows "this is intrusive" but never
    # blocks execution on it. Scope check (upstream of preflight) is the
    # only refusal.
    from tools import registry as _registry
    in_default_set = _registry.is_tool_allowed_in_mode(tool_name, mode)
    if in_default_set:
        reason = f"mode {mode!r} default set includes safety_class={safety!r}"
    else:
        reason = (f"safety_class={safety!r} is outside mode {mode!r}'s "
                  f"default set — executing anyway (mode gating advisory only)")

    return {
        "allowed":         True,  # mode dimension never blocks now
        "reason":          reason,
        "tool":            tool_name,
        "target":          target,
        "mode":            mode,
        "safety_class":    safety,
        "traffic_class":   safety,            # alias used by the SPA modal
        "rate_limit_rps":  effective_rps,
        "rate_limit_hint": rate_limit_hint,
        "timeout_s":       getattr(spec, "timeout", 0) if spec else 0,
        "technique":       getattr(spec, "technique", "") if spec else "",
    }


def render_command_preview(tool_name: str, target: Optional[str] = None) -> List[str]:
    """Render the command argv as a list of strings for the pre-flight modal.

    Substitutes ``$DOMAIN$``/``$TARGET$`` only — the dynamic placeholders
    that depend on a live job (input file, output path, threads) are left
    in template form so the operator sees the actual variable names. This
    is a *preview*, not a runnable command line.
    """
    from tools import registry as _registry
    spec = _registry.REGISTRY.get(tool_name)
    if spec is None or not spec.cmd_template:
        return []
    tpl = spec.cmd_template
    if target:
        tpl = tpl.replace("$DOMAIN$", target).replace("$TARGET$", target)
    return tpl.split()
