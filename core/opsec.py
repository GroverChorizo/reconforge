"""
OPSEC primitives. Phase 3 ships the tactic-execution boundary; Phase 7
will extend this module with the shared rate-limiter, proxy gate, and
kill-switch hooks.

THE BOUNDARY (CLAUDE.md doctrine + plan section 5):
  Mapping/reporting findings across all 14 ATT&CK tactics is unrestricted.
  TOOL EXECUTION is fenced to TA0043 Reconnaissance + TA0042 Resource
  Development. Any tool wrapper that would map to a tactic outside that
  set MUST call assert_execution_allowed(technique_id) and raise
  ExecutionBoundaryError on violation.

  This is not advisory — it is the difference between bug bounty research
  and unauthorized access. Bypassing this gate is an OPSEC violation.
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
    """Raised when an attempted tool action falls outside the allowed tactics."""


class ModeViolation(RuntimeError):
    """Raised when a tool invocation does not match the active operator mode."""


def is_execution_allowed(technique_id: str) -> bool:
    """True iff the technique maps to at least one allowed tactic.

    Unknown technique IDs return True (don't block on missing taxonomy data).
    Callers that want strict behavior should validate the ID first.
    """
    tech = taxonomy.get_technique(technique_id)
    if tech is None:
        return True
    tactics = tech.get("tactics", [])
    return any(t in EXEC_ALLOWED_TACTICS for t in tactics)


def assert_execution_allowed(technique_id: str, context: Optional[str] = None) -> None:
    if is_execution_allowed(technique_id):
        return
    tech = taxonomy.get_technique(technique_id) or {}
    tactics = tech.get("tactics", [])
    raise ExecutionBoundaryError(
        f"execution boundary violated: {technique_id} "
        f"({tech.get('name', '?')}) maps to {tactics}, "
        f"outside allowed set {sorted(EXEC_ALLOWED_TACTICS)}"
        + (f" [context: {context}]" if context else "")
    )


def filter_executable(technique_ids: Iterable[str]) -> list[str]:
    """Return only the technique IDs that are allowed for execution."""
    return [t for t in technique_ids if is_execution_allowed(t)]


# ── Phase 15: operator-mode gate ──────────────────────────────────
def assert_tool_allowed(tool_name: str, mode: str) -> None:
    """Raise ModeViolation if ``tool_name``'s safety_class is not in ``mode``'s
    allowlist. Imports are deferred to avoid a circular import between
    ``tools/registry`` and this module — registry imports opsec, opsec only
    imports registry inside this gate.
    """
    from tools import registry as _registry
    if not _registry.is_tool_allowed_in_mode(tool_name, mode):
        cls = _registry.safety_class_of(tool_name)
        allowed = sorted(_registry.MODE_ALLOWLISTS.get(mode, frozenset()))
        raise ModeViolation(
            f"mode {mode!r} does not allow {tool_name!r} (safety_class={cls!r}); "
            f"this mode permits {allowed}"
        )


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

    try:
        assert_tool_allowed(tool_name, mode)
        allowed = True
        reason = f"mode {mode!r} allows safety_class={safety!r}"
    except ModeViolation as e:
        allowed = False
        reason = str(e)

    return {
        "allowed":         allowed,
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
