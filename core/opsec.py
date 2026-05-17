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

from typing import Iterable, Optional

from attack import taxonomy


EXEC_ALLOWED_TACTICS: frozenset[str] = frozenset({"TA0043", "TA0042"})


class ExecutionBoundaryError(RuntimeError):
    """Raised when an attempted tool action falls outside the allowed tactics."""


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
