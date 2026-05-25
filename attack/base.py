"""Shared base for attack/* exploitation primitives.

Each primitive module (replay, ssrf, jwt, graphql, race, massassign) exports
a single ``run(target, opts) -> AttackResult`` function so the Hunter agent
can call them uniformly. Modules are minimum-viable today (Phase B); the
real-world hardening — Interactsh polling, hashcat secret cracking, full
Turbo-Intruder semantics — lands in Phase E when agents drive the chain.

Scope is enforced by ``core/scope_guard.py`` upstream of any module here;
nothing in this folder revalidates scope itself. Callers must ensure
``target`` is in-scope.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class AttackResult:
    """Uniform return type for every primitive in ``attack/``.

    Field semantics:
      technique  — short identifier ("idor", "ssrf", "jwt", "graphql",
                   "race", "massassign"); matches the module filename.
      success    — True iff the primitive observed evidence of the
                   vulnerability. False on negative findings AND on
                   inconclusive/errored runs (use ``error`` to discriminate).
      confidence — 0.0–1.0. 0.9+ → high-confidence finding; 0.6–0.9
                   → analyst review; <0.6 → telemetry only.
      evidence   — list of dicts. Each entry is a structured request/
                   response pair, observed signal, or correlated OOB hit.
                   Hunter writes these into the ``findings`` table.
      summary    — single-sentence operator-facing description.
      error      — populated iff the primitive could not complete (missing
                   token, network error, dependency missing). On error,
                   success is False and confidence is 0.
    """
    technique: str
    success:    bool
    confidence: float = 0.0
    evidence:   List[Dict[str, Any]] = field(default_factory=list)
    summary:    str = ""
    error:      Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AttackError(RuntimeError):
    """Raised internally by primitives when an input is malformed beyond
    the module's ability to return a meaningful AttackResult. Callers
    should catch and translate; never surface to UI."""


def _result_error(technique: str, msg: str) -> AttackResult:
    """Helper: build an error result that the Hunter agent can treat as a
    skipped probe rather than a crash."""
    return AttackResult(
        technique=technique, success=False, confidence=0.0,
        evidence=[], summary=f"{technique}: skipped ({msg})", error=msg,
    )
