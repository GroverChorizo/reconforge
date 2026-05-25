"""Attack-surface analysis and offensive primitives.

Pre-existing read-only analysis modules:
  - mapper:   finding → ATT&CK technique mapping
  - taxonomy: ATT&CK reference data
  - heatmap:  cross-finding visualization helper

Phase B exploitation primitives (each exports ``run(target, opts) -> AttackResult``):
  - replay:     two-account differential for IDOR
  - ssrf:       blind SSRF via Interactsh OOB callback
  - jwt:        alg=none, RS256→HS256 confusion, weak-secret advisory
  - graphql:    introspection, field-suggestion leak, alias-DoS
  - race:       parallel-request differential (race conditions)
  - massassign: extra-field binding probe

Hunter agent calls these uniformly. Scope is enforced by
``core.scope_guard.check`` upstream of any primitive — nothing here
revalidates scope on its own.
"""
from .base import AttackResult, AttackError

# Lazy: callers do `from attack import replay` to keep import-time costs
# low and avoid pulling urllib/threading when only AttackResult is needed.
__all__ = ["AttackResult", "AttackError"]
