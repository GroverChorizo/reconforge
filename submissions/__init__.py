"""
Per-platform submission formatters.

Each module exports ``format_draft(finding, program) -> Draft`` where
``Draft`` is a small dataclass with title / body_md / severity / weakness
fields. ``REGISTRY`` maps platform name → formatter, so the Reporter
agent dispatches uniformly:

    from submissions import REGISTRY
    fmt = REGISTRY[program["platform"]]
    draft = fmt(finding, program)

Auto-submission is out of scope for v1 — drafts are reviewed via the
SPA's submission preview (Phase 10) and copied by the operator.
"""
from __future__ import annotations

from . import hackerone, intigriti, bugcrowd, yeswehack, synack
from .common import Draft

REGISTRY = {
    "hackerone": hackerone.format_draft,
    "h1":        hackerone.format_draft,
    "intigriti": intigriti.format_draft,
    "bugcrowd":  bugcrowd.format_draft,
    "yeswehack": yeswehack.format_draft,
    "ywh":       yeswehack.format_draft,
    "synack":    synack.format_draft,
}

__all__ = ["Draft", "REGISTRY"]
