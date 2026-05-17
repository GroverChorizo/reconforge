"""Finding status state machine + manual-verification checklist loader.

Status workflow (Phase 19):

    new ─┬─→ needs_review ─┬─→ confirmed ──→ draft_ready ──→ submitted
         │                  └─→ false_positive                 │
         │                                                     ├─→ retesting ─→ closed
         └─→ false_positive                                    └─→ closed
    dup (analyst-flagged)

``findings.status`` has no CHECK constraint at the schema level (CLAUDE.md
doctrine — keep migrations forward-only and avoid the SQLite table-rebuild
dance). Allowed values are enforced at the API layer via ``set_status``.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, FrozenSet, Optional


ALLOWED_STATUSES: FrozenSet[str] = frozenset({
    "new", "needs_review", "confirmed", "false_positive",
    "draft_ready", "submitted", "retesting", "closed", "dup",
})

# Canonical Kanban column order — used by the board view.
KANBAN_COLUMNS = (
    "new", "needs_review", "confirmed",
    "draft_ready", "submitted", "retesting", "closed",
    "false_positive",
)

# Forward transitions advertised to the UI. Operator can override (the API
# accepts any allowed status), but the UI warns when moving "backwards".
STATUS_FORWARD_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    "new":            frozenset({"needs_review", "false_positive"}),
    "needs_review":   frozenset({"confirmed", "false_positive"}),
    "confirmed":      frozenset({"draft_ready", "false_positive"}),
    "draft_ready":    frozenset({"submitted"}),
    "submitted":      frozenset({"retesting", "closed"}),
    "retesting":      frozenset({"closed", "confirmed"}),
    "closed":         frozenset(),
    "false_positive": frozenset({"new"}),  # operator can revive
    "dup":            frozenset(),
}


class InvalidStatus(ValueError):
    """Raised when a status string is not in :data:`ALLOWED_STATUSES`."""


def is_forward(from_status: str, to_status: str) -> bool:
    return to_status in STATUS_FORWARD_TRANSITIONS.get(from_status, frozenset())


def set_status(
    db: sqlite3.Connection, finding_id: int, new_status: str,
    *, operator: Optional[str] = None,
) -> Dict[str, Any]:
    """Update a finding's status. Returns the post-update row dict.

    Raises:
      InvalidStatus if ``new_status`` is not allowed.
      ValueError if ``finding_id`` does not exist.
    """
    if new_status not in ALLOWED_STATUSES:
        raise InvalidStatus(
            f"invalid status {new_status!r}; allowed: {sorted(ALLOWED_STATUSES)}"
        )
    row = db.execute("SELECT id, status FROM findings WHERE id=?",
                     (finding_id,)).fetchone()
    if row is None:
        raise ValueError(f"finding {finding_id} not found")
    old = row["status"]
    db.execute(
        "UPDATE findings SET status=?, updated_at=datetime('now') WHERE id=?",
        (new_status, finding_id),
    )
    db.commit()
    # Note: A per-change audit trail isn't recorded here. ``findings.status``
    # + ``updated_at`` give the current state; if a future phase needs
    # history, add a dedicated ``finding_status_history`` table — don't
    # smear the audit into agent_memory (UNIQUE(job_id, agent, key) is
    # designed for one-row-per-slot scratchpad, not an event log).
    return {
        "id":   finding_id,
        "from": old, "to": new_status,
        "is_forward": is_forward(old, new_status),
        "operator":   operator or "operator",
    }


# ── Manual verification checklists ────────────────────────────────
# Markdown templates live alongside the Hunter playbooks. Each file is
# named after the vuln_class. Methodology-brief content distilled into
# operator checklists. Loaded lazily and cached in-memory.
_CHECKLIST_DIR = Path(__file__).resolve().parent.parent / "agents" / "playbooks" / "manual"
_CHECKLIST_CACHE: Dict[str, str] = {}


def manual_checklist(vuln_class: str) -> Optional[str]:
    """Return the raw markdown checklist for ``vuln_class``, or None when
    the class has no curated checklist yet."""
    key = (vuln_class or "").lower().strip()
    if not key:
        return None
    if key in _CHECKLIST_CACHE:
        return _CHECKLIST_CACHE[key]
    path = _CHECKLIST_DIR / f"{key}.md"
    if not path.exists():
        return None
    content = path.read_text(encoding="utf-8")
    _CHECKLIST_CACHE[key] = content
    return content


def list_checklists() -> Dict[str, str]:
    """Return mapping of vuln_class → checklist path for every curated
    checklist on disk."""
    if not _CHECKLIST_DIR.is_dir():
        return {}
    out: Dict[str, str] = {}
    for p in _CHECKLIST_DIR.glob("*.md"):
        out[p.stem] = str(p)
    return out
