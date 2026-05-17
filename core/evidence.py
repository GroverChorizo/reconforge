"""Structured finding evidence with 4-tier source labels.

Source semantics
----------------
* ``observed``      — raw tool/DB output. Immutable. Edits at the API
                       layer return 403. Examples: ``subdomains.http_status``,
                       ``subdomains.http_title``, tool stdout/stderr.
* ``inferred``      — derived by deterministic parser or correlation. Immutable.
                       Examples: takeover fingerprint match ("service=github_pages"),
                       CVSS bucket, ATT&CK keyword match.
* ``ai_hypothesis`` — LLM-generated. Mutable; the operator can promote a row
                       to ``verified`` after manual confirmation. Rendered in
                       its own visual band with an "AI HYPOTHESIS" badge.
* ``verified``      — operator-confirmed. Frozen with ``verified_by`` +
                       ``verified_at``. Counts as evidence in reports.

Transitions
-----------
The only allowed mutation is ``ai_hypothesis → verified`` via
``verify_evidence``. Everything else returns ``EvidenceImmutable``.

Per-playbook source classification
----------------------------------
``record_evidence_dict`` calls ``classify_source(playbook, key)`` to pick
a default source. Takeover fingerprint outputs split between observed
fields (pulled from ``subdomains`` rows) and inferred fields (the
fingerprint-match itself). All LLM playbooks → ``ai_hypothesis``.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


VALID_SOURCES = ("observed", "inferred", "ai_hypothesis", "verified")
IMMUTABLE_SOURCES = ("observed", "inferred")


class EvidenceImmutable(Exception):
    """Raised when an UPDATE/DELETE is attempted on observed/inferred rows."""


@dataclass
class Evidence:
    id: int
    finding_id: int
    key: str
    value: str
    source: str
    source_ref: Optional[str] = None
    created_at: str = ""
    verified_by: Optional[str] = None
    verified_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        # Re-hydrate JSON values where possible — UIs prefer typed payloads.
        try:
            parsed_value: Any = json.loads(self.value)
        except (TypeError, json.JSONDecodeError):
            parsed_value = self.value
        return {
            "id": self.id, "finding_id": self.finding_id,
            "key": self.key, "value": parsed_value,
            "source": self.source, "source_ref": self.source_ref,
            "created_at": self.created_at,
            "verified_by": self.verified_by, "verified_at": self.verified_at,
        }


# ── source classification per playbook ────────────────────────────
# Each entry: playbook → {field_key → source}. Unmapped keys fall through
# to PLAYBOOK_DEFAULT_SOURCE; unknown playbooks default to ai_hypothesis.
PLAYBOOK_FIELD_SOURCES: Dict[str, Dict[str, str]] = {
    "takeover": {
        "subdomain_id":  "observed",
        "http_status":   "observed",
        "title":         "observed",
        "cname_targets": "observed",
        "cname_matched": "inferred",
        "service":       "inferred",
    },
}

PLAYBOOK_DEFAULT_SOURCE: Dict[str, str] = {
    "takeover": "inferred",  # deterministic playbook overall
    # everything else (LLM playbooks) → ai_hypothesis below
}


def classify_source(playbook: str, key: str) -> str:
    """Pick the source label for a (playbook, evidence-key) pair."""
    pmap = PLAYBOOK_FIELD_SOURCES.get(playbook) or {}
    if key in pmap:
        return pmap[key]
    return PLAYBOOK_DEFAULT_SOURCE.get(playbook, "ai_hypothesis")


# ── writes ────────────────────────────────────────────────────────
def record_evidence(
    db: sqlite3.Connection,
    finding_id: int,
    key: str,
    value: Any,
    source: str,
    source_ref: Optional[str] = None,
) -> int:
    """Insert a single evidence row. Returns the new row id.

    ``value`` is JSON-encoded when not a string so dicts/lists round-trip.
    """
    if source not in VALID_SOURCES:
        raise ValueError(f"invalid source {source!r}; expected one of {VALID_SOURCES}")
    payload = value if isinstance(value, str) else json.dumps(value, default=str)
    cur = db.execute(
        "INSERT INTO finding_evidence(finding_id, key, value, source, source_ref) "
        "VALUES (?,?,?,?,?)",
        (finding_id, key, payload, source, source_ref),
    )
    db.commit()
    return cur.lastrowid


def record_evidence_dict(
    db: sqlite3.Connection,
    finding_id: int,
    evidence: Dict[str, Any],
    *,
    playbook: str,
    source_ref: Optional[str] = None,
) -> List[int]:
    """Bulk-write an evidence dict using per-playbook source classification."""
    if not evidence:
        return []
    ref = source_ref or f"playbook:{playbook}"
    ids: List[int] = []
    for key, value in evidence.items():
        src = classify_source(playbook, key)
        ids.append(record_evidence(db, finding_id, key, value, src, ref))
    return ids


def verify_evidence(
    db: sqlite3.Connection, evidence_id: int, operator: str,
) -> Evidence:
    """Promote an ``ai_hypothesis`` row to ``verified``.

    Returns the post-update row. Raises EvidenceImmutable on observed/inferred
    rows; verifying an already-verified row is a no-op (idempotent).
    """
    row = db.execute(
        "SELECT * FROM finding_evidence WHERE id=?", (evidence_id,)
    ).fetchone()
    if row is None:
        raise ValueError(f"evidence {evidence_id} not found")
    src = row["source"]
    if src in IMMUTABLE_SOURCES:
        raise EvidenceImmutable(
            f"cannot verify {src!r} evidence (only ai_hypothesis is mutable)"
        )
    if src == "verified":
        return _row_to_evidence(row)
    db.execute(
        "UPDATE finding_evidence "
        "SET source='verified', verified_by=?, verified_at=datetime('now') "
        "WHERE id=?",
        (operator or "operator", evidence_id),
    )
    db.commit()
    row = db.execute(
        "SELECT * FROM finding_evidence WHERE id=?", (evidence_id,)
    ).fetchone()
    return _row_to_evidence(row)


# ── reads ─────────────────────────────────────────────────────────
def list_evidence(
    db: sqlite3.Connection, finding_id: int,
) -> Dict[str, List[Dict[str, Any]]]:
    """All evidence for a finding, grouped by source.

    Groups always contain all four source keys (possibly empty lists) so the
    UI can render bands without conditional logic.
    """
    rows = db.execute(
        "SELECT * FROM finding_evidence WHERE finding_id=? "
        "ORDER BY source ASC, key ASC, id ASC",
        (finding_id,),
    ).fetchall()
    grouped: Dict[str, List[Dict[str, Any]]] = {s: [] for s in VALID_SOURCES}
    for r in rows:
        grouped[r["source"]].append(_row_to_evidence(r).to_dict())
    return grouped


def get_evidence(db: sqlite3.Connection, evidence_id: int) -> Optional[Evidence]:
    row = db.execute(
        "SELECT * FROM finding_evidence WHERE id=?", (evidence_id,)
    ).fetchone()
    return _row_to_evidence(row) if row else None


def _row_to_evidence(row: sqlite3.Row) -> Evidence:
    return Evidence(
        id=row["id"], finding_id=row["finding_id"],
        key=row["key"], value=row["value"],
        source=row["source"], source_ref=row["source_ref"],
        created_at=row["created_at"] or "",
        verified_by=row["verified_by"], verified_at=row["verified_at"],
    )


# ── completeness checklist ────────────────────────────────────────
# Phase 19 uses this; included here so evidence concerns live in one
# module. Each key is a label and a predicate over the grouped evidence
# dict; UI renders a ✓/✗ list.
REQUIRED_REPORT_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("affected_url",       "Affected URL"),
    ("reproduction_steps", "Reproduction steps"),
    ("impact",             "Impact statement"),
    ("remediation",        "Suggested remediation"),
)


def report_readiness(grouped: Dict[str, List[Dict[str, Any]]]) -> Dict[str, bool]:
    """Boolean ✓/✗ per REQUIRED_REPORT_FIELDS — true when at least one
    evidence row exists for that key in any non-empty source."""
    present_keys = {row["key"] for rows in grouped.values() for row in rows}
    out: Dict[str, bool] = {}
    for key, _label in REQUIRED_REPORT_FIELDS:
        out[key] = key in present_keys
    out["screenshot"] = any(
        "screenshot" in row["key"].lower() for rows in grouped.values()
        for row in rows
    )
    return out
