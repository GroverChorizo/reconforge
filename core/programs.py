"""Programs — first-class CRUD + scope_check on top of scope_guard.

A Program is the root context for every v3 surface: the workspace shell,
scope badges, mode-aware job creation, mission control. Scope JSON lives
here once instead of being pasted at every job.

The scope_check() wrapper assembles a program dict in the shape
``scope_guard.check`` expects and delegates to that pure-logic function —
no behavior duplication, single source of truth for the matching rules.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Union

import scope_guard as _sg


_PLATFORMS = {"intigriti", "hackerone", "bugcrowd", "yeswehack", "synack", "other"}
_SLUG_RE = re.compile(r"[^a-z0-9-]+")


@dataclass
class Program:
    id: int
    slug: str
    name: str
    platform: str
    platform_handle: str = ""
    policy_url: str = ""
    scope: List[Dict[str, Any]] = field(default_factory=list)
    out_of_scope: List[Dict[str, Any]] = field(default_factory=list)
    bounty_ranges: Dict[str, Any] = field(default_factory=dict)
    contacts: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_scope_guard_program(self) -> Dict[str, Any]:
        """Reshape into the dict scope_guard.check expects."""
        return {
            "name": self.name,
            "platform": self.platform,
            "platform_handle": self.platform_handle,
            "policy_url": self.policy_url,
            "in_scope": self.scope,
            "out_of_scope": self.out_of_scope,
            "bounty_ranges": self.bounty_ranges,
        }


# ── helpers ───────────────────────────────────────────────────────
def slugify(name: str) -> str:
    s = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-")
    return s or "program"


def _ensure_unique_slug(db: sqlite3.Connection, base: str) -> str:
    slug, i = base, 1
    while db.execute("SELECT 1 FROM programs WHERE slug=?", (slug,)).fetchone():
        i += 1
        slug = f"{base}-{i}"
    return slug


def _row_to_program(row: sqlite3.Row) -> Program:
    def _j(col: str, default):
        try:
            return json.loads(row[col]) if row[col] else default
        except (TypeError, json.JSONDecodeError):
            return default
    return Program(
        id=row["id"],
        slug=row["slug"],
        name=row["name"],
        platform=row["platform"],
        platform_handle=row["platform_handle"] or "",
        policy_url=row["policy_url"] or "",
        scope=_j("scope_json", []),
        out_of_scope=_j("out_of_scope_json", []),
        bounty_ranges=_j("bounty_ranges_json", {}),
        contacts=_j("contacts_json", {}),
        notes=row["notes"] or "",
        created_at=row["created_at"] or "",
        updated_at=row["updated_at"] or "",
    )


# ── CRUD ──────────────────────────────────────────────────────────
def create_program(
    db: sqlite3.Connection,
    *,
    name: str,
    platform: str,
    scope: Optional[List[Dict[str, Any]]] = None,
    out_of_scope: Optional[List[Dict[str, Any]]] = None,
    platform_handle: str = "",
    policy_url: str = "",
    bounty_ranges: Optional[Dict[str, Any]] = None,
    contacts: Optional[Dict[str, Any]] = None,
    notes: str = "",
    slug: Optional[str] = None,
) -> Program:
    """Create a program. Validates platform + scope shape, generates a unique slug."""
    if not name or not name.strip():
        raise ValueError("name is required")
    plat = (platform or "").lower().strip()
    if plat not in _PLATFORMS:
        raise ValueError(
            f"platform must be one of {sorted(_PLATFORMS)}, got {platform!r}"
        )
    base = slugify(slug or name)
    final_slug = _ensure_unique_slug(db, base)

    db.execute(
        "INSERT INTO programs(slug, name, platform, platform_handle, policy_url, "
        "scope_json, out_of_scope_json, bounty_ranges_json, contacts_json, notes) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            final_slug, name.strip(), plat,
            (platform_handle or "").strip(),
            (policy_url or "").strip(),
            json.dumps(scope or []),
            json.dumps(out_of_scope or []),
            json.dumps(bounty_ranges or {}),
            json.dumps(contacts or {}),
            notes or "",
        ),
    )
    db.commit()
    row = db.execute("SELECT * FROM programs WHERE slug=?", (final_slug,)).fetchone()
    return _row_to_program(row)


def list_programs(db: sqlite3.Connection) -> List[Program]:
    rows = db.execute(
        "SELECT * FROM programs ORDER BY updated_at DESC, id DESC"
    ).fetchall()
    return [_row_to_program(r) for r in rows]


def get_program(
    db: sqlite3.Connection, id_or_slug: Union[int, str]
) -> Optional[Program]:
    if isinstance(id_or_slug, int) or (isinstance(id_or_slug, str) and id_or_slug.isdigit()):
        row = db.execute(
            "SELECT * FROM programs WHERE id=?", (int(id_or_slug),)
        ).fetchone()
    else:
        row = db.execute(
            "SELECT * FROM programs WHERE slug=?", (str(id_or_slug),)
        ).fetchone()
    return _row_to_program(row) if row else None


def delete_program(db: sqlite3.Connection, id_or_slug: Union[int, str]) -> bool:
    p = get_program(db, id_or_slug)
    if p is None:
        return False
    db.execute("DELETE FROM programs WHERE id=?", (p.id,))
    db.commit()
    return True


# ── scope check ───────────────────────────────────────────────────
def _derive_scope_status(result: Dict[str, Any]) -> str:
    """Map scope_guard's allowed/reason into a 4-color badge enum.

    in        — explicit in_scope rule matched (green badge)
    blocked   — explicit out_of_scope rule matched (red badge)
    ambiguous — no rule matched either way (yellow badge — operator review)
    unknown   — empty target, unknown program, or other input error (gray)
    """
    if result.get("allowed"):
        return "in"
    reason = (result.get("reason") or "").lower()
    if reason.startswith("out_of_scope"):
        return "blocked"
    if reason == "no in_scope rule matched":
        return "ambiguous"
    return "unknown"


def scope_check(
    db: sqlite3.Connection, id_or_slug: Union[int, str], target: str
) -> Dict[str, Any]:
    """Delegate to scope_guard.check after loading the program row.

    Returns the canonical scope_guard result + the program slug so the UI
    can route blocked attempts back to the relevant program, plus a
    ``scope_status`` derived enum (in|blocked|ambiguous|unknown) that the
    SPA badge component consumes directly.
    """
    program = get_program(db, id_or_slug)
    if program is None:
        result = {
            "allowed": False, "reason": "unknown program",
            "tier": -1, "platform": "", "headers": {}, "matched": None,
            "program_slug": str(id_or_slug),
        }
        result["scope_status"] = _derive_scope_status(result)
        return result
    result = _sg.check(target, program.to_scope_guard_program())
    result["program_slug"] = program.slug
    result["scope_status"] = _derive_scope_status(result)
    return result


def domain_in_program(program: "Program", domain: str) -> bool:
    """Lightweight Python predicate — does ``domain`` match any of the
    program's ``in_scope`` rules (and not any ``out_of_scope`` rule)?

    Avoids the per-row overhead of ``scope_check()`` when filtering
    hundreds of rows on a dashboard. Delegates to ``scope_guard._matches``
    under the hood so doctrine stays in one place.
    """
    if not domain:
        return False
    host = _sg._normalize_host(domain)
    # out_of_scope wins
    for entry in (program.out_of_scope or []):
        if _sg._matches(host, domain, entry):
            return False
    for entry in (program.scope or []):
        if _sg._matches(host, domain, entry):
            return True
    return False


def blocked_targets(
    db: sqlite3.Connection, *, limit: int = 20, program_slug: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Recent scope_guard rejections captured during pipeline runs.

    Reads `agent_memory(agent='scope_guard', key='last_check')` rows where
    the cached check returned `allowed=False`. ScopeGuard short-circuits
    the pipeline on refusal (see `core.pipeline.run_agentic_pipeline`),
    so per-job `last_check` is the only check for a rejected job.

    ``program_slug`` is accepted but currently not enforced — agent_runs
    don't yet carry a program_id FK; that lands in a later phase. The
    parameter is reserved so the SPA can pass it without needing changes
    when the filter is added.
    """
    import json as _json
    rows = db.execute(
        "SELECT job_id, value_json, COALESCE(updated_at, created_at) AS ts "
        "FROM agent_memory WHERE agent='scope_guard' AND key='last_check' "
        "ORDER BY ts DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        try:
            check = _json.loads(r["value_json"])
        except (TypeError, _json.JSONDecodeError):
            continue
        if check.get("allowed"):
            continue
        matched = check.get("matched")
        if isinstance(matched, dict):
            target_repr = matched.get("value", "")
        else:
            target_repr = ""
        out.append({
            "job_id":   r["job_id"],
            "target":   target_repr,
            "reason":   check.get("reason"),
            "platform": check.get("platform"),
            "matched":  matched,
            "scope_status": _derive_scope_status(check),
            "ts":       r["ts"],
        })
    return out
