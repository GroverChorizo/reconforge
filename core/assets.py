"""Asset hierarchy for the Phase 18 tree view.

Until program_id propagates onto every table, "an asset belongs to this
program" is decided by ``programs.domain_in_program`` — same predicate
the dashboard uses. The tree shape mirrors what the SPA renders:

    program
      └── root_domain
            └── subdomain {http_status, http_title, technologies, ips,
                           screenshot, finding_count, scope_status}

Filters
-------
* ``q`` — substring match against subdomain text.
* ``in_scope_only`` — drop ambiguous / blocked rows.
* ``with_findings_only`` — keep only subdomains with ≥1 finding.

Output is a list of root-domain nodes (not a dict) so the SPA renders
in document order. Each node lists subdomain children sorted by
``subdomain`` ASC.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional

from core import programs as programs_mod


def _safe_json(blob: Optional[str], default):
    if not blob:
        return default
    try:
        return json.loads(blob)
    except (TypeError, json.JSONDecodeError):
        return default


def _root_domain(host: str) -> str:
    """Extract the apex from a subdomain. Naive — splits on '.' and takes
    the last two labels. Good enough for the tree grouping; not a public
    suffix list resolver."""
    parts = (host or "").lower().split(".")
    if len(parts) <= 2:
        return host or ""
    return ".".join(parts[-2:])


def build_asset_tree(
    db: sqlite3.Connection,
    program: "programs_mod.Program",
    *,
    q: Optional[str] = None,
    in_scope_only: bool = False,
    with_findings_only: bool = False,
) -> List[Dict[str, Any]]:
    rows = db.execute(
        "SELECT id, domain, subdomain, http_status, http_title, "
        "http_technologies, ip_addresses, screenshot_path, "
        "dns_resolved, created_at "
        "FROM subdomains ORDER BY domain ASC, subdomain ASC"
    ).fetchall()

    # Finding counts per subdomain_id — single query, in-memory join.
    counts: Dict[int, int] = {}
    for r in db.execute(
        "SELECT subdomain_id, COUNT(*) AS n FROM findings "
        "WHERE subdomain_id IS NOT NULL GROUP BY subdomain_id"
    ).fetchall():
        counts[r["subdomain_id"]] = r["n"]

    # Group by root_domain.
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    needle = (q or "").strip().lower()
    for r in rows:
        sub = r["subdomain"] or ""
        if needle and needle not in sub.lower():
            continue
        if not programs_mod.domain_in_program(program, sub):
            # `in_scope_only` is implicit here — out-of-program rows
            # never appear in the tree.
            continue
        scope_result = programs_mod.scope_check(db, program.slug, sub)
        scope_status = scope_result.get("scope_status", "unknown")
        if in_scope_only and scope_status != "in":
            continue
        finding_count = counts.get(r["id"], 0)
        if with_findings_only and finding_count == 0:
            continue

        node = {
            "id":            r["id"],
            "subdomain":     sub,
            "http_status":   r["http_status"],
            "http_title":    r["http_title"] or "",
            "technologies":  _safe_json(r["http_technologies"], []),
            "ip_addresses":  _safe_json(r["ip_addresses"], []),
            "screenshot_path": r["screenshot_path"] or "",
            "dns_resolved":  bool(r["dns_resolved"]),
            "scope_status":  scope_status,
            "finding_count": finding_count,
            "created_at":    r["created_at"],
        }
        root = _root_domain(sub)
        grouped.setdefault(root, []).append(node)

    out: List[Dict[str, Any]] = []
    for root in sorted(grouped.keys()):
        out.append({
            "root_domain": root,
            "subdomain_count": len(grouped[root]),
            "subdomains":  grouped[root],
        })
    return out


def asset_detail(db: sqlite3.Connection, subdomain_id: int) -> Optional[Dict[str, Any]]:
    """Per-asset detail pane payload: full row + recent findings + nuclei summary."""
    row = db.execute(
        "SELECT * FROM subdomains WHERE id=?", (subdomain_id,),
    ).fetchone()
    if row is None:
        return None
    findings = [
        dict(r) for r in db.execute(
            "SELECT id, bug_id, vuln_class, title, confidence, cvss_score, status "
            "FROM findings WHERE subdomain_id=? ORDER BY created_at DESC LIMIT 50",
            (subdomain_id,),
        ).fetchall()
    ]
    return {
        "id":              row["id"],
        "domain":          row["domain"],
        "subdomain":       row["subdomain"],
        "http_status":     row["http_status"],
        "http_title":      row["http_title"] or "",
        "technologies":    _safe_json(row["http_technologies"], []),
        "ip_addresses":    _safe_json(row["ip_addresses"], []),
        "nuclei_findings": _safe_json(row["nuclei_findings"], []),
        "nikto_results":   _safe_json(row["nikto_results"], []),
        "screenshot_path": row["screenshot_path"] or "",
        "dns_resolved":    bool(row["dns_resolved"]),
        "interesting":     bool(row["interesting"]),
        "created_at":      row["created_at"],
        "updated_at":      row["updated_at"],
        "findings":        findings,
    }
