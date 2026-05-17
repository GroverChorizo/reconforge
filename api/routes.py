"""
v2 API routes — pure functions over a sqlite3 connection.

Returning plain dicts (not HTTP responses) lets the same code be wired
behind either stdlib ``http.server`` (today) or any framework we adopt
later. Each function corresponds 1:1 to an SPA call site.

  GET /api/attack/heatmap?job=<id>      → attack_heatmap(db, job_id)
  GET /api/findings?job=<id>&class=...  → findings_list(db, job_id, ...)
  GET /api/findings/<id>                → finding_detail(db, finding_id)
  GET /api/submissions/<id>             → submission_detail(db, draft_id)
  POST /api/submissions/<id>/approve    → submission_approve(db, draft_id)
  GET /api/agents/runs?job=<id>         → agent_runs(db, job_id)

The SSE stream (``GET /api/agents/stream?job=``) is implemented in
``api/server.py`` (Phase 11 extraction) because it needs the live emit
hook. This module ships only the request-response endpoints.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional

from attack import heatmap as attack_heatmap_mod


# ── responses ─────────────────────────────────────────────────────
def attack_heatmap(db: sqlite3.Connection, job_id: str) -> Dict[str, Any]:
    """Per-tactic counts + max-confidence + top techniques for the SPA grid."""
    grid = attack_heatmap_mod.aggregate(db, job_id)
    total = attack_heatmap_mod.total_findings(db, job_id)
    return {"job_id": job_id, "tactics": grid, "total_findings": total}


def findings_list(
    db: sqlite3.Connection,
    job_id: str,
    *,
    vuln_class: Optional[str] = None,
    include_dup: bool = False,
    include_child: bool = False,
    limit: int = 200,
) -> Dict[str, Any]:
    """Findings table for a job, with attached technique IDs + draft count."""
    sql = (
        "SELECT id, bug_id, vuln_class, title, confidence, cvss_score, "
        "cvss_vector, bounty_estimate_usd, status, parent_finding_id, "
        "domain, created_at FROM findings WHERE job_id = ?"
    )
    args: List[Any] = [job_id]
    if not include_dup:
        sql += " AND status != 'dup'"
    if not include_child:
        sql += " AND parent_finding_id IS NULL"
    if vuln_class:
        sql += " AND vuln_class = ?"
        args.append(vuln_class)
    sql += " ORDER BY cvss_score DESC NULLS LAST, id ASC LIMIT ?"
    args.append(int(limit))
    rows = db.execute(sql, tuple(args)).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        techs = [
            x["technique_id"] for x in db.execute(
                "SELECT DISTINCT technique_id FROM attack_techniques WHERE finding_id=?",
                (r["id"],),
            ).fetchall()
        ]
        draft_count = db.execute(
            "SELECT COUNT(*) FROM submission_drafts WHERE finding_id=?",
            (r["id"],),
        ).fetchone()[0]
        out.append({
            "id": r["id"], "bug_id": r["bug_id"],
            "vuln_class": r["vuln_class"], "title": r["title"],
            "confidence": r["confidence"],
            "cvss_score": r["cvss_score"], "cvss_vector": r["cvss_vector"],
            "bounty_estimate_usd": r["bounty_estimate_usd"],
            "status": r["status"], "parent_finding_id": r["parent_finding_id"],
            "domain": r["domain"], "created_at": r["created_at"],
            "attack_techniques": techs,
            "draft_count": draft_count,
        })
    return {"job_id": job_id, "findings": out, "count": len(out)}


def finding_detail(db: sqlite3.Connection, finding_id: int) -> Optional[Dict[str, Any]]:
    row = db.execute(
        "SELECT id, bug_id, job_id, domain, subdomain_id, vuln_class, title, "
        "description, evidence_json, confidence, cvss_vector, cvss_score, "
        "bounty_estimate_usd, parent_finding_id, status, created_at, updated_at "
        "FROM findings WHERE id=?", (finding_id,),
    ).fetchone()
    if row is None:
        return None
    techs = [
        {"technique_id": r["technique_id"], "tactic": r["tactic"],
         "sub_technique_id": r["sub_technique_id"],
         "confidence": r["confidence"], "rationale": r["rationale"]}
        for r in db.execute(
            "SELECT technique_id, tactic, sub_technique_id, confidence, rationale "
            "FROM attack_techniques WHERE finding_id=?", (finding_id,),
        ).fetchall()
    ]
    drafts = [
        {"id": r["id"], "platform": r["platform"], "title": r["title"],
         "severity": r["severity"], "weakness": r["weakness"],
         "human_approved": bool(r["human_approved"])}
        for r in db.execute(
            "SELECT id, platform, title, severity, weakness, human_approved "
            "FROM submission_drafts WHERE finding_id=? ORDER BY platform ASC",
            (finding_id,),
        ).fetchall()
    ]
    try:
        evidence = json.loads(row["evidence_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        evidence = {}
    return {
        "id": row["id"], "bug_id": row["bug_id"], "job_id": row["job_id"],
        "domain": row["domain"], "subdomain_id": row["subdomain_id"],
        "vuln_class": row["vuln_class"], "title": row["title"],
        "description": row["description"],
        "evidence": evidence, "confidence": row["confidence"],
        "cvss_vector": row["cvss_vector"], "cvss_score": row["cvss_score"],
        "bounty_estimate_usd": row["bounty_estimate_usd"],
        "parent_finding_id": row["parent_finding_id"],
        "status": row["status"],
        "created_at": row["created_at"], "updated_at": row["updated_at"],
        "attack_techniques": techs,
        "drafts": drafts,
    }


def submission_detail(db: sqlite3.Connection, draft_id: int) -> Optional[Dict[str, Any]]:
    row = db.execute(
        "SELECT id, finding_id, platform, title, body_md, severity, weakness, "
        "obsidian_path, human_approved, created_at "
        "FROM submission_drafts WHERE id=?", (draft_id,),
    ).fetchone()
    if row is None:
        return None
    f_row = db.execute(
        "SELECT bug_id, cvss_vector, cvss_score, vuln_class "
        "FROM findings WHERE id=?", (row["finding_id"],),
    ).fetchone()
    return {
        "id": row["id"],
        "finding_id": row["finding_id"],
        "bug_id": f_row["bug_id"] if f_row else None,
        "platform": row["platform"], "title": row["title"],
        "body_md": row["body_md"],
        "severity": row["severity"], "weakness": row["weakness"],
        "cvss_vector": f_row["cvss_vector"] if f_row else None,
        "cvss_score": f_row["cvss_score"] if f_row else None,
        "vuln_class": f_row["vuln_class"] if f_row else None,
        "obsidian_path": row["obsidian_path"],
        "human_approved": bool(row["human_approved"]),
        "created_at": row["created_at"],
    }


def submission_approve(db: sqlite3.Connection, draft_id: int,
                       approved: bool = True) -> Dict[str, Any]:
    db.execute(
        "UPDATE submission_drafts SET human_approved=? WHERE id=?",
        (1 if approved else 0, draft_id),
    )
    db.commit()
    return {"draft_id": draft_id, "human_approved": approved}


def agent_runs(db: sqlite3.Connection, job_id: str) -> Dict[str, Any]:
    """All agent runs for a job — drives the per-agent status cards in the SPA."""
    rows = db.execute(
        "SELECT id, agent, model, status, prompt_tokens, completion_tokens, "
        "cost_usd, started_at, completed_at, error "
        "FROM agent_runs WHERE job_id=? ORDER BY started_at ASC, id ASC",
        (job_id,),
    ).fetchall()
    runs = [dict(r) for r in rows]
    total_cost = round(sum(float(r.get("cost_usd") or 0) for r in runs), 4)
    return {"job_id": job_id, "runs": runs, "total_cost_usd": total_cost}


def job_overview(db: sqlite3.Connection, job_id: str) -> Dict[str, Any]:
    """Combined snapshot used by the SPA's job-overview screen on first load."""
    return {
        "agents":    agent_runs(db, job_id),
        "heatmap":   attack_heatmap(db, job_id),
        "findings":  findings_list(db, job_id),
    }
