"""
v2 API routes — pure functions over a sqlite3 connection.

Returning plain dicts (not HTTP responses) lets the same code be wired
behind either stdlib ``http.server`` (today) or any framework we adopt
later. Each function corresponds 1:1 to an SPA call site.

  GET    /api/v2/programs                                 → programs_list(db)
  POST   /api/v2/programs                                 → programs_create(db, body)
  GET    /api/v2/programs/<slug>                          → program_detail(db, slug)
  DELETE /api/v2/programs/<slug>                          → program_delete(db, slug)
  POST   /api/v2/programs/<slug>/scope_check              → program_scope_check(db, slug, target)
  GET    /api/attack/heatmap?job=<id>                     → attack_heatmap(db, job_id)
  GET    /api/findings?job=<id>&class=...                 → findings_list(db, job_id, ...)
  GET    /api/findings/<id>                               → finding_detail(db, finding_id)
  GET    /api/submissions/<id>                            → submission_detail(db, draft_id)
  POST   /api/submissions/<id>/approve                    → submission_approve(db, draft_id)
  GET    /api/agents/runs?job=<id>                        → agent_runs(db, job_id)

The SSE stream (``GET /api/agents/stream?job=``) is implemented in
``api/server.py`` (Phase 11 extraction) because it needs the live emit
hook. This module ships only the request-response endpoints.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional

from attack import heatmap as attack_heatmap_mod
from core import programs as programs_mod
from core import evidence as evidence_mod
from core import opsec as opsec_mod
from core import workflows as workflows_mod
from core import assets as assets_mod
from core import findings as findings_mod
from core import report_gate as report_gate_mod
from tools import detect as tools_detect
from tools import registry as tools_registry


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


# ── v3 programs ────────────────────────────────────────────────────
def programs_list(db: sqlite3.Connection):
    """All programs, most-recently-updated first."""
    return programs_mod.list_programs(db)


def programs_create(db: sqlite3.Connection, body: Dict[str, Any]):
    """Create a program from a paste-JSON payload.

    Recognized keys: name, platform, platform_handle, policy_url,
    scope (or in_scope), out_of_scope, bounty_ranges, contacts, notes, slug.
    """
    return programs_mod.create_program(
        db,
        name=body.get("name", ""),
        platform=body.get("platform", ""),
        platform_handle=body.get("platform_handle", ""),
        policy_url=body.get("policy_url", ""),
        scope=body.get("scope") or body.get("in_scope") or [],
        out_of_scope=body.get("out_of_scope") or [],
        bounty_ranges=body.get("bounty_ranges") or {},
        contacts=body.get("contacts") or {},
        notes=body.get("notes", ""),
        slug=body.get("slug"),
    )


def program_detail(db: sqlite3.Connection, id_or_slug):
    return programs_mod.get_program(db, id_or_slug)


def program_delete(db: sqlite3.Connection, id_or_slug) -> bool:
    return programs_mod.delete_program(db, id_or_slug)


def program_scope_check(db: sqlite3.Connection, id_or_slug, target: str) -> Dict[str, Any]:
    return programs_mod.scope_check(db, id_or_slug, target)


def program_blocked_targets(
    db: sqlite3.Connection, id_or_slug, *, limit: int = 20,
) -> Dict[str, Any]:
    """Recent scope_guard rejections — feeds the Mission Control widget."""
    items = programs_mod.blocked_targets(db, limit=limit, program_slug=str(id_or_slug))
    return {"blocked": items, "count": len(items)}


def program_assets(
    db: sqlite3.Connection, id_or_slug,
    *, q: Optional[str] = None,
    in_scope_only: bool = False,
    with_findings_only: bool = False,
) -> Optional[Dict[str, Any]]:
    """Hierarchical asset tree for the Phase 18 view."""
    program = programs_mod.get_program(db, id_or_slug)
    if program is None:
        return None
    tree = assets_mod.build_asset_tree(
        db, program, q=q,
        in_scope_only=in_scope_only,
        with_findings_only=with_findings_only,
    )
    return {
        "program_slug":    program.slug,
        "tree":            tree,
        "root_count":      len(tree),
        "subdomain_count": sum(n["subdomain_count"] for n in tree),
    }


def asset_detail(db: sqlite3.Connection, subdomain_id: int) -> Optional[Dict[str, Any]]:
    return assets_mod.asset_detail(db, subdomain_id)


# ── v3 finding triage board ────────────────────────────────────────
def program_findings_board(
    db: sqlite3.Connection, id_or_slug,
    *, limit_per_column: int = 50,
) -> Optional[Dict[str, Any]]:
    """Findings bucketed into Kanban columns, filtered to program scope."""
    program = programs_mod.get_program(db, id_or_slug)
    if program is None:
        return None
    rows = db.execute(
        "SELECT id, bug_id, job_id, domain, subdomain_id, vuln_class, "
        "title, confidence, cvss_vector, cvss_score, bounty_estimate_usd, "
        "status, parent_finding_id, created_at, updated_at "
        "FROM findings ORDER BY confidence DESC, updated_at DESC"
    ).fetchall()

    # Pre-compute draft counts in one query.
    draft_counts: Dict[int, int] = {}
    for r in db.execute(
        "SELECT finding_id, COUNT(*) AS n FROM submission_drafts GROUP BY finding_id"
    ).fetchall():
        draft_counts[r["finding_id"]] = r["n"]

    columns: Dict[str, list] = {c: [] for c in findings_mod.KANBAN_COLUMNS}
    columns["dup"] = []  # tracked separately on the right side of the board
    counts: Dict[str, int] = {c: 0 for c in columns}

    for r in rows:
        if not programs_mod.domain_in_program(program, r["domain"] or ""):
            continue
        col = r["status"] if r["status"] in columns else "new"
        counts[col] += 1
        if len(columns[col]) >= limit_per_column:
            continue
        # Confidence label for the card.
        c = r["confidence"] or 0.0
        if c >= 0.7:   label = "high"
        elif c >= 0.4: label = "medium"
        else:          label = "low"
        columns[col].append({
            "id":            r["id"],
            "bug_id":        r["bug_id"],
            "title":         r["title"],
            "vuln_class":    r["vuln_class"],
            "confidence":    c,
            "confidence_label": label,
            "cvss_score":    r["cvss_score"],
            "bounty_estimate_usd": r["bounty_estimate_usd"],
            "draft_count":   draft_counts.get(r["id"], 0),
            "domain":        r["domain"],
            "updated_at":    r["updated_at"],
        })

    return {
        "program_slug":  program.slug,
        "columns":       columns,
        "counts":        counts,
        "total":         sum(counts.values()),
    }


def finding_set_status(
    db: sqlite3.Connection, finding_id: int, new_status: str,
    *, operator: str = "operator",
) -> Dict[str, Any]:
    """Update a finding's status. Returns ok/error envelope so HTTP layer
    can pick the right status code."""
    try:
        out = findings_mod.set_status(db, finding_id, new_status, operator=operator)
    except findings_mod.InvalidStatus as e:
        return {"ok": False, "error": str(e), "kind": "invalid_status"}
    except ValueError as e:
        return {"ok": False, "error": str(e), "kind": "not_found"}
    return {"ok": True, **out}


def submission_quality_gate(
    db: sqlite3.Connection, draft_id: int,
    *, operator_reviewed: bool = False,
) -> Optional[Dict[str, Any]]:
    """Run the 10-check quality gate on a submission draft. Returns the
    structured result the SPA renders next to the body editor."""
    draft = submission_detail(db, draft_id)
    if draft is None:
        return None
    # Enrich with finding row + program_slug for the scope check.
    finding = db.execute(
        "SELECT id, domain, vuln_class, bug_id, status FROM findings "
        "WHERE id=?", (draft["finding_id"],),
    ).fetchone()
    if finding is None:
        return None
    # Program slug: walk subdomain → scope check across all programs is
    # expensive. Quickest path: look at completed_jobs.program_id linked
    # to the finding's job, or check the most-recently-updated program
    # that contains this domain. Pragmatic: pick the first program whose
    # scope matches.
    program_slug = None
    for p in programs_mod.list_programs(db):
        if programs_mod.domain_in_program(p, finding["domain"] or ""):
            program_slug = p.slug
            break
    finding_dict = dict(finding)
    finding_dict["program_slug"] = program_slug
    draft["finding"] = finding_dict
    return report_gate_mod.run_gate(db, draft, operator_reviewed=operator_reviewed)


def finding_detail_v2(db: sqlite3.Connection, finding_id: int) -> Optional[Dict[str, Any]]:
    """Bundled finding detail for Phase 19 detail page.

    Combines the legacy detail (finding row + evidence_json + ATT&CK + drafts)
    with Phase 14's structured evidence + taxonomy and Phase 19's manual
    checklist. One round-trip for the detail tabs.
    """
    legacy = finding_detail(db, finding_id)
    if legacy is None:
        return None
    evidence = finding_evidence_list(db, finding_id) or {
        "evidence": {}, "taxonomy": [], "readiness": {},
    }
    return {
        **legacy,
        "evidence":  evidence["evidence"],
        "taxonomy":  evidence["taxonomy"],
        "readiness": evidence["readiness"],
        "manual_checklist_md": findings_mod.manual_checklist(legacy["vuln_class"]),
        "valid_statuses": sorted(findings_mod.ALLOWED_STATUSES),
        "forward_transitions": sorted(findings_mod.STATUS_FORWARD_TRANSITIONS.get(
            legacy["status"], frozenset())),
    }


# ── v3 mission control dashboard ───────────────────────────────────
def program_dashboard(
    db: sqlite3.Connection, id_or_slug, *, limit: int = 10,
) -> Optional[Dict[str, Any]]:
    """Bundled response for the Mission Control landing widgets.

    One round-trip instead of 8 parallel ones. Each widget can drill into
    its own endpoint for richer detail; this is the "above the fold"
    snapshot.

    Filtering by program: until ``program_id`` propagates to ``agent_runs``
    + ``subdomains`` + ``findings``, this endpoint matches by the rows'
    ``domain`` field against the program's scope rules. Best-effort — a
    finding whose ``domain`` was set to a string outside the scope is
    excluded even if it "morally" belongs to this program.
    """
    program = programs_mod.get_program(db, id_or_slug)
    if program is None:
        return None

    # ── helpers ─────────────────────────────────────────────────────
    def _in_program(domain_str: str) -> bool:
        return programs_mod.domain_in_program(program, domain_str)

    # ── scope summary ──────────────────────────────────────────────
    # Counts come from two sources: how many rules of each kind the
    # program defines, and how many observed subdomains land in each
    # bucket. The donut renders both.
    rule_in_count  = len(program.scope or [])
    rule_out_count = len(program.out_of_scope or [])

    sub_rows = db.execute(
        "SELECT domain, subdomain, http_status, http_title, ip_addresses, "
        "created_at FROM subdomains "
        "ORDER BY created_at DESC"
    ).fetchall()
    assets_in = 0
    assets_blocked = 0
    assets_ambiguous = 0
    recent_assets: List[Dict[str, Any]] = []
    for r in sub_rows:
        status = programs_mod.scope_check(db, program.slug, r["subdomain"])["scope_status"]
        if status == "in":
            assets_in += 1
        elif status == "blocked":
            assets_blocked += 1
        elif status == "ambiguous":
            assets_ambiguous += 1
        # Only the in-scope assets are surfaced in the "recent assets"
        # widget — the ambiguous + blocked counts feed the donut but
        # don't clutter the recent feed.
        if status == "in" and len(recent_assets) < limit:
            recent_assets.append({
                "subdomain":  r["subdomain"],
                "http_status": r["http_status"],
                "http_title":  r["http_title"] or "",
                "scope_status": status,
                "created_at":  r["created_at"],
            })

    scope_summary = {
        "rule_in_count":       rule_in_count,
        "rule_out_count":      rule_out_count,
        "assets_in":           assets_in,
        "assets_blocked":      assets_blocked,
        "assets_ambiguous":    assets_ambiguous,
    }

    # ── active jobs ────────────────────────────────────────────────
    # Until agent_runs carries program_id, the widget shows system-wide
    # running jobs. UX impact is small — operators rarely run multi-
    # program in parallel — and the cost of filtering wrong is higher
    # than the cost of showing one extra row.
    active_rows = db.execute(
        "SELECT job_id, agent, model, status, started_at "
        "FROM agent_runs WHERE status='running' "
        "ORDER BY started_at DESC LIMIT ?", (int(limit),),
    ).fetchall()
    active_jobs = [dict(r) for r in active_rows]

    # ── new finding candidates ─────────────────────────────────────
    finding_rows = db.execute(
        "SELECT id, bug_id, job_id, domain, vuln_class, title, confidence, "
        "cvss_score, bounty_estimate_usd, status, created_at "
        "FROM findings WHERE status='new' AND confidence >= 0.6 "
        "ORDER BY confidence DESC, created_at DESC"
    ).fetchall()
    new_findings: List[Dict[str, Any]] = []
    for r in finding_rows:
        if not _in_program(r["domain"] or ""):
            continue
        new_findings.append(dict(r))
        if len(new_findings) >= limit:
            break

    # ── tool health (cached internally) ───────────────────────────
    health = tool_health()  # full payload — caller can drill in
    tool_summary = health.get("summary", {})

    # ── next best actions ──────────────────────────────────────────
    # Strategist writes a JSON list to agent_memory(agent='strategist',
    # key='next_actions') per job. The widget surfaces the most recent
    # set across all jobs that touched a domain in this program.
    next_rows = db.execute(
        "SELECT job_id, value_json, COALESCE(updated_at, created_at) AS ts "
        "FROM agent_memory WHERE agent='strategist' AND key='next_actions' "
        "ORDER BY ts DESC LIMIT 1"
    ).fetchall()
    next_best_actions: List[Dict[str, Any]] = []
    for r in next_rows:
        try:
            payload = json.loads(r["value_json"])
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(payload, list):
            for a in payload[:limit]:
                if isinstance(a, str):
                    next_best_actions.append({"text": a, "job_id": r["job_id"], "ts": r["ts"]})
                elif isinstance(a, dict):
                    next_best_actions.append({**a, "job_id": r["job_id"], "ts": r["ts"]})
        elif isinstance(payload, dict):
            next_best_actions.append({**payload, "job_id": r["job_id"], "ts": r["ts"]})

    # ── reports ready ──────────────────────────────────────────────
    # submission_drafts joined to findings; filter by domain-in-program
    # and human_approved=0.
    draft_rows = db.execute(
        "SELECT d.id, d.finding_id, d.platform, d.title, d.severity, "
        "d.human_approved, d.created_at, f.bug_id, f.domain, f.status AS f_status "
        "FROM submission_drafts d JOIN findings f ON f.id = d.finding_id "
        "WHERE d.human_approved = 0 "
        "ORDER BY d.created_at DESC"
    ).fetchall()
    reports_ready: List[Dict[str, Any]] = []
    for r in draft_rows:
        if not _in_program(r["domain"] or ""):
            continue
        reports_ready.append({
            "id":          r["id"],
            "finding_id":  r["finding_id"],
            "bug_id":      r["bug_id"],
            "platform":    r["platform"],
            "title":       r["title"],
            "severity":    r["severity"],
            "created_at":  r["created_at"],
        })
        if len(reports_ready) >= limit:
            break

    return {
        "program":           program.to_dict(),
        "scope_summary":     scope_summary,
        "active_jobs":       active_jobs,
        "recent_assets":     recent_assets,
        "new_findings":      new_findings,
        "tool_summary":      tool_summary,
        "next_best_actions": next_best_actions,
        "reports_ready":     reports_ready,
    }


# ── v3 evidence + taxonomy ──────────────────────────────────────────
def finding_evidence_list(db: sqlite3.Connection, finding_id: int) -> Optional[Dict[str, Any]]:
    """Grouped evidence + CWE/OWASP taxonomy for a finding detail page."""
    row = db.execute(
        "SELECT id, vuln_class FROM findings WHERE id=?", (finding_id,)
    ).fetchone()
    if row is None:
        return None
    grouped = evidence_mod.list_evidence(db, finding_id)
    taxonomy = [
        dict(r) for r in db.execute(
            "SELECT taxonomy, code, name, confidence, source "
            "FROM finding_taxonomy WHERE finding_id=? "
            "ORDER BY taxonomy ASC, code ASC", (finding_id,),
        ).fetchall()
    ]
    return {
        "finding_id": finding_id,
        "vuln_class": row["vuln_class"],
        "evidence": grouped,
        "taxonomy": taxonomy,
        "readiness": evidence_mod.report_readiness(grouped),
    }


def finding_evidence_verify(
    db: sqlite3.Connection, finding_id: int, evidence_id: int, operator: str,
) -> Dict[str, Any]:
    """Promote an ai_hypothesis evidence row to verified.

    finding_id is checked so the URL hierarchy can't cross-contaminate
    (verifying an evidence row that doesn't belong to the named finding
    is rejected even if the evidence_id exists).
    """
    ev = evidence_mod.get_evidence(db, evidence_id)
    if ev is None:
        return {"ok": False, "error": "evidence not found"}
    if ev.finding_id != finding_id:
        return {"ok": False, "error": "evidence does not belong to this finding"}
    try:
        updated = evidence_mod.verify_evidence(db, evidence_id, operator or "operator")
    except evidence_mod.EvidenceImmutable as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "evidence": updated.to_dict()}


# ── v3 tool health (cached) ─────────────────────────────────────────
_TOOL_HEALTH_CACHE: Dict[str, Any] = {"ts": 0.0, "payload": None}
_TOOL_HEALTH_TTL_SECONDS = 60.0


def tool_health(*, refresh: bool = False, version_probe: bool = False) -> Dict[str, Any]:
    """Detect ReconForge tools on the host. Cached 60s unless refresh=True.

    ``version_probe`` subprocesses each found binary to capture its
    version; off by default because it costs ~24 subprocess spawns.
    """
    import time
    now = time.monotonic()
    cached = _TOOL_HEALTH_CACHE["payload"]
    if (cached and not refresh and not version_probe
            and now - _TOOL_HEALTH_CACHE["ts"] < _TOOL_HEALTH_TTL_SECONDS):
        return cached
    statuses = tools_detect.scan(version_probe=version_probe)
    payload = {
        "tools": [
            {
                "name": s.name, "binary": s.binary,
                "installed": s.installed, "path": s.path,
                "version": s.version, "install_method": s.install_method,
                "install_cmd": s.install_cmd, "notes": s.notes,
                "category": s.category,
            }
            for s in statuses
        ],
        "summary": {
            "total":     len(statuses),
            "installed": sum(1 for s in statuses if s.installed),
            "missing":   sum(1 for s in statuses if not s.installed),
        },
    }
    _TOOL_HEALTH_CACHE["ts"] = now
    _TOOL_HEALTH_CACHE["payload"] = payload
    return payload


def tool_install_plan() -> Dict[str, Any]:
    """Read-only install plan — operator runs commands themselves."""
    return {
        "plan": [list(cmd) for cmd in tools_detect.install_plan()],
        "human": tools_detect.install_plan_human(),
    }


# ── v3 workflows ────────────────────────────────────────────────────
def workflows_list() -> Dict[str, Any]:
    """All registered workflows; SPA renders these in the job-create flow."""
    workflows = [w.to_dict() for w in workflows_mod.list_workflows()]
    return {"workflows": workflows, "count": len(workflows)}


def workflow_detail(workflow_id: str) -> Optional[Dict[str, Any]]:
    w = workflows_mod.get_workflow(workflow_id)
    return w.to_dict() if w else None


# ── v3 preflight ───────────────────────────────────────────────────
def jobs_preflight(db: sqlite3.Connection, body: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the safety envelope for a tool invocation before the SPA shows
    the pre-flight modal.

    Body shape::
        {
          "program_slug": str,
          "target":       str,
          "mode":         str,      # one of OPERATOR_MODES; default passive_recon
          "tool":         str       # one of REGISTRY keys
        }

    Returned dict drives the modal: scope decision + matched rule + per-rule
    method allowlists + RoE excerpt + traffic class + effective rate-limit +
    command preview.
    """
    program_slug = (body.get("program_slug") or "").strip()
    target       = (body.get("target") or "").strip()
    mode         = (body.get("mode") or "passive_recon").strip()
    tool         = (body.get("tool") or "").strip()

    if not program_slug or not target or not tool:
        return {
            "allowed": False,
            "reason": "program_slug, target, and tool are required",
            "scope": None, "mode": mode, "tool": tool,
        }

    # 1. Scope gate (delegates to scope_guard.check). Out-of-scope short-
    #    circuits with no mode/safety detail leaked.
    scope_result = programs_mod.scope_check(db, program_slug, target)
    if not scope_result.get("allowed"):
        return {
            "allowed": False,
            "reason": scope_result.get("reason", "scope refused"),
            "scope": scope_result,
            "mode": mode, "tool": tool,
        }

    matched = scope_result.get("matched") or {}
    if not isinstance(matched, dict):
        matched = {}

    # 2. ScopeRule extras (methodology brief — backwards compat, all optional).
    allowed_methods    = matched.get("allowed_methods")
    disallowed_methods = matched.get("disallowed_methods")
    rate_limit_hint    = matched.get("rate_limit_rps_hint")
    scope_rule_notes   = matched.get("notes")

    # 3. Mode gate + rate-limit envelope.
    pre = opsec_mod.preflight(
        tool, mode,
        rate_limit_hint=rate_limit_hint if isinstance(rate_limit_hint, int) else None,
        target=target,
    )

    # 4. Command preview (uses opsec helper that masks dynamic placeholders).
    cmd_preview = opsec_mod.render_command_preview(tool, target=target)

    # 5. Rules of Engagement excerpt — pulled from the program's free-text
    #    notes field, truncated for the modal.
    program = programs_mod.get_program(db, program_slug)
    roe_excerpt = ""
    if program is not None and program.notes:
        roe_excerpt = program.notes.strip()[:500]

    out: Dict[str, Any] = {
        "allowed":              pre["allowed"],
        "reason":               pre["reason"] if pre["allowed"] else pre["reason"],
        "tool":                 tool,
        "target":               target,
        "mode":                 mode,
        "program_slug":         program_slug,
        "scope": {
            "reason":         scope_result.get("reason"),
            "tier":           scope_result.get("tier"),
            "matched":        matched,
            "platform":       scope_result.get("platform"),
            "headers":        scope_result.get("headers", {}),
        },
        "scope_rule_notes":         scope_rule_notes or "",
        "allowed_methods":          allowed_methods or [],
        "disallowed_methods":       disallowed_methods or [],
        "rules_of_engagement_excerpt": roe_excerpt,
        "safety_class":             pre["safety_class"],
        "traffic_class":            pre["traffic_class"],
        "rate_limit_rps":           pre["rate_limit_rps"],
        "rate_limit_hint":          pre["rate_limit_hint"],
        "timeout_s":                pre["timeout_s"],
        "technique":                pre["technique"],
        "command_preview":          cmd_preview,
    }

    # When mode rejects the tool, still surface the scope rule but mark
    # allowed=False — operator sees why it was blocked.
    return out
