"""v2 path dispatcher.

Maps ``/api/v2/*`` request paths to functions in ``api/routes.py``. Returns
``(status, body)`` so the framework wrapper (today: ``main.ReconHandler``)
just serializes to JSON. Keeping this purely functional means tests don't
need an HTTP server.

Add a route by:
  1. Implementing the handler in ``api/routes.py`` (pure function: db + args
     → dict).
  2. Adding a ``Route`` entry below in priority order (more specific paths
     come first; the dispatcher does linear scan and stops on first match).
"""
from __future__ import annotations

import re
import sqlite3
from typing import Any, Callable, Dict, List, Optional, Tuple

from api import routes


# ── route descriptors ─────────────────────────────────────────────
# Each entry: (method, regex over path, handler).
# Handler signature: (db, match, qs, body) -> (status, body_dict)

Body = Optional[Dict[str, Any]]
Handler = Callable[[sqlite3.Connection, "re.Match[str]", Dict[str, Any], Body],
                   Tuple[int, Any]]


# ── handlers ──────────────────────────────────────────────────────
def _h_programs_list(db, _m, _qs, _body):
    out = [p.to_dict() for p in routes.programs_list(db)]
    return 200, {"programs": out, "count": len(out)}


def _h_programs_create(db, _m, _qs, body):
    body = body or {}
    if "name" not in body or "platform" not in body:
        return 400, {"error": "name and platform are required"}
    try:
        program = routes.programs_create(db, body)
    except ValueError as e:
        return 400, {"error": str(e)}
    return 201, {"program": program.to_dict()}


def _h_program_detail(db, m, _qs, _body):
    p = routes.program_detail(db, m.group("slug"))
    if p is None:
        return 404, {"error": f"program not found: {m.group('slug')}"}
    return 200, {"program": p.to_dict()}


def _h_program_delete(db, m, _qs, _body):
    ok = routes.program_delete(db, m.group("slug"))
    if not ok:
        return 404, {"error": f"program not found: {m.group('slug')}"}
    return 200, {"deleted": True, "slug": m.group("slug")}


def _h_program_scope_check(db, m, _qs, body):
    body = body or {}
    target = (body.get("target") or "").strip()
    if not target:
        return 400, {"error": "target is required"}
    return 200, routes.program_scope_check(db, m.group("slug"), target)


def _h_program_blocked_targets(db, m, qs, _body):
    limit = 20
    raw = (qs.get("limit") or [None])[0]
    if raw:
        try:
            limit = max(1, min(200, int(raw)))
        except (TypeError, ValueError):
            limit = 20
    return 200, routes.program_blocked_targets(db, m.group("slug"), limit=limit)


def _h_program_dashboard(db, m, qs, _body):
    limit = 10
    raw = (qs.get("limit") or [None])[0]
    if raw:
        try:
            limit = max(1, min(50, int(raw)))
        except (TypeError, ValueError):
            limit = 10
    out = routes.program_dashboard(db, m.group("slug"), limit=limit)
    if out is None:
        return 404, {"error": f"program not found: {m.group('slug')}"}
    return 200, out


def _h_program_assets(db, m, qs, _body):
    def _flag(name):
        vals = qs.get(name) or []
        if not vals: return False
        return str(vals[0]).lower() in ("1", "true", "yes", "on")
    q = (qs.get("q") or [""])[0] or None
    out = routes.program_assets(
        db, m.group("slug"),
        q=q,
        in_scope_only=_flag("in_scope_only"),
        with_findings_only=_flag("with_findings_only"),
    )
    if out is None:
        return 404, {"error": f"program not found: {m.group('slug')}"}
    return 200, out


def _h_asset_detail(db, m, _qs, _body):
    try:
        sid = int(m.group("sid"))
    except (TypeError, ValueError):
        return 400, {"error": "subdomain id must be an integer"}
    out = routes.asset_detail(db, sid)
    if out is None:
        return 404, {"error": f"asset not found: {sid}"}
    return 200, out


def _h_findings_board(db, m, qs, _body):
    limit = 50
    raw = (qs.get("limit_per_column") or [None])[0]
    if raw:
        try:
            limit = max(1, min(200, int(raw)))
        except (TypeError, ValueError):
            limit = 50
    out = routes.program_findings_board(db, m.group("slug"),
                                          limit_per_column=limit)
    if out is None:
        return 404, {"error": f"program not found: {m.group('slug')}"}
    return 200, out


def _h_finding_detail_v2(db, m, _qs, _body):
    try:
        fid = int(m.group("fid"))
    except (TypeError, ValueError):
        return 400, {"error": "finding id must be an integer"}
    out = routes.finding_detail_v2(db, fid)
    if out is None:
        return 404, {"error": f"finding not found: {fid}"}
    return 200, out


def _h_finding_set_status(db, m, _qs, body):
    body = body or {}
    try:
        fid = int(m.group("fid"))
    except (TypeError, ValueError):
        return 400, {"error": "finding id must be an integer"}
    new_status = (body.get("status") or "").strip()
    operator = (body.get("operator") or "operator").strip() or "operator"
    out = routes.finding_set_status(db, fid, new_status, operator=operator)
    if not out.get("ok"):
        kind = out.get("kind")
        if kind == "not_found":
            return 404, out
        return 400, out
    return 200, out


def _h_submission_quality_gate(db, m, qs, _body):
    try:
        did = int(m.group("did"))
    except (TypeError, ValueError):
        return 400, {"error": "draft id must be an integer"}
    reviewed = (qs.get("reviewed") or ["0"])[0].lower() in ("1", "true", "yes", "on")
    out = routes.submission_quality_gate(db, did, operator_reviewed=reviewed)
    if out is None:
        return 404, {"error": f"draft not found: {did}"}
    return 200, out


def _h_finding_evidence_list(db, m, _qs, _body):
    try:
        fid = int(m.group("fid"))
    except (TypeError, ValueError):
        return 400, {"error": "finding id must be an integer"}
    out = routes.finding_evidence_list(db, fid)
    if out is None:
        return 404, {"error": f"finding not found: {fid}"}
    return 200, out


def _h_finding_evidence_verify(db, m, _qs, body):
    body = body or {}
    try:
        fid = int(m.group("fid"))
        eid = int(m.group("eid"))
    except (TypeError, ValueError):
        return 400, {"error": "ids must be integers"}
    operator = (body.get("operator") or "").strip() or "operator"
    out = routes.finding_evidence_verify(db, fid, eid, operator)
    if not out.get("ok"):
        # Pick a sensible status: not-found → 404, immutable → 409,
        # mismatch → 400.
        err = out.get("error", "")
        if "not found" in err:
            return 404, out
        if "does not belong" in err:
            return 400, out
        return 409, out
    return 200, out


def _h_tool_health(_db, _m, qs, _body):
    # qs values arrive as lists from urllib.parse.parse_qs
    def _flag(name: str) -> bool:
        vals = qs.get(name) or []
        if not vals:
            return False
        return str(vals[0]).lower() in ("1", "true", "yes", "on")
    return 200, routes.tool_health(refresh=_flag("refresh"),
                                    version_probe=_flag("version_probe"))


def _h_tool_install_plan(_db, _m, _qs, _body):
    return 200, routes.tool_install_plan()


def _h_workflows_list(_db, _m, _qs, _body):
    return 200, routes.workflows_list()


def _h_workflow_detail(_db, m, _qs, _body):
    out = routes.workflow_detail(m.group("id"))
    if out is None:
        return 404, {"error": f"workflow not found: {m.group('id')}"}
    return 200, {"workflow": out}


def _h_jobs_preflight(db, _m, _qs, body):
    body = body or {}
    out = routes.jobs_preflight(db, body)
    # Even when allowed=False we return 200 — the body carries the reason
    # and the SPA renders it in the pre-flight modal. 400 is reserved for
    # malformed requests.
    if "program_slug" not in body and "tool" not in body and "target" not in body:
        return 400, {"error": "program_slug, target, and tool are required"}
    return 200, out


# ── route table ───────────────────────────────────────────────────
# Tuple: (method, compiled regex, handler).
# More specific paths come first; the dispatcher does linear scan.
ROUTES: List[Tuple[str, "re.Pattern[str]", Handler]] = [
    ("GET",    re.compile(r"^/api/v2/programs$"),                            _h_programs_list),
    ("POST",   re.compile(r"^/api/v2/programs$"),                            _h_programs_create),
    ("POST",   re.compile(r"^/api/v2/programs/(?P<slug>[^/]+)/scope_check$"), _h_program_scope_check),
    ("GET",    re.compile(r"^/api/v2/programs/(?P<slug>[^/]+)/blocked_targets$"),
                                                                             _h_program_blocked_targets),
    ("GET",    re.compile(r"^/api/v2/programs/(?P<slug>[^/]+)/dashboard$"),  _h_program_dashboard),
    ("GET",    re.compile(r"^/api/v2/programs/(?P<slug>[^/]+)/assets$"),     _h_program_assets),
    ("GET",    re.compile(r"^/api/v2/assets/(?P<sid>\d+)$"),                 _h_asset_detail),
    ("GET",    re.compile(r"^/api/v2/programs/(?P<slug>[^/]+)/findings_board$"),
                                                                             _h_findings_board),
    ("GET",    re.compile(r"^/api/v2/findings/(?P<fid>\d+)$"),               _h_finding_detail_v2),
    ("POST",   re.compile(r"^/api/v2/findings/(?P<fid>\d+)/status$"),        _h_finding_set_status),
    ("GET",    re.compile(r"^/api/v2/submissions/(?P<did>\d+)/quality_gate$"),
                                                                             _h_submission_quality_gate),
    ("DELETE", re.compile(r"^/api/v2/programs/(?P<slug>[^/]+)$"),            _h_program_delete),
    ("GET",    re.compile(r"^/api/v2/programs/(?P<slug>[^/]+)$"),            _h_program_detail),
    ("GET",    re.compile(r"^/api/v2/findings/(?P<fid>\d+)/evidence$"),     _h_finding_evidence_list),
    ("POST",   re.compile(r"^/api/v2/findings/(?P<fid>\d+)/evidence/(?P<eid>\d+)/verify$"),
                                                                             _h_finding_evidence_verify),
    ("GET",    re.compile(r"^/api/v2/tools/health$"),                        _h_tool_health),
    ("POST",   re.compile(r"^/api/v2/tools/install_plan$"),                  _h_tool_install_plan),
    ("GET",    re.compile(r"^/api/v2/workflows$"),                           _h_workflows_list),
    ("GET",    re.compile(r"^/api/v2/workflows/(?P<id>[^/]+)$"),             _h_workflow_detail),
    ("POST",   re.compile(r"^/api/v2/jobs/preflight$"),                      _h_jobs_preflight),
]


# ── dispatcher ────────────────────────────────────────────────────
def dispatch(
    method: str,
    path: str,
    qs: Dict[str, Any],
    body: Body,
    db: sqlite3.Connection,
) -> Tuple[int, Any]:
    """Look up a handler for (method, path). Returns (status, body)."""
    for m, pat, handler in ROUTES:
        if m != method:
            continue
        match = pat.match(path)
        if match:
            try:
                return handler(db, match, qs, body)
            except sqlite3.Error as e:
                return 500, {"error": f"db error: {e}"}
            except Exception as e:  # noqa: BLE001 — defensive, last-resort guard
                return 500, {"error": f"unhandled: {type(e).__name__}: {e}"}
    return 404, {"error": f"v2 route not found: {method} {path}"}
