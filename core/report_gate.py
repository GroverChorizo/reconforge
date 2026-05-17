"""Pre-export report-quality gate.

Ten deterministic checks the operator must pass (or explicitly override
with a recorded reason) before a submission draft can be copied to the
clipboard. The 10 lines come straight from CLAUDE.md doctrine + the
methodology brief:

    1. title present + descriptive
    2. summary present
    3. affected asset present
    4. reproduction steps present
    5. impact statement present
    6. evidence present (≥1 observed or verified row)
    7. remediation present
    8. scope verified (finding's domain still in program scope)
    9. no secrets in body (regex sweep)
   10. operator reviewed (has visited the manual checklist tab)

Each check returns ``(passed: bool, reason: str)``. The gate aggregates
them and reports overall pass/fail plus the per-check breakdown.

This module is pure logic — no DB writes. The API layer reads the gate
output, exposes it on the draft detail page, and refuses copy-to-clipboard
when ``passed=False`` unless ``override_reason`` is supplied.
"""
from __future__ import annotations

import re
import sqlite3
from typing import Any, Dict, List, Tuple

from core import programs as _programs


# ── secret-pattern sweep (regex tier, not a full TruffleHog run) ─
# Cheap pattern set covering the most common copy-paste mistakes: API
# keys, JWTs, common cred env-vars. Real secret hunting belongs in v0.3.0
# when TruffleHog enters the pipeline; this is the fast pre-export gate.
_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("aws_access_key",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret",
     re.compile(r"\baws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
                 re.IGNORECASE)),
    ("github_token",
     re.compile(r"\bghp_[A-Za-z0-9]{36,}\b")),
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_=/-]{8,}\.[A-Za-z0-9_=/-]{8,}\.[A-Za-z0-9_=/-]{8,}")),
    ("authorization_header",
     re.compile(r"^\s*authorization\s*:\s*bearer\s+[A-Za-z0-9._=/-]{16,}",
                 re.IGNORECASE | re.MULTILINE)),
    ("password_kv",
     re.compile(r"\bpassword\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.IGNORECASE)),
    ("private_key_block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
]


def detect_secrets(body: str) -> List[Dict[str, Any]]:
    """Return a list of secret-pattern hits in ``body``."""
    if not body:
        return []
    hits: List[Dict[str, Any]] = []
    for name, pat in _SECRET_PATTERNS:
        m = pat.search(body)
        if m:
            hits.append({
                "kind":  name,
                "snippet": m.group(0)[:80],
            })
    return hits


# ── the 10 checks ─────────────────────────────────────────────────
def _check_field(body: str, marker_lower: str) -> bool:
    """True iff body contains the marker line (case-insensitive) AND has
    at least one non-blank line under it."""
    if not body:
        return False
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if marker_lower in line.lower():
            # Look for any non-blank content within the next 8 lines.
            for follow in lines[i + 1: i + 9]:
                if follow.strip():
                    return True
    return False


def run_gate(
    db: sqlite3.Connection,
    draft: Dict[str, Any],
    *,
    operator_reviewed: bool = False,
) -> Dict[str, Any]:
    """Apply the 10 checks and return a structured result.

    ``draft`` is the submission_drafts row enriched with the parent finding
    (the routes layer assembles this — keeps the gate framework-free).
    """
    body  = (draft.get("body_md") or "").strip()
    title = (draft.get("title") or "").strip()
    finding = draft.get("finding") or {}
    domain  = finding.get("domain") or ""
    program_slug = finding.get("program_slug") or draft.get("program_slug")

    checks: List[Dict[str, Any]] = []

    # 1. title
    checks.append({
        "id": "title",
        "label": "Title present + descriptive",
        "passed": bool(title) and len(title) >= 12,
        "reason": "" if title and len(title) >= 12 else
                  "title must be at least 12 characters and describe the vuln class + asset + impact",
    })

    # 2. summary
    has_summary = _check_field(body, "summary") or _check_field(body, "executive summary")
    checks.append({"id": "summary", "label": "Summary present",
                    "passed": has_summary,
                    "reason": "" if has_summary else "no Summary section detected"})

    # 3. affected asset
    has_asset = _check_field(body, "affected asset") or _check_field(body, "affected endpoint")
    checks.append({"id": "asset", "label": "Affected asset present",
                    "passed": has_asset,
                    "reason": "" if has_asset else "no Affected Asset section detected"})

    # 4. reproduction
    has_repro = _check_field(body, "steps to reproduce") or _check_field(body, "reproduction")
    checks.append({"id": "repro", "label": "Reproduction steps present",
                    "passed": has_repro,
                    "reason": "" if has_repro else "no Steps to Reproduce section detected"})

    # 5. impact
    has_impact = _check_field(body, "impact")
    checks.append({"id": "impact", "label": "Impact statement present",
                    "passed": has_impact,
                    "reason": "" if has_impact else "no Impact section detected"})

    # 6. evidence (observed or verified evidence row on the finding)
    fid = finding.get("id")
    ev_count = 0
    if fid is not None:
        ev_count = db.execute(
            "SELECT COUNT(*) FROM finding_evidence "
            "WHERE finding_id=? AND source IN ('observed','verified')",
            (fid,),
        ).fetchone()[0]
    checks.append({"id": "evidence", "label": "Evidence captured (observed or verified)",
                    "passed": ev_count > 0,
                    "reason": "" if ev_count > 0 else
                              "no observed/verified evidence rows attached to this finding"})

    # 7. remediation
    has_remediation = _check_field(body, "remediation") or _check_field(body, "fix")
    checks.append({"id": "remediation", "label": "Remediation suggested",
                    "passed": has_remediation,
                    "reason": "" if has_remediation else "no Remediation section detected"})

    # 8. scope verified
    scope_ok = True
    scope_reason = ""
    if program_slug and domain:
        program = _programs.get_program(db, program_slug)
        if program is None:
            scope_ok = False
            scope_reason = f"program {program_slug!r} not found"
        elif not _programs.domain_in_program(program, domain):
            scope_ok = False
            scope_reason = f"finding domain {domain!r} not in program scope"
    elif not domain:
        scope_ok = False
        scope_reason = "finding has no domain — cannot verify scope"
    checks.append({"id": "scope", "label": "Scope verified",
                    "passed": scope_ok, "reason": scope_reason})

    # 9. no secrets
    secret_hits = detect_secrets(body)
    checks.append({"id": "no_secrets", "label": "No secrets in body",
                    "passed": len(secret_hits) == 0,
                    "reason": "" if not secret_hits else
                              f"detected {len(secret_hits)} suspected secret(s): " +
                              ", ".join(h["kind"] for h in secret_hits),
                    "details": secret_hits})

    # 10. operator reviewed
    checks.append({"id": "reviewed", "label": "Operator has reviewed the manual checklist",
                    "passed": bool(operator_reviewed),
                    "reason": "" if operator_reviewed else
                              "operator must view + acknowledge the manual checklist tab"})

    passed_count = sum(1 for c in checks if c["passed"])
    return {
        "checks": checks,
        "passed_count": passed_count,
        "total": len(checks),
        "passed": passed_count == len(checks),
    }
