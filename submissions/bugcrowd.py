"""Bugcrowd submission formatter.

Bugcrowd requires VRT category selection up front — that field
determines the base severity. We surface our VRT pick in the draft and
the operator confirms it before submission.
"""
from __future__ import annotations

import json
from typing import Dict

from .common import BUGCROWD_VRT, Draft, cvss_meta, cwe, truncate


PLATFORM = "bugcrowd"
_MAX_BODY = 25_000   # Bugcrowd description limit


def format_draft(finding: Dict, program: Dict) -> Draft:
    vector, score, sev = cvss_meta(finding)
    vrt = BUGCROWD_VRT.get(finding.get("vuln_class", ""), "Other")
    title = truncate(f"[{vrt.split('>')[-1].strip()}] {finding.get('title') or 'finding'}", 200)
    parts = [
        f"**VRT category:** `{vrt}`",
        f"**Severity:** {sev}" + (f" (CVSS 4.0 {score} — `{vector}`)" if vector else ""),
        "",
        "## Description",
        truncate(finding.get("description") or "", 1500),
        "",
        "## Reproduction Steps",
        _steps(finding),
        "",
        "## Proof of Concept",
        _poc(finding),
        "",
        "## Impact",
        finding.get("description") or "",
        "",
        "## Suggested Fix",
        _remediation(finding),
        "",
        "## Evidence",
        "```json",
        json.dumps(finding.get("evidence", {}), indent=2, default=str),
        "```",
        "",
        "_Researcher severity: see CVSS line above. Bugcrowd triage may override._",
    ]
    body = truncate("\n".join(parts), _MAX_BODY)
    return Draft(
        platform=PLATFORM,
        title=title,
        body_md=body,
        severity=sev,
        weakness=vrt,
        cvss_vector=vector,
        cvss_score=score,
        extra={"vrt": vrt, "cwe": cwe(finding.get("vuln_class", ""))},
    )


def _steps(finding):
    return ("1. Reproduce per the evidence block.\n"
            "2. Capture both request and response.\n"
            "3. Compare against the unaffected baseline.\n")


def _poc(finding):
    ev = finding.get("evidence", {}) or {}
    return f"```\n{ev.get('poc') or ev.get('payload') or '<see evidence block>'}\n```"


def _remediation(finding):
    from .hackerone import _remediation as h1
    return h1(finding)
