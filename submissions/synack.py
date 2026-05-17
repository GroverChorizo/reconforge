"""Synack submission formatter — structured fields, numbered evidence chain."""
from __future__ import annotations

import json
from typing import Dict

from .common import Draft, cvss_meta, cwe, truncate


PLATFORM = "synack"


def format_draft(finding: Dict, program: Dict) -> Draft:
    vector, score, sev = cvss_meta(finding)
    title = truncate(finding.get("title") or "Untitled finding", 200)
    body = json.dumps({
        "title": title,
        "category": cwe(finding.get("vuln_class", "")),
        "severity": sev,
        "cvss_vector": vector,
        "cvss_score": score,
        "description": finding.get("description") or "",
        "reproduction_steps": _steps(finding),
        "proof_of_concept": _poc(finding),
        "impact": finding.get("description") or "",
        "remediation": _remediation(finding),
        "evidence": finding.get("evidence", {}),
    }, indent=2, default=str)
    return Draft(
        platform=PLATFORM,
        title=title,
        body_md=body,    # Synack fields are structured JSON
        severity=sev,
        weakness=cwe(finding.get("vuln_class", "")),
        cvss_vector=vector,
        cvss_score=score,
        extra={"structured_fields": True},
    )


def _steps(finding):
    return [
        "Authenticate to the target (if required).",
        "Reproduce per the proof of concept.",
        "Capture request, response, and any side-effects.",
        "Compare against an unaffected baseline.",
    ]


def _poc(finding):
    ev = finding.get("evidence", {}) or {}
    return ev.get("poc") or ev.get("payload") or "<see evidence>"


def _remediation(finding):
    from .hackerone import _remediation as h1
    return h1(finding)
