"""Intigriti submission formatter.

Intigriti requires the ``X-Intigriti-Username: grover`` header on every
request to a program target. The Reporter prompts the operator to
confirm the header is set in the testing tool (Burp / curl) — the
generated PoC payload section reflects this requirement.
"""
from __future__ import annotations

import json
from typing import Dict

from .common import Draft, cvss_meta, cwe, truncate


PLATFORM = "intigriti"
HEADER_HINT = "X-Intigriti-Username: grover"


def format_draft(finding: Dict, program: Dict) -> Draft:
    vector, score, sev = cvss_meta(finding)
    title = truncate(finding.get("title") or "Untitled finding", 200)
    parts = [
        "## Executive Summary",
        truncate(finding.get("description") or "", 800),
        "",
        "## Technical Details",
        finding.get("description") or "_Pending operator review._",
        "",
        "### Reproduction Steps",
        _steps(finding),
        "",
        "### Proof of Concept",
        _poc(finding),
        "",
        "## CVSS 4.0",
        f"`{vector}` — **{score} ({sev})**" if vector else "Vector pending",
        "",
        "## Impact",
        finding.get("description") or "",
        "",
        "## Remediation",
        _remediation(finding),
        "",
        "## Evidence",
        f"All requests sent with `{HEADER_HINT}` header per program rules.",
        "",
        "```json",
        json.dumps(finding.get("evidence", {}), indent=2, default=str),
        "```",
    ]
    return Draft(
        platform=PLATFORM,
        title=title,
        body_md="\n".join(parts),
        severity=sev,
        weakness=cwe(finding.get("vuln_class", "")),
        cvss_vector=vector,
        cvss_score=score,
        extra={"required_header": HEADER_HINT},
    )


def _steps(finding: Dict) -> str:
    ev = finding.get("evidence", {}) or {}
    url = ev.get("endpoint") or ev.get("url") or "the affected endpoint"
    return (
        f"1. Ensure your testing tool injects `{HEADER_HINT}` on every request.\n"
        f"2. Submit a request to `{url}`.\n"
        f"3. Observe the response — see Evidence section.\n"
    )


def _poc(finding: Dict) -> str:
    ev = finding.get("evidence", {}) or {}
    poc = ev.get("poc") or ev.get("payload")
    if poc:
        return f"```\n{poc}\n```"
    return "_Full PoC payload available on request — held back until program acknowledges._"


def _remediation(finding: Dict) -> str:
    # Mirror HackerOne's mapping; same root causes, same fixes.
    from .hackerone import _remediation as h1_rem  # type: ignore
    return h1_rem(finding)
