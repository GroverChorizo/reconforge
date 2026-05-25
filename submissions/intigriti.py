"""Intigriti submission formatter.

Intigriti requires the ``X-Intigriti-Username: <handle>`` header on every
request to a program target. The operator's handle comes from the
``platform_handle`` field on the program scope (populated during the
first-run wizard). The Reporter prompts the operator to confirm the
header is set in the testing tool (Burp / curl) — the generated PoC
payload section reflects this requirement.
"""
from __future__ import annotations

import json
from typing import Dict

from .common import Draft, cvss_meta, cwe, truncate


PLATFORM = "intigriti"


def _header_hint(program: Dict) -> str:
    """Build the required header from the program's platform_handle.

    Fails loud on missing handle — submitting a report without
    ``X-Intigriti-Username`` violates Intigriti program rules, and
    silently inserting a stale default would be worse than crashing.
    """
    handle = (program.get("platform_handle") or "").strip()
    if not handle:
        raise ValueError(
            "Intigriti report requires program.platform_handle. "
            "Run the setup wizard or set it on the program record."
        )
    return f"X-Intigriti-Username: {handle}"


def format_draft(finding: Dict, program: Dict) -> Draft:
    header_hint = _header_hint(program)
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
        _steps(finding, header_hint),
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
        f"All requests sent with `{header_hint}` header per program rules.",
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
        extra={"required_header": header_hint},
    )


def _steps(finding: Dict, header_hint: str) -> str:
    ev = finding.get("evidence", {}) or {}
    url = ev.get("endpoint") or ev.get("url") or "the affected endpoint"
    return (
        f"1. Ensure your testing tool injects `{header_hint}` on every request.\n"
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
