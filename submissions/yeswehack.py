"""YesWeHack submission formatter — OWASP-oriented + business-impact narrative."""
from __future__ import annotations

import json
from typing import Dict

from .common import Draft, OWASP_MAP, cvss_meta, cwe, truncate


PLATFORM = "yeswehack"


def format_draft(finding: Dict, program: Dict) -> Draft:
    vector, score, sev = cvss_meta(finding)
    owasp = OWASP_MAP.get(finding.get("vuln_class", ""), "Other")
    title = truncate(finding.get("title") or "Untitled finding", 200)
    parts = [
        f"**OWASP Top 10 (2021):** {owasp}",
        f"**CWE:** {cwe(finding.get('vuln_class', ''))}",
        f"**CVSS 4.0:** `{vector}` → {score} ({sev})" if vector else "",
        "",
        "## Business Impact",
        _business_impact(finding, sev),
        "",
        "## Technical Details",
        finding.get("description") or "",
        "",
        "## Reproduction Steps",
        _steps(finding),
        "",
        "## Proof of Concept",
        _poc(finding),
        "",
        "## Remediation",
        _remediation(finding),
        "",
        "## Evidence",
        "```json",
        json.dumps(finding.get("evidence", {}), indent=2, default=str),
        "```",
    ]
    return Draft(
        platform=PLATFORM,
        title=title,
        body_md="\n".join(p for p in parts if p is not None),
        severity=sev,
        weakness=owasp,
        cvss_vector=vector,
        cvss_score=score,
        extra={"owasp": owasp, "cwe": cwe(finding.get("vuln_class", ""))},
    )


def _business_impact(finding, sev):
    """Narrative for a non-technical reader — required by YWH."""
    vc = finding.get("vuln_class", "")
    canned = {
        "ssrf": ("This vulnerability lets an attacker pivot from the public website "
                 "into internal infrastructure, potentially reaching databases or "
                 "cloud credentials that should never be exposed."),
        "idor": ("Customers' private data can be accessed or modified by anyone with "
                 "a free account, breaking the trust model the service is built on."),
        "graphql": ("Internal data structures and operations are exposed beyond what "
                    "the public product is designed to allow."),
        "xss": ("An attacker can take over a victim's account simply by getting them "
                "to click a link or view affected content — including admin accounts."),
        "jwt": ("Anyone can impersonate any user, including administrators, by "
                "forging authentication tokens the server fails to validate."),
        "takeover": ("An attacker can take control of one of the company's "
                     "subdomains and use it to phish customers under a trusted name."),
    }
    return canned.get(vc, f"Severity assessed as **{sev}** — see technical details.")


def _steps(finding):
    return ("1. As documented in technical details.\n"
            "2. Compare against an unaffected baseline endpoint to confirm.\n")


def _poc(finding):
    ev = finding.get("evidence", {}) or {}
    return f"```\n{ev.get('poc') or ev.get('payload') or '<see evidence block>'}\n```"


def _remediation(finding):
    from .hackerone import _remediation as h1
    return h1(finding)
