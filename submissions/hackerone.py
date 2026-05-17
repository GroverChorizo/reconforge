"""HackerOne submission formatter — CLAUDE.md doctrine."""
from __future__ import annotations

import json
from typing import Dict

from .common import Draft, cvss_meta, cwe, truncate


PLATFORM = "hackerone"


def format_draft(finding: Dict, program: Dict) -> Draft:
    vector, score, sev = cvss_meta(finding)
    title = _title(finding)
    body = _body(finding, program, vector, score, sev)
    return Draft(
        platform=PLATFORM,
        title=title,
        body_md=body,
        severity=sev,
        weakness=cwe(finding.get("vuln_class", "")),
        cvss_vector=vector,
        cvss_score=score,
        extra={"asset_type": "URL"},
    )


def _title(finding: Dict) -> str:
    raw = (finding.get("title") or "").strip() or "Untitled finding"
    return truncate(raw, 200)


def _body(finding: Dict, program: Dict, vector, score, sev) -> str:
    desc = finding.get("description") or ""
    evidence = finding.get("evidence", {}) or {}
    techniques = finding.get("attack_techniques", []) or []
    parts = [
        "## Summary",
        truncate(desc, 1200),
        "",
        "## Steps to Reproduce",
        _steps(finding),
        "",
        "## Proof of Concept",
        _poc(finding),
        "",
        "## Impact",
        _impact(finding, sev),
        "",
        "## CVSS 4.0",
        f"`{vector}` → **{score} ({sev})**" if vector else "Vector pending",
        "",
        "## Remediation",
        _remediation(finding),
        "",
        "## Evidence",
        "```json",
        json.dumps(evidence, indent=2, default=str),
        "```",
    ]
    if techniques:
        parts += ["", "## ATT&CK Mapping",
                  ", ".join(f"`{t}`" for t in techniques)]
    return "\n".join(parts)


def _steps(finding: Dict) -> str:
    ev = finding.get("evidence", {}) or {}
    url = ev.get("endpoint") or ev.get("url") or ""
    return (
        f"1. Authenticate to the target (if required).\n"
        f"2. Send a request to `{url or 'the affected endpoint'}`.\n"
        f"3. Observe the response — see Evidence section.\n"
    )


def _poc(finding: Dict) -> str:
    ev = finding.get("evidence", {}) or {}
    poc = ev.get("poc") or ev.get("payload")
    if poc:
        return f"```\n{poc}\n```"
    return "_See evidence block — full request/response will be attached after triage acknowledgment._"


def _impact(finding: Dict, sev: str) -> str:
    vc = finding.get("vuln_class", "")
    canned = {
        "ssrf": "An unauthenticated attacker can pivot internal-network requests through the affected service, reach cloud-metadata endpoints, and exfiltrate credentials.",
        "idor": "An authenticated attacker can access or modify resources belonging to other users by manipulating object identifiers.",
        "graphql": "An attacker can leverage missing authorization checks on GraphQL resolvers to read or modify resources outside their session scope.",
        "xss": "An attacker delivering this payload can execute arbitrary JavaScript in a victim's browser, hijacking their session and authenticated actions.",
        "jwt": "An attacker can forge or manipulate JWTs to impersonate arbitrary users, including administrators.",
        "bizlogic": "An attacker can abuse the application's business flow to receive value (credit, items, access) not intended by the design.",
        "takeover": "An attacker can register the dangling resource and serve arbitrary content on a subdomain trusted by users and the parent organization.",
        "api_misconfig": "An attacker can leverage the misconfiguration to bypass intended access controls or extract data not exposed by the documented API surface.",
    }
    return canned.get(vc, f"Severity assessed as **{sev}**. See description for finding-specific impact.")


def _remediation(finding: Dict) -> str:
    vc = finding.get("vuln_class", "")
    return {
        "ssrf": "Validate and allowlist all outbound URLs. Block requests to RFC1918, link-local (169.254.0.0/16), and cloud-metadata IPs.",
        "idor": "Enforce per-request ownership checks: every object access must verify the caller's identity against the resource's owner.",
        "graphql": "Apply authorization decorators on every resolver. Disable introspection in production. Rate-limit per-request alias count.",
        "xss": "Apply context-aware output encoding. Deploy a Content-Security-Policy header that blocks inline script.",
        "jwt": "Reject `alg: none`. Pin the signing algorithm server-side. Validate `exp`, `iss`, `aud`, and `kid` against an allowlist.",
        "bizlogic": "Add server-side invariant checks on transactional flows. Use idempotency keys; lock the resource state machine in a single transaction.",
        "takeover": "Either claim the dangling resource or remove the DNS record. Audit DNS regularly.",
        "api_misconfig": "Audit the API surface against the documented spec. Strip undocumented fields on input. Require explicit security decorators on every route.",
    }.get(vc, "See description.")
