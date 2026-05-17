"""Shared types + helpers for platform formatters."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from core import cvss


# Vuln class → CWE primary ID
CWE_MAP: Dict[str, str] = {
    "ssrf":          "CWE-918",
    "idor":          "CWE-639",
    "graphql":       "CWE-639",   # most common manifest; analyst can override
    "xss":           "CWE-79",
    "jwt":           "CWE-345",
    "bizlogic":      "CWE-840",
    "takeover":      "CWE-350",
    "api_misconfig": "CWE-285",
    "open_redirect": "CWE-601",
    "cors":          "CWE-942",
    "csrf":          "CWE-352",
}

# OWASP Top 10 (2021) mapping for YesWeHack
OWASP_MAP: Dict[str, str] = {
    "ssrf":          "A10:2021 — Server-Side Request Forgery",
    "idor":          "A01:2021 — Broken Access Control",
    "graphql":       "A01:2021 — Broken Access Control",
    "xss":           "A03:2021 — Injection",
    "jwt":           "A07:2021 — Identification and Authentication Failures",
    "bizlogic":      "A04:2021 — Insecure Design",
    "takeover":      "A05:2021 — Security Misconfiguration",
    "api_misconfig": "A05:2021 — Security Misconfiguration",
    "open_redirect": "A10:2021 — Server-Side Request Forgery",
    "cors":          "A05:2021 — Security Misconfiguration",
    "csrf":          "A01:2021 — Broken Access Control",
}

# Bugcrowd VRT primary path
BUGCROWD_VRT: Dict[str, str] = {
    "ssrf":          "Server Security Misconfiguration > Server-Side Request Forgery",
    "idor":          "Broken Access Control > Insecure Direct Object Reference",
    "graphql":       "Broken Access Control > Insecure Direct Object Reference",
    "xss":           "Cross-Site Scripting (XSS) > Stored",
    "jwt":           "Broken Authentication and Session Management > Cryptographic Flaws",
    "bizlogic":      "Application-Level Denial-of-Service > Business Logic",
    "takeover":      "Server Security Misconfiguration > Using Default Credentials",
    "api_misconfig": "Server Security Misconfiguration > API Misconfiguration",
    "open_redirect": "Server Security Misconfiguration > Open Redirect",
    "cors":          "Server Security Misconfiguration > CORS",
    "csrf":          "Broken Authentication and Session Management > CSRF",
}


@dataclass
class Draft:
    platform: str
    title: str
    body_md: str
    severity: str
    weakness: str           # CWE / VRT / OWASP — platform-specific
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    extra: Dict[str, Any] = None   # platform-specific metadata


def cvss_meta(finding: Dict) -> tuple[Optional[str], Optional[float], str]:
    """(vector, score, severity-label). Missing/invalid → (None, None, 'Unknown')."""
    vector = finding.get("cvss_vector")
    if vector and cvss.is_valid(vector):
        s = finding.get("cvss_score")
        if s is None:
            s = cvss.score(vector)
        return vector, float(s), cvss.severity(float(s))
    return None, None, "Unknown"


def cwe(vuln_class: str) -> str:
    return CWE_MAP.get(vuln_class, "CWE-Other")


def truncate(text: str, n: int) -> str:
    text = text or ""
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"
