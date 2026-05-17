"""
ATT&CK taxonomy loader.

Reads the vendored data/attack-stix-mirror.json snapshot. The mapper
(attack.mapper) and the OPSEC boundary (core.opsec) both consume this.

Refresh policy: snapshot is updated manually via `reconforge attack refresh`
(Phase 11). v1 ships a curated subset focused on web/API/cloud findings —
all 14 tactics covered, ~50 techniques.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "attack-stix-mirror.json"


@lru_cache(maxsize=1)
def _load() -> Dict:
    return json.loads(_DATA_FILE.read_text(encoding="utf-8"))


# ── public surface ────────────────────────────────────────────────
def tactics() -> List[Dict]:
    """All 14 tactics in canonical ordering (Reconnaissance → Impact)."""
    return list(_load()["tactics"])


def techniques() -> List[Dict]:
    return list(_load()["techniques"])


def tactic_ids() -> List[str]:
    return [t["id"] for t in tactics()]


def get_tactic(tactic_id: str) -> Optional[Dict]:
    for t in tactics():
        if t["id"] == tactic_id:
            return t
    return None


def get_technique(technique_id: str) -> Optional[Dict]:
    """Looks up by exact ID; sub-techniques like T1552.005 work directly."""
    for t in techniques():
        if t["id"] == technique_id:
            return t
    return None


def tactic_name(tactic_id: str) -> str:
    t = get_tactic(tactic_id)
    return t["name"] if t else tactic_id


def split_sub(technique_id: str) -> tuple[str, Optional[str]]:
    """T1552.005 → ('T1552', 'T1552.005'). T1190 → ('T1190', None)."""
    if "." in technique_id:
        parent = technique_id.split(".", 1)[0]
        return parent, technique_id
    return technique_id, None


def techniques_for_tactic(tactic_id: str) -> List[Dict]:
    return [t for t in techniques() if tactic_id in t.get("tactics", [])]


def version() -> str:
    return _load().get("version", "unknown")


# ════════════════════════════════════════════════════════════════
#  Phase 14 — CWE + OWASP companion taxonomy
# ════════════════════════════════════════════════════════════════
# Distinct namespace from the ATT&CK STIX accessors above. Bug-bounty
# reports want all three taxonomies; ATT&CK lives in attack_techniques,
# CWE/OWASP live in finding_taxonomy.
#
# Each VULN_CLASS_TAXONOMY entry is (taxonomy_kind, code, name). Codes
# are the canonical published identifiers (CWE-639, A01:2021). Names are
# the published titles so the SPA can render without a second lookup.
from typing import Tuple  # noqa: E402

TaxonomyEntry = Tuple[str, str, str]  # (kind, code, name)


VULN_CLASS_TAXONOMY: Dict[str, List[TaxonomyEntry]] = {
    "idor": [
        ("cwe",   "CWE-639",   "Authorization Bypass Through User-Controlled Key"),
        ("cwe",   "CWE-284",   "Improper Access Control"),
        ("owasp", "A01:2021",  "Broken Access Control"),
    ],
    "ssrf": [
        ("cwe",   "CWE-918",   "Server-Side Request Forgery"),
        ("owasp", "A10:2021",  "Server-Side Request Forgery"),
    ],
    "graphql": [
        ("cwe",   "CWE-200",   "Information Exposure"),
        ("cwe",   "CWE-863",   "Incorrect Authorization"),
        ("owasp", "A01:2021",  "Broken Access Control"),
        ("owasp", "A05:2021",  "Security Misconfiguration"),
    ],
    "xss": [
        ("cwe",   "CWE-79",    "Improper Neutralization of Input During Web Page Generation"),
        ("owasp", "A03:2021",  "Injection"),
    ],
    "jwt": [
        ("cwe",   "CWE-345",   "Insufficient Verification of Data Authenticity"),
        ("cwe",   "CWE-347",   "Improper Verification of Cryptographic Signature"),
        ("owasp", "A02:2021",  "Cryptographic Failures"),
        ("owasp", "A07:2021",  "Identification and Authentication Failures"),
    ],
    "bizlogic": [
        ("cwe",   "CWE-840",   "Business Logic Errors"),
        ("owasp", "A04:2021",  "Insecure Design"),
    ],
    "takeover": [
        ("cwe",   "CWE-1188",  "Insecure Default Initialization of Resource"),
        ("owasp", "A05:2021",  "Security Misconfiguration"),
    ],
    "api_misconfig": [
        ("cwe",   "CWE-915",   "Improperly Controlled Modification of Object Attributes"),
        ("cwe",   "CWE-16",    "Configuration"),
        ("owasp", "A05:2021",  "Security Misconfiguration"),
        ("owasp", "A08:2021",  "Software and Data Integrity Failures"),
    ],
    "open_redirect": [
        ("cwe",   "CWE-601",   "URL Redirection to Untrusted Site"),
        ("owasp", "A01:2021",  "Broken Access Control"),
    ],
    "cors": [
        ("cwe",   "CWE-942",   "Permissive Cross-domain Policy"),
        ("owasp", "A05:2021",  "Security Misconfiguration"),
    ],
    "csrf": [
        ("cwe",   "CWE-352",   "Cross-Site Request Forgery"),
        ("owasp", "A01:2021",  "Broken Access Control"),
    ],
    "sqli": [
        ("cwe",   "CWE-89",    "SQL Injection"),
        ("owasp", "A03:2021",  "Injection"),
    ],
    "rce": [
        ("cwe",   "CWE-78",    "OS Command Injection"),
        ("cwe",   "CWE-94",    "Improper Control of Generation of Code"),
        ("owasp", "A03:2021",  "Injection"),
    ],
    "xxe": [
        ("cwe",   "CWE-611",   "Improper Restriction of XML External Entity"),
        ("owasp", "A05:2021",  "Security Misconfiguration"),
    ],
}


def lookup_taxonomy(vuln_class: str) -> List[TaxonomyEntry]:
    """Deterministic CWE/OWASP lookup for a vuln_class. Returns [] when unknown."""
    return list(VULN_CLASS_TAXONOMY.get((vuln_class or "").lower(), []))


def persist_taxonomy_for_finding(
    conn, finding_id: int, vuln_class: str,
) -> List[TaxonomyEntry]:
    """Write CWE + OWASP rows to finding_taxonomy. Idempotent — clears prior rows.

    Caller commits.
    """
    entries = lookup_taxonomy(vuln_class)
    conn.execute(
        "DELETE FROM finding_taxonomy WHERE finding_id=? AND taxonomy IN ('cwe','owasp')",
        (finding_id,),
    )
    for kind, code, name in entries:
        conn.execute(
            "INSERT INTO finding_taxonomy(finding_id, taxonomy, code, name, "
            "confidence, source) VALUES (?,?,?,?,?,?)",
            (finding_id, kind, code, name, 1.0, "rule"),
        )
    return entries
