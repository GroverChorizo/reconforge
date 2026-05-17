"""
ATT&CK mapper. Finding → list[AttackHit].

Three-tier algorithm:
  1. Rule table per vuln_class — high-confidence canonical mappings.
  2. Keyword scan of title + description + evidence — boosts existing hits
     by +0.1 per match; adds new candidates at 0.4.
  3. LLM disambiguation (Phase 5+) — if max confidence < 0.5 the agent base
     layer is called with a constrained "pick ≤3 from this list" prompt.
     Currently a noop hook returning [] until BaseAgent exists.

Result confidence is capped at 0.95. Returned hits are sorted by confidence
desc and deduped by technique_id (highest confidence wins).

Invocation:
    python -m attack.mapper sample      # synthetic findings → heatmap JSON
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from typing import Callable, Dict, List, Optional

from . import taxonomy


# ── result type ───────────────────────────────────────────────────
@dataclass
class AttackHit:
    tactic: str
    technique_id: str
    sub_technique_id: Optional[str]
    confidence: float
    rationale: str

    def as_row(self) -> Dict:
        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "sub_technique_id": self.sub_technique_id,
            "confidence": round(self.confidence, 3),
            "rationale": self.rationale,
        }


# ── tier 1: rule table ────────────────────────────────────────────
# Each entry: (technique_id, base_confidence, rationale).
# Confidences calibrated so the canonical map per class lands at 0.7–0.95.
RULES: Dict[str, List[tuple]] = {
    "idor": [
        ("T1190",     0.70, "exploited via authenticated web request abuse"),
        ("T1213",     0.60, "unauthorized data access from app information repository"),
    ],
    "ssrf": [
        ("T1190",     0.90, "exploitable weakness in public-facing app"),
        ("T1090",     0.70, "outbound proxying through victim infrastructure"),
        ("T1552.005", 0.80, "cloud instance metadata API exposure path"),
    ],
    "graphql": [
        ("T1190",     0.80, "weakness in public GraphQL endpoint"),
        ("T1213",     0.60, "data from app information repository"),
        ("T1083",     0.40, "schema introspection enumerates resolvers"),
    ],
    "xss": [
        ("T1190",     0.70, "client-side injection in public-facing app"),
        ("T1059",     0.60, "script execution in victim browser context"),
        ("T1203",     0.50, "exploitation for client execution"),
    ],
    "jwt": [
        ("T1552",     0.85, "unsecured credential / token handling"),
        ("T1078",     0.70, "valid accounts abuse via forged tokens"),
    ],
    "bizlogic": [
        ("T1190",     0.60, "logic flaw in public-facing app"),
        ("T1565",     0.70, "data manipulation via business rule abuse"),
    ],
    "takeover": [
        ("T1583.001", 0.95, "subdomain takeover = adversary acquires domain"),
        ("T1071",     0.50, "subsequent C2 over hijacked subdomain"),
        ("T1566",     0.50, "credible phishing surface from hijacked subdomain"),
    ],
    "api_misconfig": [
        ("T1190",     0.70, "weakness in public API surface"),
        ("T1078",     0.60, "mass-assignment privilege escalation"),
        ("T1552",     0.60, "credential exposure via hidden parameters"),
    ],
    "open_redirect": [
        ("T1566",     0.70, "credible phishing chain via trusted-domain redirect"),
        ("T1078",     0.40, "OAuth callback abuse → account takeover"),
    ],
    "cors": [
        ("T1213",     0.65, "cross-origin data theft from info repository"),
        ("T1190",     0.50, "weakness in public-facing app"),
    ],
    "csrf": [
        ("T1190",     0.60, "weakness in public-facing app"),
        ("T1098",     0.50, "account manipulation via forged request"),
    ],
}


# ── tier 2: keyword index ─────────────────────────────────────────
# Each technique gets a list of literal substrings that, if found
# (case-insensitive) in title+description+evidence, boost its confidence.
TECHNIQUE_KEYWORDS: Dict[str, List[str]] = {
    "T1190":     ["sqli", "sql injection", "rce", "lfi", "rfi", "xxe", "ssti",
                  "deserialization", "command injection", "ssrf", "directory traversal"],
    "T1090":     ["proxy", "tunnel", "pivot"],
    "T1552":     ["leaked credential", "exposed secret", "api key", "token",
                  "private key", ".env"],
    "T1552.001": ["credentials in file", "config leak", ".env", "credentials.json"],
    "T1552.004": ["private key", "id_rsa", "pem", "pkcs"],
    "T1552.005": ["169.254.169.254", "metadata.google.internal", "imds",
                  "aws metadata", "ec2 metadata", "cloud metadata"],
    "T1078":     ["account takeover", "auth bypass", "session fixation",
                  "credential stuffing", "valid account"],
    "T1583.001": ["dangling cname", "subdomain takeover", "nxdomain",
                  "github.io", "s3.amazonaws.com", "azurewebsites"],
    "T1071":     ["c2", "command and control", "beacon"],
    "T1566":     ["phishing", "spear phishing"],
    "T1213":     ["wiki", "confluence", "jira", "data leak", "info repository"],
    "T1530":     ["s3 bucket", "public bucket", "gcs bucket", "blob storage"],
    "T1059":     ["script execution", "javascript", "shell"],
    "T1203":     ["browser exploit", "drive-by"],
    "T1505.003": ["webshell", "web shell"],
    "T1110":     ["brute force", "password spray", "rate limit bypass"],
    "T1499":     ["denial of service", "dos", "resource exhaustion",
                  "graphql batching", "alias dos"],
    "T1565":     ["data tampering", "race condition", "negative quantity",
                  "balance manipulation"],
    "T1485":     ["data destruction", "wipe", "delete data"],
    "T1098":     ["account manipulation", "role escalation", "mass assignment"],
    "T1083":     ["directory listing", "introspection", "schema dump", "swagger"],
    "T1046":     ["port scan", "service enumeration"],
    "T1567":     ["exfil", "data exfiltration"],
}


# ── LLM hook (Phase 5+) ───────────────────────────────────────────
# When Phase 5 lands, base agent layer will register a callable here:
#   mapper.set_llm_hook(lambda finding, candidates: [AttackHit(...)])
# Default is noop so the mapper works standalone today.
_LLM_HOOK: Optional[Callable[[Dict, List[Dict]], List[AttackHit]]] = None


def set_llm_hook(hook: Optional[Callable[[Dict, List[Dict]], List[AttackHit]]]) -> None:
    global _LLM_HOOK
    _LLM_HOOK = hook


# ── core ──────────────────────────────────────────────────────────
_CONF_CAP = 0.95
_KEYWORD_BOOST = 0.10
_KEYWORD_NEW = 0.40
_LLM_THRESHOLD = 0.50


def _haystack(finding: Dict) -> str:
    parts = [
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        json.dumps(finding.get("evidence", {}) or finding.get("evidence_json", {})),
    ]
    return " ".join(parts).lower()


def _make_hit(technique_id: str, confidence: float, rationale: str) -> AttackHit:
    tech = taxonomy.get_technique(technique_id)
    parent, sub = taxonomy.split_sub(technique_id)
    if tech is None:
        # graceful: still return a hit but with no tactic info — caller decides
        return AttackHit(tactic="", technique_id=parent,
                         sub_technique_id=sub,
                         confidence=min(confidence, _CONF_CAP),
                         rationale=rationale)
    # techniques can map to multiple tactics; pick the first canonical one.
    tactic = tech["tactics"][0] if tech.get("tactics") else ""
    return AttackHit(
        tactic=tactic,
        technique_id=parent,
        sub_technique_id=sub,
        confidence=min(confidence, _CONF_CAP),
        rationale=rationale,
    )


def map_finding(finding: Dict) -> List[AttackHit]:
    """Map a single finding dict to ATT&CK techniques.

    Expected finding shape (minimum):
        {"vuln_class": "ssrf", "title": "...", "description": "...",
         "evidence": {...}}
    """
    vuln_class = (finding.get("vuln_class") or "other").lower()
    hits: Dict[str, AttackHit] = {}

    # tier 1: rules
    for tech_id, conf, why in RULES.get(vuln_class, []):
        hits[tech_id] = _make_hit(tech_id, conf, why)

    # tier 2: keyword boost / add
    hay = _haystack(finding)
    for tech_id, words in TECHNIQUE_KEYWORDS.items():
        matched = [w for w in words if w.lower() in hay]
        if not matched:
            continue
        if tech_id in hits:
            existing = hits[tech_id]
            new_conf = min(_CONF_CAP, existing.confidence + _KEYWORD_BOOST * len(matched))
            hits[tech_id] = AttackHit(
                tactic=existing.tactic,
                technique_id=existing.technique_id,
                sub_technique_id=existing.sub_technique_id,
                confidence=new_conf,
                rationale=f"{existing.rationale} [+kw: {', '.join(matched)}]",
            )
        else:
            hits[tech_id] = _make_hit(
                tech_id, _KEYWORD_NEW + _KEYWORD_BOOST * (len(matched) - 1),
                f"keyword match: {', '.join(matched)}",
            )

    # tier 3: LLM disambiguation if still uncertain
    max_conf = max((h.confidence for h in hits.values()), default=0.0)
    if _LLM_HOOK is not None and max_conf < _LLM_THRESHOLD:
        candidates = [{"id": t["id"], "name": t["name"], "tactics": t["tactics"]}
                      for t in taxonomy.techniques()]
        try:
            extra = _LLM_HOOK(finding, candidates) or []
            for hit in extra:
                if hit.technique_id not in hits or hit.confidence > hits[hit.technique_id].confidence:
                    hits[hit.technique_id] = hit
        except Exception:
            # LLM failure must not block the deterministic path
            pass

    return sorted(hits.values(), key=lambda h: h.confidence, reverse=True)


# ── persistence helper ────────────────────────────────────────────
def persist_for_finding(conn, finding_id: int, finding: Dict) -> List[AttackHit]:
    """Map a finding and write rows to the attack_techniques table.

    Idempotent: deletes prior rows for this finding before inserting.
    Caller commits.
    """
    hits = map_finding(finding)
    conn.execute("DELETE FROM attack_techniques WHERE finding_id=?", (finding_id,))
    for h in hits:
        conn.execute(
            "INSERT INTO attack_techniques"
            "(finding_id, tactic, technique_id, sub_technique_id, confidence, rationale)"
            " VALUES (?,?,?,?,?,?)",
            (finding_id, h.tactic, h.technique_id, h.sub_technique_id,
             round(h.confidence, 3), h.rationale)
        )
    return hits


# ── CLI ───────────────────────────────────────────────────────────
_SAMPLE_FINDINGS = [
    {"vuln_class": "ssrf",   "title": "SSRF in /api/fetch", "description": "Server fetches user-supplied URL; reaches 169.254.169.254 IMDS"},
    {"vuln_class": "idor",   "title": "User ID enumeration in /api/users/{id}"},
    {"vuln_class": "graphql", "title": "GraphQL introspection enabled"},
    {"vuln_class": "jwt",    "title": "Alg=none accepted on /auth", "description": "JWT signature stripped, token accepted"},
    {"vuln_class": "takeover","title": "Subdomain takeover via dangling CNAME to github.io"},
    {"vuln_class": "xss",    "title": "Stored XSS in /profile/bio"},
    {"vuln_class": "api_misconfig", "title": "Mass assignment allows role=admin"},
    {"vuln_class": "bizlogic","title": "Negative quantity in checkout produces credit"},
    {"vuln_class": "open_redirect","title": "Open redirect on /go?url= chains to OAuth callback"},
    {"vuln_class": "cors",   "title": "CORS Origin: null allowed with credentials"},
]


def _cli(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="attack.mapper")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("sample", help="Map a synthetic finding set, print JSON.")
    pm = sub.add_parser("map", help="Map a single finding from stdin JSON.")
    pm.add_argument("--vuln-class", required=True)
    pm.add_argument("--title", default="")
    pm.add_argument("--description", default="")

    args = p.parse_args(argv)

    if args.cmd == "sample":
        out = []
        for f in _SAMPLE_FINDINGS:
            hits = map_finding(f)
            out.append({"finding": f, "hits": [h.as_row() for h in hits]})
        print(json.dumps(out, indent=2))
        return 0

    if args.cmd == "map":
        f = {"vuln_class": args.vuln_class,
             "title": args.title, "description": args.description}
        hits = map_finding(f)
        print(json.dumps([h.as_row() for h in hits], indent=2))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(_cli())
