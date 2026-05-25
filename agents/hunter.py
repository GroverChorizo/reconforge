"""
Hunter agent — Haiku 4.5, per-vuln-class playbooks.

Reads ``agent_memory[recon_summary]`` from the Recon agent, selects
playbooks based on observed signals, and runs each. Surviving
candidates (confidence ≥ ``min_confidence``) are persisted to
``findings`` and auto-mapped to ATT&CK techniques via
``attack.mapper.persist_for_finding``.

Hallucination guard
-------------------
Every finding's evidence MUST carry a ``subdomain_id`` that resolves to
a real row in ``subdomains``. Candidates that fail this check are
dropped with a ``hunter.evidence_rejected`` SSE event — the LLM is not
trusted to invent host IDs.

Mixed model
-----------
Seven playbooks call Haiku. **Takeover is fully deterministic** — pure
title-pattern matching against a fingerprint table, no LLM involved.
That's per CLAUDE.md doctrine (subdomain takeover detection is a known
deterministic pipeline; the LLM adds no value).
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent, AgentContext, AgentResult, LLMError, CostCapExceeded
from attack import mapper as attack_mapper
from attack import taxonomy as attack_taxonomy
from core import evidence as evidence_mod


_PROMPT_DIR = Path(__file__).parent / "playbooks"
_DEFAULT_MIN_CONFIDENCE = 0.40
_DEFAULT_MAX_TOKENS = 3000
_MEMORY_KEY_FINDINGS = "findings_summary"


# ── candidate type ────────────────────────────────────────────────
@dataclass
class FindingCandidate:
    vuln_class: str
    title: str
    description: str
    confidence: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    playbook: str = ""


# ── playbook prompt loader ────────────────────────────────────────
def _load_prompt(name: str) -> str:
    return (_PROMPT_DIR / f"{name}.md").read_text(encoding="utf-8")


# ── JSON extraction (mirrors strategist._parse_plan_json) ─────────
def _parse_findings_json(content: str) -> Optional[List[Dict]]:
    """Extract a JSON array of finding objects from an LLM response."""
    if not content:
        return None
    s = content.strip()
    if s.startswith("```"):
        s = s[3:]
        if s.lower().startswith("json"):
            s = s[4:].lstrip("\r\n")
        if s.endswith("```"):
            s = s[:-3]
        s = s.strip()
    start = s.find("[")
    end = s.rfind("]")
    if start < 0 or end <= start:
        # Allow a single-object response — wrap it.
        try:
            single = json.loads(s)
            return [single] if isinstance(single, dict) else None
        except json.JSONDecodeError:
            return None
    try:
        arr = json.loads(s[start:end + 1])
        return arr if isinstance(arr, list) else None
    except json.JSONDecodeError:
        return None


def _coerce_candidate(raw: Dict, playbook: str, fallback_class: str) -> Optional[FindingCandidate]:
    title = (raw.get("title") or "").strip()
    if not title:
        return None
    try:
        conf = float(raw.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    return FindingCandidate(
        vuln_class=(raw.get("vuln_class") or fallback_class).strip().lower(),
        title=title,
        description=(raw.get("description") or "").strip(),
        confidence=max(0.0, min(1.0, conf)),
        evidence=raw.get("evidence") or {},
        playbook=playbook,
    )


# ── helpers: subdomain queries ────────────────────────────────────
def _live_hosts(db: sqlite3.Connection, domain: str) -> List[sqlite3.Row]:
    return db.execute(
        "SELECT id, subdomain, http_status, http_title, http_technologies, ip_addresses "
        "FROM subdomains WHERE domain=? AND http_status IS NOT NULL",
        (domain,),
    ).fetchall()


def _all_subs(db: sqlite3.Connection, domain: str) -> List[sqlite3.Row]:
    return db.execute(
        "SELECT id, subdomain, http_status, http_title, http_technologies, ip_addresses, dns_resolved "
        "FROM subdomains WHERE domain=?", (domain,),
    ).fetchall()


def _rows_to_lite(rows: List[sqlite3.Row]) -> List[Dict]:
    """Compact subdomain rows for embedding in LLM prompts."""
    out: List[Dict] = []
    for r in rows:
        out.append({
            "subdomain_id": r["id"],
            "host": r["subdomain"],
            "status": r["http_status"],
            "title": (r["http_title"] or "")[:120],
            "tech": (r["http_technologies"] or "[]"),
        })
    return out


# ════════════════════════════════════════════════════════════════
# PLAYBOOKS (each returns List[FindingCandidate])
# ════════════════════════════════════════════════════════════════

def _llm_playbook(
    hunter: "HunterAgent", ctx: AgentContext,
    name: str, fallback_class: str,
    user_payload: Dict, *, max_tokens: int = _DEFAULT_MAX_TOKENS,
) -> List[FindingCandidate]:
    """Generic LLM-driven playbook wrapper. Returns parsed candidates."""
    try:
        system = _load_prompt(name)
    except FileNotFoundError:
        return []
    user_msg = json.dumps(user_payload, indent=2, default=str)
    try:
        resp = hunter.call_llm(
            system=system,
            messages=[{"role": "user", "content": user_msg}],
            ctx=ctx, max_tokens=max_tokens,
        )
    except (LLMError, CostCapExceeded) as e:
        hunter.emit_event("hunter.playbook_skipped",
                          {"playbook": name, "reason": str(e)})
        return []
    raw = _parse_findings_json(resp.get("content") or "")
    if not raw:
        return []
    out: List[FindingCandidate] = []
    for r in raw:
        c = _coerce_candidate(r, playbook=name, fallback_class=fallback_class)
        if c:
            out.append(c)
    return out


def run_graphql(hunter, ctx, recon) -> List[FindingCandidate]:
    eps = (recon.get("signals") or {}).get("graphql_endpoints") or []
    if not eps:
        return []
    hosts = _live_hosts(ctx.db, recon["domain"])
    payload = {
        "graphql_endpoints": eps,
        "live_hosts": _rows_to_lite(hosts),
        "instruction": ("Identify GraphQL-specific vulnerabilities (introspection, "
                        "alias batching DoS, mutation IDOR, injection in resolvers). "
                        "Return a JSON array of findings."),
    }
    return _llm_playbook(hunter, ctx, "graphql", "graphql", payload)


def run_idor(hunter, ctx, recon) -> List[FindingCandidate]:
    hosts = _live_hosts(ctx.db, recon["domain"])
    if not hosts:
        return []
    payload = {
        "live_hosts": _rows_to_lite(hosts),
        "signals": recon.get("signals", {}),
        "instruction": ("Hunt for IDOR opportunities. Focus on API endpoints with "
                        "numeric or UUID IDs, user-scoped resources, and admin paths. "
                        "Return a JSON array."),
    }
    return _llm_playbook(hunter, ctx, "idor", "idor", payload)


def run_ssrf(hunter, ctx, recon) -> List[FindingCandidate]:
    hosts = _live_hosts(ctx.db, recon["domain"])
    if not hosts:
        return []
    payload = {
        "live_hosts": _rows_to_lite(hosts),
        "signals": recon.get("signals", {}),
        "instruction": ("Identify SSRF candidates: URL-accepting parameters, "
                        "webhook configs, image-from-URL endpoints, PDF generators. "
                        "Return a JSON array."),
    }
    return _llm_playbook(hunter, ctx, "ssrf", "ssrf", payload)


def run_xss(hunter, ctx, recon) -> List[FindingCandidate]:
    hosts = _live_hosts(ctx.db, recon["domain"])
    if not hosts:
        return []
    payload = {
        "live_hosts": _rows_to_lite(hosts),
        "signals": recon.get("signals", {}),
        "instruction": ("Identify XSS surfaces. Note: CSP analysis if headers were "
                        "captured. Return a JSON array, prioritizing stored XSS in "
                        "admin-visible fields (Critical-class)."),
    }
    return _llm_playbook(hunter, ctx, "xss", "xss", payload)


def run_jwt(hunter, ctx, recon) -> List[FindingCandidate]:
    sigs = recon.get("signals") or {}
    has_login = bool(sigs.get("login_pages")) or "jwt" in str(sigs).lower()
    if not has_login:
        return []
    hosts = _live_hosts(ctx.db, recon["domain"])
    payload = {
        "login_pages": sigs.get("login_pages", []),
        "live_hosts": _rows_to_lite(hosts),
        "instruction": ("Identify JWT misconfigurations: alg:none acceptance, "
                        "RS256→HS256 confusion, weak secret, missing exp check. "
                        "Return a JSON array."),
    }
    return _llm_playbook(hunter, ctx, "jwt", "jwt", payload)


def run_bizlogic(hunter, ctx, recon) -> List[FindingCandidate]:
    hosts = _live_hosts(ctx.db, recon["domain"])
    if not hosts:
        return []
    payload = {
        "live_hosts": _rows_to_lite(hosts),
        "signals": recon.get("signals", {}),
        "instruction": ("Identify business-logic flaws: race conditions, negative "
                        "values, mass assignment, parameter tampering. Return a "
                        "JSON array."),
    }
    return _llm_playbook(hunter, ctx, "bizlogic", "bizlogic", payload)


def run_api_misconfig(hunter, ctx, recon) -> List[FindingCandidate]:
    hosts = _live_hosts(ctx.db, recon["domain"])
    if not hosts:
        return []
    payload = {
        "live_hosts": _rows_to_lite(hosts),
        "signals": recon.get("signals", {}),
        "instruction": ("Identify API misconfigurations: mass-assignment, hidden "
                        "params, HTTP method override, missing auth on admin "
                        "endpoints. Return a JSON array."),
    }
    return _llm_playbook(hunter, ctx, "api_misconfig", "api_misconfig", payload)


# ── deterministic takeover playbook ───────────────────────────────
# fingerprints: (cname_regex, title_evidence_substrings, service, confidence)
TAKEOVER_FINGERPRINTS: List[Dict[str, Any]] = [
    {"cname_re": re.compile(r"\.github\.io$", re.I),
     "title_evidence": ["there isn't a github pages site here",
                        "404 - file or directory not found"],
     "service": "github_pages", "confidence": 0.95},
    {"cname_re": re.compile(r"\.s3[\.-][a-z0-9-]*\.?amazonaws\.com$", re.I),
     "title_evidence": ["nosuchbucket", "the specified bucket does not exist"],
     "service": "aws_s3", "confidence": 0.92},
    {"cname_re": re.compile(r"\.herokuapp\.com$", re.I),
     "title_evidence": ["no such app", "herokucdn.com/error-pages/no-such-app"],
     "service": "heroku", "confidence": 0.90},
    {"cname_re": re.compile(r"\.azurewebsites\.net$", re.I),
     "title_evidence": ["404 web site not found", "site is stopped"],
     "service": "azure_websites", "confidence": 0.88},
    {"cname_re": re.compile(r"\.cloudapp\.net$", re.I),
     "title_evidence": ["not found"],
     "service": "azure_cloudapp", "confidence": 0.75},
    {"cname_re": re.compile(r"\.fastly\.net$", re.I),
     "title_evidence": ["fastly error: unknown domain"],
     "service": "fastly", "confidence": 0.90},
    {"cname_re": re.compile(r"\.shopify\.com$", re.I),
     "title_evidence": ["sorry, this shop is currently unavailable"],
     "service": "shopify", "confidence": 0.85},
    {"cname_re": re.compile(r"\.unbouncepages\.com$", re.I),
     "title_evidence": ["the requested url was not found"],
     "service": "unbounce", "confidence": 0.85},
]


def run_takeover(hunter, ctx, recon) -> List[FindingCandidate]:
    """Pure-logic subdomain takeover detection. No LLM."""
    rows = _all_subs(ctx.db, recon["domain"])
    candidates: List[FindingCandidate] = []
    for r in rows:
        title = (r["http_title"] or "").lower()
        cnames: List[str] = []
        try:
            cnames = json.loads(r["ip_addresses"] or "[]")
        except (TypeError, json.JSONDecodeError):
            cnames = []
        for fp in TAKEOVER_FINGERPRINTS:
            cname_match = any(fp["cname_re"].search(c or "") for c in cnames)
            title_match = any(s.lower() in title for s in fp["title_evidence"])
            # Strong: both signals. Medium: title-only.
            if not (cname_match or title_match):
                continue
            if not title_match:
                # cname pattern alone is too noisy; need title evidence.
                continue
            confidence = fp["confidence"] if cname_match else fp["confidence"] - 0.20
            candidates.append(FindingCandidate(
                vuln_class="takeover",
                title=f"Subdomain takeover candidate: {r['subdomain']} → {fp['service']}",
                description=(
                    f"Host {r['subdomain']} returned HTTP {r['http_status']} with title "
                    f"'{r['http_title']}', matching the {fp['service']} takeover "
                    f"signature."
                    + (f" CNAME chain resolves to {fp['service']}." if cname_match else "")
                ),
                confidence=confidence,
                evidence={
                    "subdomain_id": r["id"],
                    "service": fp["service"],
                    "title": r["http_title"],
                    "http_status": r["http_status"],
                    "cname_targets": cnames,
                    "cname_matched": cname_match,
                },
                playbook="takeover",
            ))
    return candidates


# ── playbook registry ─────────────────────────────────────────────
PlaybookFn = Callable[["HunterAgent", AgentContext, Dict], List[FindingCandidate]]

PLAYBOOKS: Dict[str, PlaybookFn] = {
    "graphql":       run_graphql,
    "idor":          run_idor,
    "ssrf":          run_ssrf,
    "xss":           run_xss,
    "jwt":           run_jwt,
    "bizlogic":      run_bizlogic,
    "api_misconfig": run_api_misconfig,
    "takeover":      run_takeover,
}


# ── operator-mode gate (Phase 15) ─────────────────────────────────
# Playbooks differ in the kind of analysis they perform on DB content. The
# takeover playbook is deterministic and uses only data already in the DB;
# the LLM-driven playbooks reason over recon's live_hosts summary. Modes
# without live HTTP data should skip the LLM playbooks entirely.
HUNTER_PLAYBOOKS_BY_MODE: Dict[str, frozenset[str]] = {
    "passive_recon":       frozenset(),                # no live data; skip all
    "active_recon":        frozenset({"takeover"}),    # deterministic only
    "content_discovery":   frozenset(PLAYBOOKS.keys()),
    "vuln_triage":         frozenset(PLAYBOOKS.keys()),
    "evidence_collection": frozenset(PLAYBOOKS.keys()),
    "report_drafting":     frozenset(),
    "retest":              frozenset(),
}


def select_playbooks(recon: Dict, mode: str = "vuln_triage") -> List[str]:
    """Decide which playbooks to run from the recon summary. Mode is no
    longer used to filter — agents pick by signals (graphql_endpoints
    drives graphql; login_pages drives jwt; live_hosts drives the
    always-on set). HUNTER_PLAYBOOKS_BY_MODE remains as a reference for
    the *default* set per mode but is not used to refuse playbooks."""
    signals = recon.get("signals") or {}
    out: List[str] = []
    # Adaptive — only when triggered.
    if signals.get("graphql_endpoints"):
        out.append("graphql")
    if signals.get("login_pages"):
        out.append("jwt")
    # Always-on if any live hosts were observed.
    if recon.get("live_hosts", 0) > 0 or signals.get("admin_panels") or signals.get("interesting_urls"):
        out += ["idor", "ssrf", "xss", "bizlogic", "api_misconfig"]
    # Takeover scans all subdomains, no signal precondition.
    out.append("takeover")
    # Stable dedup.
    seen: set = set()
    return [p for p in out if not (p in seen or seen.add(p))]


# ════════════════════════════════════════════════════════════════
# HunterAgent
# ════════════════════════════════════════════════════════════════
class HunterAgent(BaseAgent):
    name = "hunter"
    default_model = "haiku"

    def __init__(self, db=None, emit_fn=None, *,
                 min_confidence: float = _DEFAULT_MIN_CONFIDENCE) -> None:
        super().__init__(db=db, emit_fn=emit_fn)
        self.min_confidence = min_confidence

    def run(self, ctx: AgentContext) -> AgentResult:
        recon = self._load_recon(ctx)
        if not recon:
            return AgentResult(self.name, False, None,
                               error="no recon_summary in agent_memory")
        if not recon.get("domain"):
            return AgentResult(self.name, False, None,
                               error="recon_summary missing 'domain'")

        mode = (ctx.inputs or {}).get("mode", "vuln_triage")
        playbooks = select_playbooks(recon, mode=mode)
        self.emit_event("hunter.start", {"playbooks": playbooks, "mode": mode})

        all_candidates: List[FindingCandidate] = []
        by_class: Dict[str, int] = {}
        inserted: List[Dict[str, Any]] = []
        dropped_low_conf = 0
        dropped_bad_evidence = 0

        for pb in playbooks:
            handler = PLAYBOOKS[pb]
            try:
                cands = handler(self, ctx, recon)
            except Exception as e:  # pragma: no cover — defense
                self.emit_event("hunter.playbook_error",
                                {"playbook": pb, "error": f"{type(e).__name__}: {e}"})
                continue
            for c in cands:
                if c.confidence < self.min_confidence:
                    dropped_low_conf += 1
                    continue
                if not self._validate_evidence(ctx, c):
                    dropped_bad_evidence += 1
                    self.emit_event("hunter.evidence_rejected", {
                        "playbook": pb, "title": c.title,
                        "evidence": c.evidence,
                    })
                    continue
                row = self._persist_finding(ctx, c)
                all_candidates.append(c)
                by_class[c.vuln_class] = by_class.get(c.vuln_class, 0) + 1
                inserted.append(row)

        summary = {
            "domain": recon["domain"],
            "playbooks_run": playbooks,
            "findings_count": len(inserted),
            "by_class": by_class,
            "dropped_low_conf": dropped_low_conf,
            "dropped_bad_evidence": dropped_bad_evidence,
            "bug_ids": [r["bug_id"] for r in inserted],
        }
        self.remember(ctx, _MEMORY_KEY_FINDINGS, summary)
        self.emit_event("hunter.complete", summary)
        return AgentResult(self.name, True, output=summary)

    # ── internals ──────────────────────────────────────────────────
    def _load_recon(self, ctx: AgentContext) -> Optional[Dict]:
        if self.db is None:
            return None
        row = self.db.execute(
            "SELECT value_json FROM agent_memory "
            "WHERE job_id=? AND agent='recon' AND key='recon_summary'",
            (ctx.job_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except (TypeError, json.JSONDecodeError):
            return None

    def _validate_evidence(self, ctx: AgentContext, c: FindingCandidate) -> bool:
        """Reject candidates whose evidence doesn't reference a real subdomain row."""
        sid = (c.evidence or {}).get("subdomain_id")
        if sid is None:
            return False
        try:
            sid = int(sid)
        except (TypeError, ValueError):
            return False
        row = self.db.execute(
            "SELECT id FROM subdomains WHERE id=?", (sid,)
        ).fetchone()
        return row is not None

    def _next_bug_id(self, ctx: AgentContext) -> str:
        short = (ctx.job_id or "job")[:8].lower().replace("-", "")
        row = self.db.execute(
            "SELECT COUNT(*) FROM findings WHERE job_id=?", (ctx.job_id,)
        ).fetchone()
        seq = (row[0] if row else 0) + 1
        return f"BUG-{short}-{seq:03d}"

    def _persist_finding(self, ctx: AgentContext,
                         c: FindingCandidate) -> Dict[str, Any]:
        bug_id = self._next_bug_id(ctx)
        sid = (c.evidence or {}).get("subdomain_id")
        domain = (ctx.program or {}).get("name") or self._recon_domain(ctx) or ""
        cur = self.db.execute(
            "INSERT INTO findings(bug_id, job_id, domain, subdomain_id, vuln_class, "
            "title, description, evidence_json, confidence, status) "
            "VALUES (?,?,?,?,?,?,?,?,?,'new')",
            (bug_id, ctx.job_id, domain, sid, c.vuln_class, c.title,
             c.description, json.dumps(c.evidence, default=str), c.confidence),
        )
        finding_row_id = cur.lastrowid
        # Auto-map to ATT&CK techniques.
        attack_mapper.persist_for_finding(self.db, finding_row_id, {
            "vuln_class": c.vuln_class,
            "title": c.title,
            "description": c.description,
            "evidence": c.evidence,
        })
        # CWE + OWASP taxonomy (deterministic lookup).
        attack_taxonomy.persist_taxonomy_for_finding(
            self.db, finding_row_id, c.vuln_class,
        )
        # Structured 4-tier evidence rows alongside the legacy evidence_json
        # blob. Source classification keys off the playbook name.
        evidence_mod.record_evidence_dict(
            self.db, finding_row_id, c.evidence or {},
            playbook=c.playbook,
        )
        self.db.commit()
        return {
            "id": finding_row_id, "bug_id": bug_id,
            "vuln_class": c.vuln_class, "confidence": c.confidence,
            "title": c.title, "playbook": c.playbook,
        }

    def _recon_domain(self, ctx: AgentContext) -> Optional[str]:
        recon = self._load_recon(ctx)
        return recon.get("domain") if recon else None
