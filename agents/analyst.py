"""
Analyst agent — Opus 4.7.

Reads ``findings`` + ``attack_techniques`` for a job, asks the LLM for:
  - CVSS 4.0 BTE vector per finding
  - bounty estimate (USD) per finding
  - chains (parent → children)
  - duplicate groupings (canonical → dups)

The Python side validates CVSS vectors (re-rejects on parse failure),
computes scores deterministically via ``core.cvss.score``, and updates
``findings`` rows. Chains set ``parent_finding_id``. Duplicates flip
``status='dup'`` on the non-canonical rows.

A secondary deterministic pass (TF-IDF + cosine) catches duplicates the
LLM missed within the same ``vuln_class``. The threshold is conservative
(0.85 cosine similarity) — the goal is to suppress only obvious dups.
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agents.base import BaseAgent, AgentContext, AgentResult, LLMError, CostCapExceeded
from core import cvss


_PROMPT_PATH = Path(__file__).parent / "prompts" / "analyst.md"
_MAX_TOKENS = 8000
_MEMORY_KEY = "analyst_summary"
_TFIDF_DUP_THRESHOLD = 0.85


# ── 2026 market rate table (per CLAUDE.md doctrine) ───────────────
BOUNTY_TABLE: Dict[str, Tuple[int, int, int]] = {
    # vuln_class → (low, typical, high)
    "graphql":       (2_500,  5_000, 10_000),
    "ssrf":          (3_000,  7_500, 25_000),
    "idor":          (  500,  2_000,  5_000),
    "idor_write":    (1_000,  3_500, 10_000),
    "auth_bypass":   (2_000,  5_000, 20_000),
    "jwt":           (1_000,  3_000, 10_000),
    "bizlogic":      (1_500,  4_200, 15_000),
    "xss":           (  500,  2_000,  5_000),
    "takeover":      (  200,    500,  2_000),
    "api_misconfig": (  500,  2_000,  5_000),
    "open_redirect": (  100,    300,  1_000),
    "cors":          (  300,  1_000,  3_000),
    "csrf":          (  300,  1_000,  3_000),
}


@dataclass
class _FindingRow:
    id: int
    bug_id: str
    vuln_class: str
    title: str
    description: str
    evidence: Dict[str, Any]
    techniques: List[str]


class AnalystAgent(BaseAgent):
    name = "analyst"
    default_model = "opus"

    def run(self, ctx: AgentContext) -> AgentResult:
        if ctx.db is None:
            return AgentResult(self.name, False, None, error="no db on context")
        findings = self._load_findings(ctx)
        if not findings:
            return AgentResult(self.name, False, None,
                               error="no findings to analyze")

        try:
            llm = self._call_analyst_llm(ctx, findings)
        except (LLMError, CostCapExceeded) as e:
            return AgentResult(self.name, False, None, error=f"analyst LLM call failed: {e}")
        if llm is None:
            return AgentResult(self.name, False, None,
                               error="analyst response not parseable as JSON")

        # ── apply CVSS + bounty per finding ──
        scored = 0
        rejected_vectors: List[str] = []
        bug_to_id = {f.bug_id: f.id for f in findings}
        for entry in llm.get("findings", []):
            bug_id = entry.get("bug_id")
            row_id = bug_to_id.get(bug_id)
            if row_id is None:
                continue
            vector = entry.get("cvss_vector", "")
            if not cvss.is_valid(vector):
                rejected_vectors.append(f"{bug_id}: {vector!r}")
                continue
            score_v = cvss.score(vector)
            bounty = self._sanitize_bounty(entry.get("bounty_estimate_usd"),
                                           self._find_class(findings, row_id))
            ctx.db.execute(
                "UPDATE findings SET cvss_vector=?, cvss_score=?, "
                "bounty_estimate_usd=?, updated_at=datetime('now') WHERE id=?",
                (vector, score_v, bounty, row_id),
            )
            scored += 1

        # ── chains (parent_finding_id) ──
        chain_count = self._apply_chains(ctx, llm.get("chains", []), bug_to_id)

        # ── duplicates (LLM-emitted) ──
        dup_count = self._apply_duplicates(ctx, llm.get("duplicates", []), bug_to_id)

        # ── deterministic dedup pass within vuln_class ──
        dup_count += self._tfidf_dedup_pass(ctx, findings, bug_to_id)

        ctx.db.commit()
        summary = {
            "findings_scored": scored,
            "findings_total": len(findings),
            "chains_applied": chain_count,
            "duplicates_marked": dup_count,
            "rejected_vectors": rejected_vectors,
        }
        self.remember(ctx, _MEMORY_KEY, summary)
        self.emit_event("analyst.complete", summary)
        return AgentResult(self.name, True, output=summary)

    # ── DB ─────────────────────────────────────────────────────────
    def _load_findings(self, ctx: AgentContext) -> List[_FindingRow]:
        rows = ctx.db.execute(
            "SELECT id, bug_id, vuln_class, title, description, evidence_json "
            "FROM findings WHERE job_id=? AND status != 'dup' "
            "ORDER BY id ASC", (ctx.job_id,),
        ).fetchall()
        out: List[_FindingRow] = []
        for r in rows:
            techs = ctx.db.execute(
                "SELECT DISTINCT technique_id FROM attack_techniques "
                "WHERE finding_id=?", (r["id"],),
            ).fetchall()
            try:
                evidence = json.loads(r["evidence_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                evidence = {}
            out.append(_FindingRow(
                id=r["id"], bug_id=r["bug_id"],
                vuln_class=r["vuln_class"], title=r["title"],
                description=r["description"] or "",
                evidence=evidence,
                techniques=[t["technique_id"] for t in techs],
            ))
        return out

    def _find_class(self, findings: List[_FindingRow], row_id: int) -> str:
        for f in findings:
            if f.id == row_id:
                return f.vuln_class
        return ""

    # ── LLM call ───────────────────────────────────────────────────
    def _call_analyst_llm(self, ctx: AgentContext,
                          findings: List[_FindingRow]) -> Optional[Dict]:
        system = _PROMPT_PATH.read_text(encoding="utf-8")
        bounty_view = {k: {"low": v[0], "typical": v[1], "high": v[2]}
                       for k, v in BOUNTY_TABLE.items()}
        payload = {
            "program": (ctx.program or {}).get("name"),
            "platform": (ctx.program or {}).get("platform"),
            "program_bounty_ranges": (ctx.program or {}).get("bounty_ranges"),
            "market_rate_table_usd": bounty_view,
            "findings": [{
                "bug_id": f.bug_id,
                "vuln_class": f.vuln_class,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "attack_techniques": f.techniques,
            } for f in findings],
            "cvss_examples": cvss.example_vectors(),
        }
        resp = self.call_llm(
            system=system,
            messages=[{"role": "user",
                       "content": json.dumps(payload, indent=2, default=str)}],
            ctx=ctx, max_tokens=_MAX_TOKENS,
        )
        return _parse_analyst_json(resp.get("content") or "")

    # ── post-processing ────────────────────────────────────────────
    def _sanitize_bounty(self, value: Any, vuln_class: str) -> int:
        try:
            v = int(value)
        except (TypeError, ValueError):
            v = BOUNTY_TABLE.get(vuln_class, (0, 1000, 5000))[1]
        # Clamp to 50% below low / 200% above high of the class range —
        # generous slack for LLM judgment within reason.
        rng = BOUNTY_TABLE.get(vuln_class)
        if rng:
            low, _, high = rng
            v = max(int(low * 0.5), min(v, int(high * 2.0)))
        return max(0, v)

    def _apply_chains(self, ctx: AgentContext, chains: List[Dict],
                      bug_to_id: Dict[str, int]) -> int:
        n = 0
        for chain in chains or []:
            parent = bug_to_id.get(chain.get("parent_bug_id"))
            if parent is None:
                continue
            for cb in chain.get("child_bug_ids", []) or []:
                child = bug_to_id.get(cb)
                if child is None or child == parent:
                    continue
                ctx.db.execute(
                    "UPDATE findings SET parent_finding_id=?, "
                    "updated_at=datetime('now') WHERE id=?",
                    (parent, child),
                )
                n += 1
        return n

    def _apply_duplicates(self, ctx: AgentContext, dups: List[Dict],
                          bug_to_id: Dict[str, int]) -> int:
        n = 0
        for grp in dups or []:
            canonical = bug_to_id.get(grp.get("canonical_bug_id"))
            if canonical is None:
                continue
            for db_bug in grp.get("duplicate_bug_ids", []) or []:
                dup_id = bug_to_id.get(db_bug)
                if dup_id is None or dup_id == canonical:
                    continue
                ctx.db.execute(
                    "UPDATE findings SET status='dup', "
                    "parent_finding_id=COALESCE(parent_finding_id, ?), "
                    "updated_at=datetime('now') WHERE id=?",
                    (canonical, dup_id),
                )
                n += 1
        return n

    def _tfidf_dedup_pass(self, ctx: AgentContext, findings: List[_FindingRow],
                          bug_to_id: Dict[str, int]) -> int:
        """Catch obvious dups the LLM missed (high TF-IDF cosine within class)."""
        by_class: Dict[str, List[_FindingRow]] = {}
        for f in findings:
            by_class.setdefault(f.vuln_class, []).append(f)
        n = 0
        for cls, items in by_class.items():
            if len(items) < 2:
                continue
            for i in range(len(items)):
                for j in range(i + 1, len(items)):
                    if _cosine_tfidf(items[i].title + " " + items[i].description,
                                     items[j].title + " " + items[j].description) >= _TFIDF_DUP_THRESHOLD:
                        # Mark j as dup of i (lower id wins).
                        canonical, dup = sorted([items[i].id, items[j].id])
                        row = ctx.db.execute(
                            "SELECT status FROM findings WHERE id=?", (dup,),
                        ).fetchone()
                        if row and row["status"] != "dup":
                            ctx.db.execute(
                                "UPDATE findings SET status='dup', "
                                "parent_finding_id=COALESCE(parent_finding_id, ?), "
                                "updated_at=datetime('now') WHERE id=?",
                                (canonical, dup),
                            )
                            n += 1
        return n


# ── helpers ───────────────────────────────────────────────────────
def _parse_analyst_json(content: str) -> Optional[Dict]:
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
    start = s.find("{")
    end = s.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        out = json.loads(s[start:end + 1])
        return out if isinstance(out, dict) else None
    except json.JSONDecodeError:
        return None


_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def _tokens(text: str) -> List[str]:
    return _TOKEN_RE.findall((text or "").lower())


def _cosine_tfidf(a: str, b: str) -> float:
    """Term-frequency cosine similarity between two short documents.

    For pair-wise duplicate detection a true TF-IDF would zero out every
    common term (df = N → log(N/df) = 0), defeating the purpose. Plain
    TF cosine is the standard tool here. Stopwords aren't filtered —
    finding descriptions are short enough that they don't dominate.
    """
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    ca, cb = Counter(ta), Counter(tb)
    keys = set(ca) | set(cb)
    dot = sum(ca.get(k, 0) * cb.get(k, 0) for k in keys)
    na = math.sqrt(sum(v * v for v in ca.values()))
    nb = math.sqrt(sum(v * v for v in cb.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)
