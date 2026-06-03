"""
Reporter agent — Opus 4.7.

For each non-dup non-child finding the Analyst scored, generate:
  * A polished title and 2-sentence executive summary (via Opus)
  * One submission draft per platform in ``program.platforms`` (Python
    formatters in ``submissions/<platform>.py``)
  * A ``BUG-XXX.md`` note in ``ResearchVault/01-Programs/<program>/``
    with all platform drafts as collapsible sections
  * One row per draft in the ``submission_drafts`` table

Auto-submission is out of scope for v1 — drafts are reviewed via the
SPA's submission preview and copied by hand into each platform's UI.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base import BaseAgent, AgentContext, AgentResult, LLMError, CostCapExceeded
from vault import writer as vault_writer
from submissions import REGISTRY as PLATFORM_FORMATTERS


_PROMPT_PATH = Path(__file__).parent / "prompts" / "reporter.md"
_MAX_TOKENS = 5000
_MEMORY_KEY = "reporter_summary"


class ReporterAgent(BaseAgent):
    name = "reporter"
    default_model = "opus"

    def run(self, ctx: AgentContext) -> AgentResult:
        if ctx.db is None:
            return AgentResult(self.name, False, None, error="no db on context")
        findings = self._load_eligible(ctx)
        if not findings:
            return AgentResult(self.name, False, None,
                               error="no eligible findings (none scored, or all dup/child)")

        polished = self._polish(ctx, findings)
        platforms = self._program_platforms(ctx)
        if not platforms:
            return AgentResult(self.name, False, None,
                               error="program has no platforms configured")

        program_name = (ctx.program or {}).get("name") or "unknown"
        drafts_count = 0
        notes_written: List[str] = []
        errors: List[str] = []

        for f in findings:
            f["polished_title"] = polished.get(f["bug_id"], {}).get("polished_title") or f["title"]
            f["executive_summary"] = polished.get(f["bug_id"], {}).get("executive_summary", "")
            f["preferred_platform"] = polished.get(f["bug_id"], {}).get("preferred_platform")

            per_platform: Dict[str, Any] = {}
            for platform in platforms:
                fmt = PLATFORM_FORMATTERS.get(platform.lower())
                if fmt is None:
                    errors.append(f"{f['bug_id']}: unsupported platform '{platform}'")
                    continue
                # Use polished title for the formatter input.
                finding_for_fmt = dict(f)
                finding_for_fmt["title"] = f["polished_title"]
                if f["executive_summary"]:
                    finding_for_fmt["description"] = (
                        f["executive_summary"] + "\n\n" + (f.get("description") or "")
                    )
                draft = fmt(finding_for_fmt, ctx.program or {})
                per_platform[draft.platform] = draft
                self._insert_draft_row(ctx, f["id"], draft)
                drafts_count += 1

            try:
                path = vault_writer.write_finding(program_name, f, per_platform, overwrite=True)
                notes_written.append(str(path))
            except Exception as e:
                errors.append(f"{f['bug_id']}: vault write failed: {e}")

        summary = {
            "findings_reported": len(findings),
            "drafts_count": drafts_count,
            "platforms": platforms,
            "notes_written": notes_written,
            "errors": errors,
        }
        self.remember(ctx, _MEMORY_KEY, summary)
        self.emit_event("reporter.complete", summary)
        return AgentResult(self.name, True, output=summary)

    # ── data ──────────────────────────────────────────────────────
    def _load_eligible(self, ctx: AgentContext) -> List[Dict[str, Any]]:
        """Findings that are scored AND not flagged dup AND not a chain child."""
        rows = ctx.db.execute(
            "SELECT id, bug_id, vuln_class, title, description, evidence_json, "
            "confidence, cvss_vector, cvss_score, bounty_estimate_usd, status, "
            "parent_finding_id "
            "FROM findings "
            "WHERE job_id=? AND status != 'dup' AND parent_finding_id IS NULL "
            "AND cvss_score IS NOT NULL "
            "ORDER BY cvss_score DESC, id ASC",
            (ctx.job_id,),
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            try:
                ev = json.loads(r["evidence_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                ev = {}
            techs = ctx.db.execute(
                "SELECT DISTINCT technique_id FROM attack_techniques WHERE finding_id=?",
                (r["id"],),
            ).fetchall()
            out.append({
                "id": r["id"], "bug_id": r["bug_id"],
                "vuln_class": r["vuln_class"], "title": r["title"],
                "description": r["description"] or "",
                "evidence": ev, "confidence": r["confidence"],
                "cvss_vector": r["cvss_vector"],
                "cvss_score": r["cvss_score"],
                "bounty_estimate_usd": r["bounty_estimate_usd"],
                "status": r["status"],
                "attack_techniques": [t["technique_id"] for t in techs],
            })
        return out

    def _program_platforms(self, ctx: AgentContext) -> List[str]:
        prog = ctx.program or {}
        # Program JSON may carry one platform or a list.
        plats = prog.get("platforms") or prog.get("platform")
        if isinstance(plats, str):
            return [plats]
        if isinstance(plats, list):
            return [p for p in plats if isinstance(p, str)]
        return []

    # ── LLM ───────────────────────────────────────────────────────
    def _polish(self, ctx: AgentContext,
                findings: List[Dict[str, Any]]) -> Dict[str, Dict]:
        """Call Opus once for the whole batch. Empty {} on failure (formatter falls back)."""
        try:
            system = _PROMPT_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        payload = {
            "program_name": (ctx.program or {}).get("name"),
            "platforms": self._program_platforms(ctx),
            "findings": [{
                "bug_id": f["bug_id"], "vuln_class": f["vuln_class"],
                "title": f["title"], "description": f["description"],
                "cvss_score": f["cvss_score"],
                "evidence": f["evidence"],
            } for f in findings],
        }
        try:
            resp = self.call_llm(
                system=system,
                messages=[{"role": "user",
                           "content": json.dumps(payload, indent=2, default=str)}],
                ctx=ctx, max_tokens=_MAX_TOKENS,
            )
        except (LLMError, CostCapExceeded) as e:
            self.emit_event("reporter.polish_skipped", {"reason": str(e)})
            return {}
        data = _parse_reporter_json(resp.get("content") or "")
        if not data:
            return {}
        return {p["bug_id"]: p for p in data.get("polished", []) if p.get("bug_id")}

    # ── persistence ───────────────────────────────────────────────
    def _insert_draft_row(self, ctx: AgentContext, finding_id: int, draft) -> None:
        program_name = (ctx.program or {}).get("name") or ""
        rel_path = f"01-Programs/{vault_writer.sanitize_name(program_name)}/"
        # Path joined later — we store the relative dir + bug_id filename.
        ctx.db.execute(
            "INSERT INTO submission_drafts(finding_id, platform, title, body_md, "
            "severity, weakness, vault_path, human_approved, created_at) "
            "VALUES (?,?,?,?,?,?,?, 0, datetime('now'))",
            (finding_id, draft.platform, draft.title, draft.body_md,
             draft.severity, draft.weakness, rel_path),
        )
        ctx.db.commit()


def _parse_reporter_json(content: str) -> Optional[Dict]:
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
