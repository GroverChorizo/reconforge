"""
Markdown research vault writer.

Resolves vault root from config[vault.path] (default ~/Documents/ResearchVault),
creates the notes folder structure (00-Dashboard / 01-Programs/<name>/ /
02-Techniques / 03-Payloads / 05-Templates), writes notes with YAML
frontmatter atomically (tmp + rename).

Phase 6 shipped: write_note, ensure_skeleton, ensure_program_dir,
sanitize_name (used by the Strategist).

Phase 9 adds: write_finding (BUG-XXX.md per finding, with platform-draft
appendices), which the Reporter agent invokes once per non-dup non-child
finding.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_VAULT = "~/Documents/ResearchVault"
SECTIONS = ("00-Dashboard", "01-Programs", "02-Techniques", "03-Payloads", "05-Templates")


def vault_root() -> Path:
    """Resolve vault root: config[vault.path] → env → default."""
    try:
        import main as M
        p = M.get_config("vault.path", os.environ.get("RECONFORGE_VAULT", DEFAULT_VAULT))
    except Exception:
        p = os.environ.get("RECONFORGE_VAULT", DEFAULT_VAULT)
    return Path(os.path.expanduser(p))


def ensure_skeleton() -> Path:
    """Create the top-level research vault structure if missing."""
    root = vault_root()
    root.mkdir(parents=True, exist_ok=True)
    for sec in SECTIONS:
        (root / sec).mkdir(parents=True, exist_ok=True)
    return root


def ensure_program_dir(program_name: str) -> Path:
    """Return (and create) 01-Programs/<sanitized-name>/."""
    root = ensure_skeleton()
    name = sanitize_name(program_name)
    pdir = root / "01-Programs" / name
    pdir.mkdir(parents=True, exist_ok=True)
    return pdir


def write_finding(
    program_name: str,
    finding: Dict[str, Any],
    drafts: Optional[Dict[str, Any]] = None,
    overwrite: bool = True,
) -> Path:
    """Write a single BUG-XXX.md per-finding note into 01-Programs/<program>/.

    ``drafts`` is a mapping ``{platform_name: Draft}`` (the Draft dataclass
    from ``submissions.common``). Each draft is appended as a collapsible
    section so the operator can copy-paste into the platform UI.
    """
    program_name = program_name or "unknown"
    pdir = ensure_program_dir(program_name)
    bug_id = finding.get("bug_id") or "BUG-UNKNOWN"
    target = pdir / f"{bug_id}.md"

    fm = {
        "tags": ["reconforge", "finding", program_name, finding.get("vuln_class", "")],
        "bug_id": bug_id,
        "program": program_name,
        "vuln_class": finding.get("vuln_class", ""),
        "cvss_score": finding.get("cvss_score"),
        "cvss_vector": finding.get("cvss_vector"),
        "bounty_estimate_usd": finding.get("bounty_estimate_usd"),
        "status": finding.get("status", "new"),
        "confidence": finding.get("confidence"),
    }
    body = _render_finding_body(finding, drafts or {})
    title = (finding.get("title") or bug_id).strip()
    rel = target.relative_to(vault_root())
    return write_note(str(rel), title, body, frontmatter=fm, overwrite=overwrite)


def _render_finding_body(finding: Dict[str, Any],
                         drafts: Dict[str, Any]) -> str:
    lines = []
    if finding.get("description"):
        lines += ["## Description", finding["description"], ""]
    if finding.get("evidence"):
        lines += ["## Evidence", "```json",
                  _safe_json(finding["evidence"]), "```", ""]
    techs = finding.get("attack_techniques") or []
    if techs:
        lines += ["## ATT&CK Techniques",
                  ", ".join(f"`{t}`" for t in techs), ""]
    if drafts:
        lines += ["## Platform Drafts"]
        for platform, draft in drafts.items():
            lines += [
                f"### {platform}",
                f"**Title:** {getattr(draft, 'title', '')}",
                f"**Severity:** {getattr(draft, 'severity', '')}  ",
                f"**Weakness:** `{getattr(draft, 'weakness', '')}`",
                "",
                "<details><summary>Draft body (click to expand)</summary>",
                "",
                getattr(draft, "body_md", ""),
                "",
                "</details>",
                "",
            ]
    return "\n".join(lines)


def _safe_json(value: Any) -> str:
    import json
    try:
        return json.dumps(value, indent=2, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def write_note(
    relative_path: str,
    title: str,
    body: str,
    frontmatter: Optional[Dict[str, Any]] = None,
    overwrite: bool = False,
) -> Path:
    """Atomic write of a markdown note under vault_root().

    ``relative_path`` is from the vault root, e.g.
    ``"01-Programs/examplecorp/strategist_plan.md"``.

    Raises FileExistsError when the target exists and overwrite=False.
    """
    target = vault_root() / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not overwrite:
        raise FileExistsError(str(target))

    content = _render_note(title, body, frontmatter or {})
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(target)
    return target


# ── helpers ──────────────────────────────────────────────────────
def sanitize_name(name: str) -> str:
    s = re.sub(r"[^a-z0-9_-]+", "-", (name or "").lower())
    return s.strip("-") or "unnamed"


def _render_note(title: str, body: str, fm: Dict[str, Any]) -> str:
    parts = []
    if fm:
        parts.append("---")
        parts.append(_format_frontmatter(fm).rstrip("\n"))
        parts.append("---")
        parts.append("")
    parts.append(f"# {title}")
    parts.append("")
    parts.append(body.rstrip("\n"))
    parts.append("")  # trailing newline
    return "\n".join(parts)


def _format_frontmatter(fm: Dict[str, Any]) -> str:
    """Minimal YAML-compatible frontmatter — no PyYAML dependency."""
    lines = []
    for k, v in fm.items():
        if isinstance(v, list):
            lines.append(f"{k}:")
            for item in v:
                lines.append(f"  - {_yaml_scalar(item)}")
        elif isinstance(v, dict):
            lines.append(f"{k}:")
            for ik, iv in v.items():
                lines.append(f"  {ik}: {_yaml_scalar(iv)}")
        else:
            lines.append(f"{k}: {_yaml_scalar(v)}")
    return "\n".join(lines) + "\n"


def _yaml_scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    s = str(v)
    if any(c in s for c in ":#[]{}|>!&*'\"%@`") or s != s.strip():
        return '"' + s.replace('"', '\\"') + '"'
    return s
