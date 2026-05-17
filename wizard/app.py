"""
ReconForge first-run wizard (Textual TUI).

Run via ``reconforge wizard`` or ``python -m reconforge.wizard``.
Five screens:
  1. Welcome — license, OPSEC reminder
  2. Tool Detect — table of CATALOG tools + install plan
  3. LLM Setup — Claude API key OR Ollama URL
  4. Scope Paste — paste program scope JSON
  5. Vault Pick — choose ~/Documents/BugBountyVault directory

Textual is the runtime; if Textual isn't installed the wizard falls
back to a Rich-based, non-interactive printout that walks the operator
through the same steps via stdout (CLAUDE.md doctrine: graceful
degradation across the wizard).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from tools import detect


# ── plain-stdout fallback (used when Textual isn't available) ─────
def run_text_wizard(out=sys.stdout, in_=sys.stdin) -> int:
    """Walk the five screens via plain prompts. Returns 0 on success."""
    def _say(*a, **kw): print(*a, file=out, flush=True, **kw)
    def _ask(prompt: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        _say(f"{prompt}{suffix}: ", end="")
        try:
            line = in_.readline().rstrip("\n")
        except (EOFError, KeyboardInterrupt):
            return default
        return line or default

    _say("=" * 60)
    _say("ReconForge first-run wizard")
    _say("=" * 60)
    _say("\n[1/5] Welcome\n")
    _say("ReconForge is a bug-bounty research assistant. It will only run")
    _say("tools mapped to MITRE ATT&CK Reconnaissance + Resource Development.")
    _say("You must have written authorization (program scope) for every target.")
    _ask("\nPress Enter to continue", default="")

    _say("\n[2/5] Tool Detect\n")
    statuses = detect.scan()
    installed = sum(1 for s in statuses if s.installed)
    _say(f"  Found {installed}/{len(statuses)} known tools on PATH.")
    plan = detect.install_plan_human()
    _say("\n  Install plan for missing tools (run separately):\n")
    _say(plan)
    _ask("\nPress Enter to continue", default="")

    _say("\n[3/5] LLM Setup\n")
    mode = _ask("Backend: 'api' for Claude, 'local' for Ollama, 'skip' for "
                "no-LLM (degraded)", default="api")
    setup: Dict[str, Any] = {"mode": mode}
    if mode == "api":
        setup["api_key"] = _ask("Claude API key (stays in ~/.config/reconforge)")
    elif mode == "local":
        setup["ollama_url"] = _ask("Ollama URL", default="http://localhost:11434")
        setup["opus_sub"]   = _ask("Substitute for Opus 4.7", default="llama3.1:70b")
        setup["haiku_sub"]  = _ask("Substitute for Haiku 4.5", default="llama3.1:8b")

    _say("\n[4/5] Scope Paste\n")
    _say("Paste your program scope JSON (CLAUDE.md schema). Finish with a")
    _say("blank line and Ctrl-D / Ctrl-Z.\n")
    buf: list[str] = []
    try:
        for line in in_:
            buf.append(line)
    except KeyboardInterrupt:
        pass
    scope_text = "".join(buf).strip()
    try:
        scope_doc = json.loads(scope_text) if scope_text else {}
    except json.JSONDecodeError as e:
        _say(f"  Warning: scope is not valid JSON ({e}). Saving raw.")
        scope_doc = {"_raw": scope_text}

    _say("\n[5/5] Vault Pick\n")
    default_vault = str(Path.home() / "Documents" / "BugBountyVault")
    vault = _ask("Vault directory", default=default_vault)

    cfg_dir = Path.home() / ".config" / "reconforge"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "settings.json").write_text(
        json.dumps({"llm": setup, "vault": {"path": vault}}, indent=2),
        encoding="utf-8",
    )
    program_name = (scope_doc.get("name") or "default").lower()
    scopes_dir = cfg_dir / "scopes"
    scopes_dir.mkdir(parents=True, exist_ok=True)
    (scopes_dir / f"{program_name}.json").write_text(
        json.dumps(scope_doc, indent=2), encoding="utf-8",
    )
    _say("\nWizard complete. Configuration written to "
         f"{cfg_dir}/settings.json")
    _say(f"Scope saved to {scopes_dir}/{program_name}.json")
    _say("Run `reconforge run` to start the service.")
    return 0


# ── Textual TUI ───────────────────────────────────────────────────
def run_textual() -> int:
    """Start the Textual TUI. Falls back to text wizard on import failure."""
    try:
        from textual.app import App, ComposeResult  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "textual not installed — falling back to text wizard. "
            "Install with: pip install --user textual\n"
        )
        return run_text_wizard()

    from .tui import ReconForgeWizard
    return ReconForgeWizard().run() or 0


def main(argv: Optional[list[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if "--text" in argv or os.environ.get("RECONFORGE_NO_TUI"):
        return run_text_wizard()
    return run_textual()


if __name__ == "__main__":
    sys.exit(main())
