"""
ReconForge first-run wizard (text + Textual TUI).

Run via ``reconforge wizard``, ``python -m wizard``, or auto-launched
by ``main.py`` on first server start when no setup exists.

Seven screens:
  1. Welcome — license, OPSEC reminder
  2. Platform Identities — your handle on each bug-bounty platform
  3. Tool Detect — table of CATALOG tools + install plan
  4. API Keys — GitHub token, Interactsh server, etc.
  5. LLM Setup — Claude API key OR Ollama URL
  6. Scope Paste — paste program scope JSON (optional)
  7. Vault Pick — choose ~/Documents/BugBountyVault directory

Settings are written to ``~/.config/reconforge/settings.json`` with a
``setup_complete: true`` marker. Nothing about identities or keys is
stored in the web app's database; they live in the local config file
so the web UI can read them but can't be exfiltrated via the web app
attack surface.

Textual is the preferred runtime; if Textual isn't installed the
wizard falls back to a plain-stdout walk through the same steps.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Importing readline (POSIX stdlib) silently upgrades input() with arrow
# keys, line editing, and history — without it, typos in the wizard mean
# starting the prompt over. No-op import on Windows builds that lack it.
try:
    import readline  # noqa: F401
    _READLINE = True
except ImportError:
    _READLINE = False

from tools import detect


SUPPORTED_PLATFORMS: List[str] = [
    "intigriti", "hackerone", "bugcrowd", "yeswehack", "synack",
]


def config_dir() -> Path:
    return Path.home() / ".config" / "reconforge"


def settings_path() -> Path:
    return config_dir() / "settings.json"


def is_setup_complete() -> bool:
    """True if a prior wizard run wrote settings.json with the marker."""
    p = settings_path()
    if not p.exists():
        return False
    try:
        return bool(json.loads(p.read_text(encoding="utf-8")).get("setup_complete"))
    except (OSError, ValueError):
        return False


# ── plain-stdout fallback (used when Textual isn't available) ─────
def run_text_wizard(out=sys.stdout, in_=sys.stdin) -> int:
    """Walk the seven screens via plain prompts. Returns 0 on success."""
    def _say(*a, **kw): print(*a, file=out, flush=True, **kw)
    # When driving a real TTY (the production path), route through input()
    # so libreadline (imported above) gives arrow keys + history. The test
    # suite passes io.StringIO for in_; fall back to readline() there.
    use_input = (in_ is sys.stdin) and out is sys.stdout and sys.stdin.isatty()

    def _ask(prompt: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        try:
            if use_input:
                line = input(f"{prompt}{suffix}: ")
            else:
                _say(f"{prompt}{suffix}: ", end="")
                line = in_.readline().rstrip("\n")
        except (EOFError, KeyboardInterrupt):
            return default
        return line or default

    _say("=" * 60)
    _say("ReconForge first-run wizard")
    _say("=" * 60)

    # ── [1/7] Welcome ────────────────────────────────────────────
    _say("\n[1/7] Welcome\n")
    _say("ReconForge is a bug-bounty research assistant. It will only run")
    _say("tools mapped to MITRE ATT&CK Reconnaissance + Resource Development.")
    _say("You must have written authorization (program scope) for every target.")
    _ask("\nPress Enter to continue", default="")

    # ── [2/7] Platform Identities ────────────────────────────────
    _say("\n[2/7] Platform Identities\n")
    _say("Enter your researcher handle on each platform you use.")
    _say("Leave blank to skip a platform — you can re-run the wizard later.")
    _say("These handles are injected into program-required headers")
    _say("(e.g., X-Intigriti-Username) and your User-Agent on HackerOne.\n")
    identities: Dict[str, str] = {}
    for plat in SUPPORTED_PLATFORMS:
        h = _ask(f"  {plat} handle")
        if h.strip():
            identities[plat] = h.strip()
    if not identities:
        _say("\n  Warning: no platform handles set. Tools will run unattributed")
        _say("  and Intigriti report generation will fail until you set one.")

    # ── [3/7] Tool Detect ────────────────────────────────────────
    _say("\n[3/7] Tool Detect\n")
    statuses = detect.scan()
    installed = sum(1 for s in statuses if s.installed)
    _say(f"  Found {installed}/{len(statuses)} known tools on PATH.")
    missing = [s for s in statuses if not s.installed]
    if missing:
        _say(f"  Missing: {', '.join(s.name for s in missing[:10])}"
             + (f" (+{len(missing)-10} more)" if len(missing) > 10 else ""))
        _say("\n  Install plan for missing tools (run separately in another shell):\n")
        _say(detect.install_plan_human())
    else:
        _say("  All catalog tools present.")
    _ask("\nPress Enter to continue", default="")

    # ── [4/7] API Keys ───────────────────────────────────────────
    _say("\n[4/7] API Keys & Tokens\n")
    _say("Optional but recommended. Stored locally in")
    _say(f"  {settings_path()}")
    _say("(0600 perms — not in the web DB).\n")
    api_keys: Dict[str, str] = {}
    gh = _ask("  GitHub token (for github-subdomains)")
    if gh.strip():
        api_keys["github_token"] = gh.strip()
    interactsh = _ask("  Interactsh server URL (blind-SSRF/OOB callbacks)",
                       default="https://oast.pro")
    if interactsh.strip():
        api_keys["interactsh_server"] = interactsh.strip()
    shodan = _ask("  Shodan API key (passive recon)")
    if shodan.strip():
        api_keys["shodan_api_key"] = shodan.strip()

    # ── [5/7] LLM Setup ──────────────────────────────────────────
    _say("\n[5/7] LLM Setup\n")
    mode = _ask("Backend: 'api' for Claude, 'local' for Ollama, 'skip' for "
                "no-LLM (degraded)", default="api")
    llm: Dict[str, Any] = {"mode": mode}
    if mode == "api":
        llm["api_key"] = _ask("Claude API key (stays in ~/.config/reconforge)")
    elif mode == "local":
        llm["ollama_url"] = _ask("Ollama URL", default="http://localhost:11434")
        llm["opus_sub"]   = _ask("Substitute for Opus 4.7", default="llama3.1:70b")
        llm["haiku_sub"]  = _ask("Substitute for Haiku 4.5", default="llama3.1:8b")

    # ── [6/7] Scope Paste ────────────────────────────────────────
    _say("\n[6/7] Scope Paste (optional)\n")
    _say("Paste your program scope JSON (CLAUDE.md schema). Finish with a")
    _say("blank line and Ctrl-D / Ctrl-Z. Press Enter at an empty prompt to skip.\n")
    buf: List[str] = []
    try:
        for line in in_:
            buf.append(line)
    except KeyboardInterrupt:
        pass
    scope_text = "".join(buf).strip()
    scope_doc: Dict[str, Any] = {}
    if scope_text:
        try:
            scope_doc = json.loads(scope_text)
        except json.JSONDecodeError as e:
            _say(f"  Warning: scope is not valid JSON ({e}). Saving raw.")
            scope_doc = {"_raw": scope_text}
        # Backfill platform_handle from identities if missing
        plat = (scope_doc.get("platform") or "").lower()
        if plat in identities and not scope_doc.get("platform_handle"):
            scope_doc["platform_handle"] = identities[plat]

    # ── [7/7] Vault Pick ─────────────────────────────────────────
    _say("\n[7/7] Vault Pick\n")
    default_vault = str(Path.home() / "Documents" / "BugBountyVault")
    vault = _ask("Vault directory", default=default_vault)

    # ── persist ──────────────────────────────────────────────────
    cfg_dir = config_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)
    out_doc = {
        "setup_complete":     True,
        "platform_identities": identities,
        "api_keys":           api_keys,
        "llm":                llm,
        "vault":              {"path": vault},
    }
    sp = settings_path()
    sp.write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
    try:
        os.chmod(sp, 0o600)  # POSIX-only; no-op on Windows
    except OSError:
        pass

    if scope_doc:
        scopes_dir = cfg_dir / "scopes"
        scopes_dir.mkdir(parents=True, exist_ok=True)
        program_name = (scope_doc.get("name") or "default").lower()
        (scopes_dir / f"{program_name}.json").write_text(
            json.dumps(scope_doc, indent=2), encoding="utf-8",
        )
        _say(f"\nScope saved to {scopes_dir}/{program_name}.json")

    _say(f"\nWizard complete. Settings written to {sp}")
    _say("Run `python main.py` (or `reconforge run`) to start the service.")
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
