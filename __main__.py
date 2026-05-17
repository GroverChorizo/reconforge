"""
ReconForge CLI entry. Dispatches to:

    python -m reconforge run            — start HTTP server (default 8342)
    python -m reconforge wizard         — first-run Textual TUI (Phase 11)
    python -m reconforge scan <domain>  — submit one scan via API
    python -m reconforge migrate up     — apply pending DB migrations
    python -m reconforge migrate status — list applied/pending
    python -m reconforge attack sample  — print mapper output for synthetic findings
    python -m reconforge scope check    — validate a target against a program JSON

Phase 4a: this is a thin dispatcher. Heavier subcommands (wizard, scan)
land in their respective phases. ``run`` delegates to the existing
``main.py`` to preserve byte-identical behavior — the modular extraction
of main.py into core/job.py / core/dispatcher.py / api/server.py happens
incrementally in later phases.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))


def _cmd_run(argv: list[str]) -> int:
    import main as legacy_main
    # Hand off argv to the existing argparse-based main.
    sys.argv = ["reconforge", *argv]
    legacy_main.main()
    return 0


def _cmd_migrate(argv: list[str]) -> int:
    from db.migrations.runner import _cli as mig_cli
    return mig_cli(argv)


def _cmd_attack(argv: list[str]) -> int:
    from attack.mapper import _cli as att_cli
    return att_cli(argv)


def _cmd_scope(argv: list[str]) -> int:
    from scope_guard import _cli as scope_cli
    return scope_cli(argv)


def _cmd_scan(argv: list[str]) -> int:
    # Quick scan helper: drives /api/jobs via in-process call, bypassing HTTP.
    if not argv:
        print("usage: reconforge scan <domain> [--user <name>]", file=sys.stderr)
        return 2
    domain = argv[0]
    username = "cli"
    if "--user" in argv:
        i = argv.index("--user")
        username = argv[i + 1] if i + 1 < len(argv) else "cli"
    import main as legacy_main
    legacy_main.init_db()
    legacy_main.init_tool_gates()
    jobs = legacy_main.submit_domain(domain, username)
    if not jobs:
        print(f"no jobs created for {domain} (scope rejection?)", file=sys.stderr)
        return 1
    for j in jobs:
        print(f"queued {j.id}  domain={j.domain}")
    return 0


def _cmd_wizard(argv: list[str]) -> int:
    # Phase 11 will replace this with the Textual TUI.
    print("reconforge wizard: not yet implemented (Phase 11). "
          "For now, edit scopes/*.json and set the active program via:")
    print("  python -c \"import main as M; M.init_db(); M.set_config('active_program','scopes/rivian.json')\"")
    return 0


_CMDS = {
    "run":     _cmd_run,
    "migrate": _cmd_migrate,
    "attack":  _cmd_attack,
    "scope":   _cmd_scope,
    "scan":    _cmd_scan,
    "wizard":  _cmd_wizard,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print("ReconForge — agentic ATT&CK-aligned bug-bounty assistant\n")
        print("Subcommands:")
        for name in _CMDS:
            print(f"  reconforge {name}")
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd not in _CMDS:
        print(f"unknown subcommand: {cmd}", file=sys.stderr)
        print(f"available: {', '.join(_CMDS)}", file=sys.stderr)
        return 2
    return _CMDS[cmd](rest)


if __name__ == "__main__":
    sys.exit(main())
