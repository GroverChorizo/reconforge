"""
ReconForge CLI entry. Dispatches to:

    python -m reconforge run            — start HTTP server (default 8342)
    python -m reconforge wizard         — first-run Textual TUI (Phase 11)
    python -m reconforge scan <domain>  — submit one scan via API
    python -m reconforge migrate up     — apply pending DB migrations
    python -m reconforge migrate status — list applied/pending
    python -m reconforge attack sample  — print mapper output for synthetic findings
    python -m reconforge scope check    — validate a target against a program JSON
    python -m reconforge contract emit  — re-emit the vault contract output for a completed job

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


def _cmd_contract(argv: list[str]) -> int:
    """Vault-contract subcommand. Today: ``emit`` re-emits the per-run
    directory for a job that already completed. Useful for backfilling runs
    that finished before the emitter shipped, or for testing on a known job
    without re-running the pipeline.
    """
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage: reconforge contract emit --job-id <id> [--vault-output PATH] "
            "[--domain D] [--program-slug S]\n"
            "  --vault-output PATH overrides $RECONFORGE_OUTPUT_DIR for this run.\n"
            "  --domain / --program-slug are required only if the job row "
            "is missing them.",
            file=sys.stderr,
        )
        return 0 if argv else 2

    sub = argv[0]
    rest = argv[1:]
    if sub != "emit":
        print(f"unknown contract subcommand: {sub}", file=sys.stderr)
        return 2

    import argparse
    import json as _json
    from types import SimpleNamespace

    ap = argparse.ArgumentParser(prog="reconforge contract emit")
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--vault-output", default=None,
                    help="overrides RECONFORGE_OUTPUT_DIR for this run")
    ap.add_argument("--domain", default=None,
                    help="override domain (defaults to completed_jobs.domain)")
    ap.add_argument("--program-slug", default=None,
                    help="override program slug (defaults to job's program)")
    args = ap.parse_args(rest)

    if args.vault_output:
        import os
        os.environ["RECONFORGE_OUTPUT_DIR"] = args.vault_output

    import main as legacy_main
    legacy_main.init_db()
    db = legacy_main.get_db() if hasattr(legacy_main, "get_db") else legacy_main._db()

    # Load the completed job row.
    job_row = db.execute(
        "SELECT job_id, domain, started_at, completed_at, status, "
        "program_id, mode FROM completed_jobs WHERE job_id = ?",
        (args.job_id,),
    ).fetchone()
    if not job_row:
        print(f"no completed_jobs row for job_id={args.job_id}", file=sys.stderr)
        return 1

    def _g(row, key, default=None):
        if hasattr(row, "keys") and key in row.keys():
            return row[key]
        return default

    domain = args.domain or _g(job_row, "domain")
    started_at = _g(job_row, "started_at") or _g(job_row, "completed_at")
    completed_at = _g(job_row, "completed_at")

    # Reconstruct the program dict if available.
    program_dict = None
    pid = _g(job_row, "program_id")
    if pid:
        prog_row = db.execute(
            "SELECT slug, name, scope_json, out_of_scope_json FROM programs WHERE id = ?",
            (pid,),
        ).fetchone()
        if prog_row:
            program_dict = {
                "slug": args.program_slug or _g(prog_row, "slug"),
                "name": _g(prog_row, "name"),
                "in_scope": _json.loads(_g(prog_row, "scope_json") or "[]"),
                "out_of_scope": _json.loads(_g(prog_row, "out_of_scope_json") or "[]"),
            }
    if program_dict is None and args.program_slug:
        program_dict = {"slug": args.program_slug, "name": args.program_slug,
                        "in_scope": [], "out_of_scope": []}

    ctx = SimpleNamespace(
        job_id=args.job_id,
        program=program_dict,
        inputs={"domain": domain, "mode": _g(job_row, "mode") or ""},
        db=db,
    )
    result = SimpleNamespace(
        job_id=args.job_id,
        domain=domain or "",
        status=_g(job_row, "status") or "completed",
        started_at=started_at,
        completed_at=completed_at,
        agents={},   # legacy backfill has no per-agent record
        errors={},
        total_cost_usd=0.0,
    )

    from core.manifest_emitter import emit_run
    out_dir = emit_run(ctx, result)
    print(f"emitted contract output to: {out_dir}")
    return 0


def _cmd_wizard(argv: list[str]) -> int:
    # Phase 11 will replace this with the Textual TUI.
    print("reconforge wizard: not yet implemented (Phase 11). "
          "For now, edit scopes/*.json and set the active program via:")
    print("  python -c \"import main as M; M.init_db(); M.set_config('active_program','scopes/rivian.json')\"")
    return 0


_CMDS = {
    "run":      _cmd_run,
    "migrate":  _cmd_migrate,
    "attack":   _cmd_attack,
    "scope":    _cmd_scope,
    "scan":     _cmd_scan,
    "wizard":   _cmd_wizard,
    "contract": _cmd_contract,
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
