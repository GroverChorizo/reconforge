# ReconForge

ReconForge is an agentic, ATT&CK-aligned bug bounty reconnaissance assistant. It combines a local web dashboard, a SQLite-backed scan queue, external recon tool orchestration, scope enforcement, ATT&CK mapping, agent memory, report drafting, and Obsidian-friendly output.

ReconForge is intended for authorized security research only. Configure program scope before scanning, and only run it against assets where you have explicit permission.

## What It Does

- Runs a local web UI for managing targets, jobs, findings, reports, monitors, backups, users, and tool settings.
- Orchestrates common recon tools such as `amass`, `subfinder`, `assetfinder`, `findomain`, `dnsx`, `httpx`, `gowitness`, `nuclei`, `nikto`, `ffuf`, `wafw00f`, and `nmap`.
- Enforces program scope before dispatching work through `scope_guard`.
- Maintains scan state, history, screenshots, resources, backups, and findings in SQLite.
- Adds an agentic pipeline: ScopeGuard -> Strategist -> Recon -> Hunter -> Analyst -> Reporter.
- Maps findings to MITRE ATT&CK techniques and produces submission drafts for HackerOne, Bugcrowd, Intigriti, YesWeHack, Synack, and common report formats.
- Supports Claude API mode and local Ollama fallback for LLM-backed agents.

## v0.2.0 Operator Console (Phases 13-20)

The v3 UI is a program-workspace shell — pick a program, the whole console
re-orients around it. Operator flow:

1. **Onboard** — paste a program scope JSON. ReconForge stores it as a
   first-class `programs` row and offers it in the topbar selector.
2. **Pick a workflow + mode** — `passive_recon`, `active_recon`,
   `content_discovery`, `vuln_triage`, `evidence_collection`,
   `report_drafting`, `retest`. The chosen mode gates which tools the
   pipeline allows. `passive_recon` is the safest default.
3. **Pre-flight** — every mod-active+ tool launch passes through a modal
   showing the matched scope rule, allowed/disallowed methods, RoE
   excerpt, command preview, and effective rate-limit. Cancel default,
   explicit ACK required to proceed.
4. **Recon + Hunt** — the agentic pipeline runs end-to-end (or partial
   per mode). Discovered subdomains appear in the Assets tree with
   scope badges; Hunter playbook output lands in the Findings Kanban
   board.
5. **Triage** — drag findings between status columns (`new` →
   `needs_review` → `confirmed` → `draft_ready` → `submitted` →
   `retesting` / `closed`). Click a card for the detail page with
   tabs: Overview · Raw Evidence · AI Analysis · ATT&CK/CWE/OWASP ·
   Manual Verification · Drafts.
6. **Verify** — Manual Verification tab carries the curated checklist
   for the vuln class (IDOR, mass-assignment, XSS, XXE, SSRF,
   takeover). AI Analysis rows are mutable until the operator clicks
   Verify; verified rows freeze with `verified_by` / `verified_at`.
7. **Report** — per-platform drafts. The Report Quality Gate runs 10
   deterministic checks (title, sections, evidence, scope re-verified,
   no secrets, manual checklist acknowledged). Copy-to-clipboard is
   gated until all checks pass.

Open `http://localhost:8342/` after starting the server. The legacy SPA
stays reachable behind `RECONFORGE_UI=legacy` for emergency rollback.

## Repository Layout

```text
main.py                 Legacy HTTP server, web UI, scan queue, auth, and tool orchestration
__main__.py             CLI dispatcher for run, scan, migrate, attack, scope, and wizard commands
agents/                 Agent runtime and ScopeGuard, Strategist, Recon, Hunter, Analyst, Reporter
api/                    JSON route helpers for findings, heatmaps, submissions, and agent runs
attack/                 ATT&CK taxonomy, mapper, and heatmap aggregation
core/                   Agentic pipeline and shared signal types
db/migrations/          Forward-only SQLite migrations
obsidian/               Vault writing helpers
scopes/                 Example program scope JSON files
submissions/            Platform-specific report draft formatters
tools/                  Tool detection, registry, and dispatch helpers
ui/spa/                 Extracted SPA assets for the newer interface work
wizard/                 First-run Textual/plain-text wizard
tests/                  Unit, integration, and smoke tests
```

Runtime output is written under `recon_data/` by default and is intentionally ignored by Git.

## Vault contract output

Every completed agentic-pipeline run emits a contract-compliant directory
that the CyberBrain Obsidian vault's `tools/ingest_recon.py` can ingest:

```
<RECONFORGE_OUTPUT>/<program-slug>/<YYYY-MM-DD-HHmm>/
    _manifest.json
    hosts.jsonl
    endpoints.jsonl
    findings.jsonl
    raw/         (placeholder; tools may drop raw output here later)
    screenshots/ (placeholder)
```

`<RECONFORGE_OUTPUT>` resolves from `$RECONFORGE_OUTPUT_DIR` (default
`./out/`). The schema is owned by the vault — see
`CyberBrain/.system/schemas/reconforge-manifest.schema.json` and
`CyberBrain/RECONFORGE_CONTRACT.md`. A pinned copy lives at
`tests/fixtures/reconforge-manifest.schema.json`.

Emission happens automatically at end-of-run in
`core/pipeline.py::run_agentic_pipeline()` and never marks the pipeline
failed if it errors — pipeline status is independent of vault sync.
**A completed run with no contract directory is not a pipeline failure**:
check the run's event log for `pipeline.contract_emit_failed` and
re-emit manually with the command below. To backfill or re-emit a run by
ID:

```powershell
python -m reconforge contract emit --job-id <id> [--vault-output PATH]
```

The vault then promotes drafts via:

```powershell
python tools\vault_gateway.py promote-run --run-id rf-<id> --program <slug>
```

## Requirements

- Python 3.11+
- Optional but recommended: Docker and Docker Compose
- Optional external recon tools, depending on enabled modules:
  - `amass`, `subfinder`, `assetfinder`, `findomain`, `sublist3r`
  - `dnsx`, `httpx`, `gowitness`, `nuclei`, `nikto`
  - `wafw00f`, `ffuf`, `nmap`
- Optional LLM backend:
  - Claude API key for hosted agent runs
  - Ollama for local model mode

The Docker image installs the main recon toolchain for Linux targets.

## Quick Start

### Local Python

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python main.py --host 127.0.0.1 --port 8342
```

Open `http://127.0.0.1:8342`.

On first run, ReconForge creates an admin account and prints the generated password to the terminal. Save it before closing the terminal.

### Docker Compose

```powershell
docker compose up --build
```

Open `http://127.0.0.1:8342`.

Docker persists data in the `recon_data` volume mounted at `/data` inside the container.

## Common Commands

Start the web service:

```powershell
python main.py --host 127.0.0.1 --port 8342
```

Start with HTTPS and generated self-signed certs:

```powershell
python main.py --host 127.0.0.1 --port 8342 --https
```

Queue a scan without the browser:

```powershell
python -m reconforge scan example.com --user cli
```

Apply pending database migrations:

```powershell
python -m reconforge migrate up
```

Show migration status:

```powershell
python -m reconforge migrate status
```

Check a target against a scope file:

```powershell
python -m reconforge scope check --program scopes/example.json --target example.com
```

Run the first-run wizard:

```powershell
python -m reconforge wizard
```

If Textual is not installed, the wizard falls back to a plain terminal flow.

## Scope Configuration

Scope files are JSON documents with `in_scope`, `out_of_scope`, optional platform metadata, and optional bounty ranges. Start from `scopes/example.json`:

```json
{
  "name": "example-program",
  "platform": "intigriti",
  "platform_handle": "example",
  "policy_url": "https://example.com/policy",
  "in_scope": [
    {"type": "domain", "value": "example.com", "tier": 1},
    {"type": "wildcard", "value": "*.example.com", "tier": 2}
  ],
  "out_of_scope": [
    {"type": "domain", "value": "careers.example.com"}
  ],
  "bounty_ranges": {
    "critical": [2000, 5000],
    "high": [1000, 3000],
    "medium": [500, 1000],
    "low": [100, 500]
  }
}
```

The scope guard rejects targets that match out-of-scope entries or are not covered by in-scope entries. Keep scope files current with the bug bounty program policy.

## Web UI Workflow

1. Log in with the first-run admin credentials.
2. Open Settings and verify the tool configuration, concurrency, wordlist path, and API keys.
3. Add or select a target in scope.
4. Start a job and monitor progress from the Jobs view.
5. Review discovered subdomains, HTTP metadata, screenshots, and tool findings.
6. Inspect ATT&CK-mapped findings and generated draft reports.
7. Approve, revise, or export submission drafts.
8. Create backups before major changes or after valuable scan sessions.

## Tool Configuration

ReconForge stores tool settings in SQLite and exposes them through the Settings view. Each tool has:

- enabled/disabled state
- command template
- maximum concurrency
- parser mode
- description

Command templates support variables such as:

- `$DOMAIN$`
- `$SUBDOMAIN$`
- `$OUTPUT$`
- `$INPUT_FILE$`
- `$THREADS$`
- `$WORDLIST$`
- `$GITHUB_TOKEN$`

Tools that are disabled or missing from `PATH` are skipped or marked unavailable. The `crt.sh` module uses an HTTP API and does not require a local binary.

## LLM Configuration

Agent-backed phases can run in hosted API mode or local mode.

Hosted mode expects a Claude API key in ReconForge config:

```json
{
  "llm.mode": "api",
  "llm.api_key": "..."
}
```

Local mode uses Ollama model substitutes:

```json
{
  "llm.mode": "local",
  "llm.ollama_default_model": "llama3.1:8b",
  "llm.ollama_opus_substitute": "llama3.1:70b",
  "llm.ollama_haiku_substitute": "llama3.1:8b"
}
```

Agent runs track prompt tokens, completion tokens, estimated cost, status, and errors in the `agent_runs` table. The default job cost cap is `$5`.

## Data and Backups

By default, runtime data is stored in:

```text
recon_data/
```

Important subdirectories include:

- `jobs/` for per-job artifacts
- `screenshots/` for captured web screenshots
- `backups/` for tarball backups
- `tmp/` for temporary files
- `recon.db` for SQLite state

Set `RECON_DATA_DIR` to move runtime data:

```powershell
$env:RECON_DATA_DIR = "C:\tmp\reconforge-data"
python main.py
```

## Testing

Install development dependencies and run the suite:

```powershell
python -m pip install -e ".[dev]"
pytest
```

The tests use temporary SQLite databases and mock external tool or LLM calls where needed.

## Security Notes

- Do not commit `recon_data/`, generated certs, API keys, session cookies, or scan artifacts.
- Rotate any token that was ever pasted into Git config, shell history, logs, or screenshots.
- Keep program scope files aligned with the current program policy.
- Review report drafts manually before submitting to any platform.
- External tools can generate traffic quickly; tune concurrency and rate limits before scanning production assets.

## License

MIT
