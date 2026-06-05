# ReconForge

ReconForge is a local-first bug-bounty operations console for disciplined recon,
scope enforcement, continuous monitoring, and evidence-ready reporting. It wraps
the tools operators already use (`subfinder`, `amass`, `dnsx`, `httpx`,
`katana`, `nuclei`, `jsluice`, `arjun`, `paramspider`, and more) behind one
workflow that keeps targets in scope, traffic attributable, and notes ready for
your vault.

Run it on your machine. Point it at authorized program scope. Start passive,
promote to active only when the rules allow it, and keep the output organized
from first subdomain to final report draft.

For authorized security research only. ReconForge is built for bug-bounty and
internal security work where you have explicit permission to test.

## What You Get

- A browser-based recon console at `http://127.0.0.1:8342/` (binds loopback by default).
- First-run setup wizard for handles, API keys, tool detection, and vault path.
- Scope-aware scan submission with local SQLite storage; declared scope is
  enforced by `scope_guard` on every job and tool dispatch.
- OPSEC defaults for target-touching tools: rate limits, optional proxy, jitter,
  random User-Agent, and platform identity headers.
- An app-driven **kill-chain pipeline**: run the `scripts/recon/NN-*.sh` phases
  from the UI with live logs and results ingested back into the database.
- A **six-agent AI pipeline** (Scope Guard → Strategist → Recon → Hunter →
  Analyst → Reporter) with a switchable backend — Claude API or local Ollama —
  and a per-run cost cap.
- Editable command builders (Passive, Active, URL, JS, parameter, vuln-triage),
  a findings board, tool-health view, evidence, and report workflow cards.
- Continuous monitoring with adaptive cadence for enrolled targets.
- Notes-vault-friendly contract output and report archive paths.

## Requirements

| Requirement | Minimum | Notes |
| --- | --- | --- |
| Python | 3.11+ | Python 3.12 recommended |
| OS | Linux, macOS, Windows | Linux has the best toolchain support |
| Disk | 2 GB+ | Tool output and screenshots can grow quickly |
| Browser | Any modern browser | UI is served locally |

Optional but useful:

- Docker, if you prefer containerized execution.
- GitHub token for `github-subdomains` and richer passive recon.
- ProjectDiscovery `notify` config for monitor alerts.
- Claude API or Ollama if you want agent-assisted analysis and reports.
- A markdown notes vault or any directory for exported notes.

## Install

### Local Python

```bash
git clone https://github.com/GroverChorizo/reconforge.git
cd reconforge
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python main.py
```

On Windows PowerShell:

```powershell
git clone https://github.com/GroverChorizo/reconforge.git
cd reconforge
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python main.py
```

### Docker

```bash
docker compose up --build
```

If you use Docker, keep the data volume mounted somewhere durable. ReconForge
stores jobs, screenshots, reports, and SQLite state locally.

## First Launch

Start the server:

```bash
python main.py
```

On first run, ReconForge opens the terminal setup wizard. The wizard writes
local configuration to `~/.config/reconforge/settings.json` and does not store
API keys in the web app database.

The wizard asks for:

| Step | Input | Why It Matters |
| --- | --- | --- |
| Platform identities | Your handles for Intigriti, HackerOne, Bugcrowd, YesWeHack, Synack | Used for required headers and report metadata |
| Tool detection | Nothing to type unless tools are missing | Prints install commands for missing recon tools |
| API keys | GitHub, Interactsh server, Shodan | Enables richer passive recon and OOB testing support |
| LLM setup | Claude API, Ollama, or skip | Enables optional agent workflows |
| Scope JSON | Optional program scope | Seeds the first authorized target/program |
| Vault path | Path to your notes vault | Controls where notes and contract output are written |

To re-run the wizard later:

```bash
python -m wizard
```

To skip setup in scripted environments:

```bash
python main.py --skip-setup
```

## Log In

After startup, ReconForge prints the first admin password once:

```text
====================================================
  ReconForge first-run - admin account created
  Username : admin
  Password : <copy this immediately>
====================================================
```

Open `http://127.0.0.1:8342/`, authenticate as `admin`, and keep the generated
password in your password manager.

## Configure Your First Program

ReconForge works best when every target is tied to a program scope. You can add
scope during the wizard or through the UI.

In the UI:

1. Open `Target -> Intake`.
2. Enter the target domain, program name, workspace name, and vault path.
3. Paste in-scope and out-of-scope rules.
4. Pick `Passive` for the first run.
5. Save the intake.

You can also place JSON scope files in:

```text
~/.config/reconforge/scopes/
```

Example scope:

```json
{
  "name": "example-program",
  "platform": "intigriti",
  "platform_handle": "your-handle",
  "policy_url": "https://example.com/program-policy",
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

Scope rules to remember:

- Out-of-scope wins over in-scope.
- `*.example.com` does not include `example.com`; add the apex separately.
- Active workflows should only run after you confirm the program rules allow
  that traffic.

## Configure OPSEC Defaults

Open `Admin -> Settings` and review the OPSEC panel before active scans.

Recommended starting values:

| Setting | Default | Use |
| --- | --- | --- |
| HTTP/SOCKS proxy | blank | Route tools through Burp, Caido, Tor, or a lab proxy |
| Rate limit | `50` req/s | Applied to target-touching tools that support it |
| Delay | blank, monitor uses `200ms` | Adds per-request spacing/jitter |
| Random User-Agent | on | Disabled automatically when a program User-Agent is pinned |

Platform handles from the wizard are converted into headers such as
`X-Intigriti-Username` or a HackerOne researcher User-Agent where applicable.

## Run Your First Scan

Start with passive recon:

1. Open `Recon -> Passive Recon`.
2. Review the listed commands.
3. Copy or run the passive workflow for your authorized target.
4. Watch `Dashboard`, `Jobs`, and the activity console for progress.

Passive recon uses public sources and should not send traffic to the target.
Typical commands include:

```bash
subfinder -d example.com -all -silent -o subs/subfinder.txt
amass enum -passive -d example.com -o subs/amass.txt
curl -s "https://crt.sh/?q=%25.example.com&output=json"
```

After passive recon, move to active probing only when scope allows it:

1. Open `Recon -> Active Recon`.
2. Resolve candidates with `dnsx`.
3. Probe live hosts with `httpx`.
4. Keep rate limits conservative until you understand the program tolerance.

From the dashboard, you can also submit a scan directly with a target domain.
ReconForge records the job, tool output, logs, screenshots, and discovered
assets under `recon_data/`.

## Continuous Monitoring

Use `Operations -> Monitors` to enroll a target for recurring lightweight recon.

The scheduler starts with a 4-hour cadence. If new assets keep appearing, the
cadence stays tight. If the target is quiet, it backs off through longer bands
up to 7 days. New assets reset the cadence and can trigger `notify` if enabled.

Monitor scans are intended for passive enum plus light HTTP probing. Loud vuln
triage remains a deliberate operator action.

## Vault Configuration

ReconForge has two vault-related paths:

| Setting | Meaning |
| --- | --- |
| Vault root | Your notes vault root, usually set in the wizard or UI |
| `reconforge_output_dir` | Contract output directory, defaults to `./out/` |

Set or update them in `Admin -> Settings`, or edit:

```text
~/.config/reconforge/settings.json
```

Typical settings:

```json
{
  "vault_path": "C:/Users/you/Documents/ResearchVault",
  "reconforge_output_dir": "./out",
  "auto_emit_contract": true,
  "auto_ingest_vault": true,
  "notify_on_new_assets": true
}
```

Each completed run can emit a contract directory:

```text
out/<program-slug>/<YYYY-MM-DD-HHmm>/
├── _manifest.json
├── hosts.jsonl
├── endpoints.jsonl
├── findings.jsonl
├── raw/
└── screenshots/
```

Use this output as the handoff point for your notes vault, evidence review, or
downstream reporting workflows.

## Where Data Lives

| Path | Contents |
| --- | --- |
| `~/.config/reconforge/settings.json` | Local identities, API keys, LLM config, vault paths |
| `~/.config/reconforge/scopes/*.json` | Program scope definitions |
| `recon_data/recon.db` | SQLite app state, jobs, assets, findings, users |
| `recon_data/jobs/<job_id>/` | Per-job raw output and intermediate files |
| `recon_data/screenshots/` | Web screenshots |
| `recon_data/backups/` | Local backup archives |
| `out/<program>/<timestamp>/` | Vault/contract export directories |

Move runtime data with:

```bash
RECON_DATA_DIR=/path/to/recon_data python main.py
```

## Useful Commands

```bash
# Start locally
python main.py --host 127.0.0.1 --port 8342

# Start with HTTPS using a generated self-signed certificate
python main.py --https

# Re-run setup
python -m wizard

# Run tests
pytest -q
```

## Safety Model

- ReconForge is local-first. It **binds `127.0.0.1` by default** — pass
  `--host 0.0.0.0` only when you deliberately want LAN access, and put it behind
  your own auth/firewall. Do not expose the web UI to the public internet.
- **Secrets stay server-side.** API keys and tokens are write-only through the
  UI: `GET /api/config` is admin-only and returns secrets masked (`********`),
  never the raw value. Saving a blank key leaves the stored one untouched.
- **Roles.** Each operator gets their own login. Configuration, user
  management, backups, and the LLM/agent backend are admin-only. The Anthropic
  API key is configured per instance by an admin and shared by the agent
  pipeline; a per-run cost cap (`llm.max_cost_usd`) bounds spend.
- Keep program scope current before scanning. Start passive, then promote to
  active only when authorized. Use a proxy when you need raw request visibility.
- Keep platform identity headers configured for programs that require them.
- Do not commit `recon_data/`, vault output, API keys, screenshots, or scan
  artifacts. Local config (`~/.config/reconforge/settings.json`) holds your keys
  and is never committed — keep it `0600`.

## Status

ReconForge is under active development and optimized for practical bug-bounty
operations. Expect fast iteration, local-first defaults, and workflows designed
for researchers who care about coverage, evidence, and clean reporting.
