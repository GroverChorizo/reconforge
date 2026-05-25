# ReconForge

A local-first, agentic bug-bounty recon assistant. ReconForge runs entirely on
your machine, orchestrates the standard recon toolchain (`subfinder`, `dnsx`,
`httpx`, `katana`, `nuclei`, `jsluice`, and ~20 others), enforces program scope
on every tool invocation, maps findings to MITRE ATT&CK, and drafts
submission-ready reports for HackerOne, Intigriti, Bugcrowd, YesWeHack, and
Synack — all behind a single web UI you reach at `http://localhost:8342/`.

**For authorized security research only.** Scope Guard rejects any target that
isn't covered by a configured program scope, and the Intigriti report
formatter refuses to generate output without your platform handle attached.

> A full wiki with deep-dive docs (agent internals, workflow customization,
> contract schema) is coming. This README is meant to take you from clean
> machine to first submitted draft.

---

## Contents

1. [Requirements](#requirements)
2. [Install](#install)
3. [First run — the setup wizard](#first-run--the-setup-wizard)
4. [Logging in](#logging-in)
5. [Add your first program](#add-your-first-program)
6. [Run your first scan](#run-your-first-scan)
7. [Read the results](#read-the-results)
8. [Verify a finding](#verify-a-finding)
9. [Generate a report](#generate-a-report)
10. [Vault & contract output](#vault--contract-output)
11. [Where everything lives](#where-everything-lives)
12. [Day-to-day commands](#day-to-day-commands)
13. [Safety guardrails](#safety-guardrails)

---

## Requirements

| What | Minimum | Notes |
|---|---|---|
| Python | 3.11+ | 3.12 preferred |
| OS | Linux (Parrot, Kali, Ubuntu) | macOS and Windows also run |
| Disk | ~2 GB | for tool binaries + scan artifacts |
| Recon tools | none upfront | the wizard tells you exactly what's missing and how to install each |

Optional but recommended:
- **Docker** — bundles the recon toolchain so you can skip system installs.
- **Claude API key** — unlocks the Strategist / Hunter / Analyst / Reporter
  agents. Without one you can still drive recon manually.
- **GitHub PAT** with `public_repo` scope — required by `github-subdomains`.

---

## Install

### Option A — local Python (Linux / macOS)

```bash
git clone https://github.com/grover-bb/reconforge.git
cd reconforge
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Option B — Docker

```bash
docker compose up --build
```

The image bundles the recon toolchain. Data persists in the `recon_data` named
volume; mount a different one to relocate it.

### Windows

Same as Option A in PowerShell, with `.\.venv\Scripts\Activate.ps1` instead of
`source`.

---

## First run — the setup wizard

```bash
python main.py
```

On first launch ReconForge detects that `~/.config/reconforge/settings.json`
doesn't exist and auto-runs the **setup wizard** in your terminal. The wizard
writes a single local config file (`0600` perms on POSIX) and **never stores
credentials in the web app DB**.

The seven screens, with what each one is asking for and why:

| # | Screen | What you give it | What it's used for |
|---|---|---|---|
| 1 | **Welcome** | Press Enter | OPSEC reminder |
| 2 | **Platform Identities** | Your researcher handle on each of Intigriti / HackerOne / Bugcrowd / YesWeHack / Synack (blank = skip) | Injected into required headers (`X-Intigriti-Username`, etc.) on every outbound request, and into HackerOne's identifiable User-Agent. **Required for report generation on Intigriti.** |
| 3 | **Tool Detect** | Press Enter | Scans `PATH` for all 24 catalog tools and prints copy-pasteable install commands for anything missing (apt / `go install` / `pip`). Paste them into another shell — the wizard does not run `sudo` for you. |
| 4 | **API Keys** | `GITHUB_TOKEN`, Interactsh server URL (default `https://oast.pro`), Shodan key | `GITHUB_TOKEN` unlocks `github-subdomains`; Interactsh is used for blind-SSRF / OOB callbacks; Shodan for passive recon enrichment. |
| 5 | **LLM Setup** | `api` + Claude API key, `local` + Ollama URL, or `skip` | Powers the agentic pipeline. `skip` gives you manual recon only — fine for getting started. |
| 6 | **Scope Paste** *(optional)* | Paste a program scope JSON, or blank to skip | Creates `~/.config/reconforge/scopes/<name>.json`. If you skip, add programs through the UI later. `platform_handle` is auto-filled from screen 2. |
| 7 | **Vault Pick** | Path to your Obsidian vault (default `~/Documents/BugBountyVault`) | Where the Reporter writes Obsidian-friendly notes. |

To re-run the wizard later (it overwrites `settings.json`):

```bash
python -m wizard
```

To bypass entirely (systemd / CI / non-interactive):

```bash
python main.py --skip-setup
```

---

## Logging in

After the wizard exits, the server starts and prints your admin password
**exactly once**:

```
====================================================
  ReconForge first-run — admin account created
  Username : admin
  Password : <copy this immediately>
====================================================
```

Copy it. Open `http://127.0.0.1:8342/` and log in. To reset it later, delete
the user row in SQLite and restart the server — a new password will be
generated.

---

## Add your first program

ReconForge organizes everything around **programs**. A program is your scope +
platform metadata + bounty ranges. You can add one three ways:

**Via the UI:** Settings → Programs → New. Paste the scope JSON, save.

**Via the wizard's Scope Paste screen** (covered above).

**By dropping a file** into `~/.config/reconforge/scopes/<program>.json`.

The scope JSON shape — `scopes/example.json` is a working template:

```json
{
  "name": "example-program",
  "platform": "intigriti",
  "platform_handle": "<YOUR_HANDLE>",
  "policy_url": "https://app.intigriti.com/programs/example/policy",
  "in_scope": [
    {"type": "domain",   "value": "example.com",    "tier": 1},
    {"type": "wildcard", "value": "*.example.com",  "tier": 2},
    {"type": "cidr",     "value": "203.0.113.0/24", "tier": 3}
  ],
  "out_of_scope": [
    {"type": "domain",   "value": "careers.example.com"},
    {"type": "wildcard", "value": "*.dev.example.com"}
  ],
  "bounty_ranges": {
    "critical": [2000, 5000], "high":   [1000, 3000],
    "medium":   [500,  1000], "low":    [100,  500]
  }
}
```

Two rules baked into Scope Guard you should know about:

1. **Out-of-scope always wins.** A subdomain that matches an out-of-scope
   pattern is rejected even if it also matches an in-scope wildcard.
2. **`*.example.com` does NOT include `example.com` itself.** List the apex
   explicitly if it's in scope.

Verify a target without launching anything:

```bash
python -m reconforge scope check --program scopes/example.json --target sub.example.com
# → {"allowed": true, "tier": 2, "headers": {"X-Intigriti-Username": "..."}}
```

---

## Run your first scan

Once a program exists, the top-bar **program selector** appears and the whole
console re-orients around it. Pick the program, then:

### 1. Pick a workflow + mode

| Workflow | What it does | Mode it implies |
|---|---|---|
| `passive_recon` | OSINT-only subdomain enumeration (`subfinder`, `amass -passive`, `crt.sh`, `findomain`). Zero traffic to target. | safest — always allowed |
| `active_recon` | DNS resolution + HTTP probing + screenshots (`dnsx`, `httpx`, `gowitness`). Sends requests. | `active_recon` |
| `content_discovery` | URL discovery and content fuzzing (`katana`, `feroxbuster`, `ffuf`). | `content_discovery` |
| `vuln_triage` | Nuclei + targeted vuln scans on confirmed assets. | `vuln_triage` |
| `evidence_collection` | Re-run targeted tools to capture raw req/resp pairs for a draft. | `evidence_collection` |
| `report_drafting` | Per-platform draft generation (no scanning). | `report_drafting` |
| `retest` | Re-verify a previously-closed finding. | `retest` |

The selected mode gates which tools the pipeline allows. `passive_recon` is
the safest default for a new program.

### 2. Pre-flight gate

Every tool launch above `passive_recon` shows a **pre-flight modal** with:

- The matched scope rule and tier
- Allowed/disallowed HTTP methods for the mode
- An excerpt of the program's Rules of Engagement (from `policy_url`)
- The exact command that will run (variables expanded)
- The effective rate limit (default 50 req/s, 10 threads, 200ms jitter)

The default is **Cancel**. You must explicitly acknowledge to proceed. This
is intentional — it catches scope mistakes before they cost you the program.

### 3. Watch it run

The Jobs view streams stdout from each tool in real time. Stats (CPU, memory,
disk, queue depth) live in the dashboard. Discovered hosts appear in the
**Assets tree** with scope badges as they're confirmed.

---

## Read the results

After a scan completes you'll have output in three places:

### In the web UI

- **Assets tree** — hierarchical view of discovered subdomains, each tagged
  with tier, scope status, HTTP fingerprint, and screenshot. Click a node
  for endpoints, tech stack, response headers.
- **Findings Kanban board** — vuln candidates surfaced by Nuclei and the
  Hunter agent, organized by status:
  `new → needs_review → confirmed → draft_ready → submitted → retesting / closed`.
  Drag cards between columns to update status.
- **Dashboard** — counts by tier, scope-block log, recent jobs.

### In `recon_data/` on disk

```
recon_data/
├── recon.db              SQLite — all programs, jobs, findings, sessions
├── jobs/<job_id>/        per-job working dir (raw tool stdout, intermediate files)
├── screenshots/          gowitness PNGs of probed hosts
├── backups/              tarball snapshots (manual or auto-backup worker)
└── tmp/                  scratch space, cleaned every few hours
```

Move it with `RECON_DATA_DIR=/path/to/data python main.py`.

### As a "contract directory" for the Obsidian vault

See [Vault & contract output](#vault--contract-output).

---

## Verify a finding

Click a finding card to open the detail page. Six tabs:

| Tab | What to do here |
|---|---|
| **Overview** | Title, severity, CVSS, affected asset, status |
| **Raw Evidence** | The actual request/response pair that triggered the detection |
| **AI Analysis** | Hunter/Analyst output. **Mutable** until you hit Verify; once verified it freezes with `verified_by` + `verified_at` |
| **ATT&CK / CWE / OWASP** | Taxonomy mapping for your report |
| **Manual Verification** | Curated checklist for the vuln class (IDOR, mass-assignment, XSS, XXE, SSRF, takeover). You must tick every item before the Quality Gate will let you draft a report |
| **Drafts** | Generated per-platform drafts (only available once status is `draft_ready`) |

To move a finding to `draft_ready`, complete the Manual Verification
checklist and drag the card to the next column.

---

## Generate a report

On the Drafts tab, pick the platform. The **Report Quality Gate** runs 10
deterministic checks before letting you copy:

1. Title names the vuln class + asset + impact
2. All required sections present (Summary, Reproduction, PoC, Impact, CVSS, Remediation)
3. CVSS 4.0 vector + per-metric justification
4. Working PoC (not a placeholder)
5. Scope re-verified at draft time (catches deleted/moved assets)
6. No secrets / tokens / cookies / internal hostnames leaked in evidence
7. Manual Verification checklist acknowledged
8. Platform handle present (Intigriti will refuse to format without it)
9. Severity matches CVSS score band
10. Evidence chain links resolve

Copy-to-clipboard is gated until all 10 pass. Submit through the platform's
own UI — ReconForge never sends reports for you.

The draft also writes a `BUG-XXX.md` file into your Obsidian vault for
permanent archive.

---

## Vault & contract output

Every completed pipeline run also emits a **contract directory** that the
CyberBrain Obsidian vault's `tools/ingest_recon.py` can consume:

```
$RECONFORGE_OUTPUT_DIR/<program-slug>/<YYYY-MM-DD-HHmm>/
├── _manifest.json    run metadata, tool versions, scope used
├── hosts.jsonl       one host per line: subdomain, IP, status, tech
├── endpoints.jsonl   discovered URLs with method, status, length
├── findings.jsonl    vuln candidates with severity, evidence ref
├── raw/              raw tool stdout (placeholder; tools may drop here)
└── screenshots/      gowitness output
```

Default `$RECONFORGE_OUTPUT_DIR` is `./out/`. Schema spec lives in the vault
(`CyberBrain/RECONFORGE_CONTRACT.md`); a pinned copy is at
`tests/fixtures/reconforge-manifest.schema.json`.

Emission is automatic at end-of-run and **never fails the pipeline** — check
the run's event log for `pipeline.contract_emit_failed` if a contract dir is
missing. Re-emit manually:

```bash
python -m reconforge contract emit --job-id <id> [--vault-output PATH]
```

---

## Where everything lives

| Path | What's there |
|---|---|
| `~/.config/reconforge/settings.json` | Local identities, API keys, LLM config. `0600`. Source of truth for credentials; mirrored read-only into web DB on each boot. |
| `~/.config/reconforge/scopes/*.json` | Program scope JSON files. |
| `recon_data/recon.db` | SQLite — programs, jobs, findings, sessions, ATT&CK mappings. |
| `recon_data/jobs/<id>/` | Per-job stdout, intermediate files. |
| `recon_data/screenshots/` | Gowitness PNGs. |
| `recon_data/backups/` | Tarball snapshots. |
| `./out/<program>/<timestamp>/` | Contract directory for vault ingest (override with `RECONFORGE_OUTPUT_DIR`). |
| `~/Documents/BugBountyVault/` | Obsidian-friendly notes the Reporter writes (set in wizard). |

---

## Day-to-day commands

```bash
# Start the server
python main.py --host 127.0.0.1 --port 8342

# HTTPS with auto-generated self-signed cert
python main.py --https

# Skip the wizard at boot (systemd, CI, scripted env)
python main.py --skip-setup

# Re-run the setup wizard (overwrites ~/.config/reconforge/settings.json)
python -m wizard

# Submit a scan from the CLI (no browser)
python -m reconforge scan example.com

# Check a target against a scope file before launching anything
python -m reconforge scope check --program scopes/example.json --target sub.example.com

# Apply pending DB migrations (usually happens automatically on boot)
python -m reconforge migrate up
python -m reconforge migrate status

# Re-emit the vault contract directory for a completed job
python -m reconforge contract emit --job-id <id>
```

---

## Safety guardrails

These are non-negotiable in the codebase, not just policy:

- **No synthetic data.** ReconForge will not generate fake HTTP responses or
  fabricate vulnerability evidence. Every claim in a finding traces to a real
  request/response pair stored in `recon_data/`.
- **No unauthorized targets.** Scope Guard runs before *every* tool
  invocation. Out-of-scope entries always win over in-scope wildcards.
- **No silent header drops.** Report generators raise an error rather than
  send unattributed traffic. If you see "platform_handle required," re-run
  the wizard or fix the program JSON.
- **Conservative defaults.** 50 req/s, 10 threads, 200ms jitter, T2 nmap
  timing. Aggressive mode requires explicit operator confirmation per scan.
- **Pre-flight ACK.** Mod-active+ tool launches show the exact command,
  rate, and matched scope rule. Default action is Cancel.
- **Local-only by default.** Server binds `0.0.0.0` but the printed banner
  always points at `127.0.0.1`. Don't expose it to the internet — there's
  no rate limit on the login endpoint.

---

## License

MIT
