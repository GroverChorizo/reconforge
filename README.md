# ReconForge

A local-first, agentic bug-bounty recon assistant. Orchestrates the standard
recon toolchain (`subfinder`, `dnsx`, `httpx`, `nuclei`, `katana`, `jsluice`,
and ~20 others), enforces program scope on every tool invocation, maps
findings to MITRE ATT&CK, and drafts submission-ready reports for HackerOne,
Intigriti, Bugcrowd, YesWeHack, and Synack — all behind a single web UI you
run on `localhost`.

**For authorized security research only.** ReconForge will refuse to run a
tool against any target that isn't in a configured program scope.

> A full wiki is coming. This README only covers install and first run.

---

## Requirements

- Python 3.11+
- A Linux box (Parrot, Kali, or Ubuntu work best). macOS and Windows also run.
- The recon tools themselves — the wizard tells you exactly which are missing
  and prints the install commands.

Optional:
- Docker, if you want to skip system-level tool installs.
- A Claude API key for the agentic phases (Strategist / Hunter / Analyst /
  Reporter). Without one, you can still drive recon manually.

---

## Install

### Linux / macOS

```bash
git clone https://github.com/grover-bb/reconforge.git
cd reconforge
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Docker

```bash
docker compose up --build
```

The image bundles the recon toolchain. Data persists in the `recon_data`
named volume.

---

## First run

```bash
python main.py
```

On first launch, the setup wizard auto-runs in your terminal. Seven screens:

1. **Welcome** — OPSEC reminder.
2. **Platform Identities** — your handle on each platform you hunt on
   (Intigriti, HackerOne, Bugcrowd, YesWeHack, Synack). Blank skips.
   These are injected into required headers like `X-Intigriti-Username`.
3. **Tool Detect** — scans `PATH` for all 24 catalog tools. Anything missing
   gets a copy-pasteable install plan (apt / go install / pip). Paste it
   into another shell — the wizard doesn't run sudo itself.
4. **API Keys** — `GITHUB_TOKEN` (for `github-subdomains`), Interactsh
   server URL, Shodan key. All optional, all stored at
   `~/.config/reconforge/settings.json` with `0600` perms.
5. **LLM Setup** — Claude API key, Ollama local URL, or skip.
6. **Scope Paste** — drop in a program scope JSON, or skip and add later
   via the UI.
7. **Vault Pick** — where Obsidian-friendly notes get written
   (default `~/Documents/BugBountyVault`).

When the wizard finishes, the server starts and prints your admin password
**once**:

```
====================================================
  ReconForge first-run — admin account created
  Username : admin
  Password : <copy this somewhere safe>
====================================================
```

Open `http://127.0.0.1:8342/` and log in.

### Re-running or skipping the wizard

```bash
python -m wizard                  # re-run anytime (overwrites settings.json)
python main.py --skip-setup       # bypass entirely (for systemd / CI)
```

---

## Day-to-day

```bash
# Start the server
python main.py --host 127.0.0.1 --port 8342

# HTTPS with self-signed cert
python main.py --https

# Queue a scan from the CLI
python -m reconforge scan example.com

# Check a target against a scope file before scanning
python -m reconforge scope check --program scopes/example.json --target sub.example.com

# Apply pending DB migrations (rare; happens automatically on boot)
python -m reconforge migrate up
```

---

## Scope files

Program scopes live in `~/.config/reconforge/scopes/<program>.json` or wherever
you import them via the UI. See `scopes/example.json` for the schema.
**Scope Guard rejects out-of-scope targets unconditionally** — wildcard
matches do *not* include the apex domain unless it's listed explicitly.

---

## Where things live

| Path | What's there |
|---|---|
| `~/.config/reconforge/settings.json` | Your local identities, API keys, LLM config. `0600`. Not synced to the web DB except as read-only mirror. |
| `~/.config/reconforge/scopes/` | Program scope JSON files. |
| `recon_data/` (or `$RECON_DATA_DIR`) | SQLite state, screenshots, job artifacts, backups. |
| `~/Documents/BugBountyVault/` | Obsidian-friendly notes the Reporter writes. |

---

## Safety

- Every claim in a finding must trace to a real request/response pair —
  ReconForge will not generate synthetic vulnerability data.
- Reports won't generate without a `platform_handle` on the program — silently
  sending unattributed traffic to a platform like Intigriti violates the rules.
- Default rate limits: 50 req/s, 10 threads, 200ms jitter. Bump only with
  explicit operator confirmation.

---

## License

MIT
