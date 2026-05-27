# `scripts/recon/` — phase-by-phase recon scripts

Default scripts composing the operator toolchain ReconForge ships. Each
script is a thin wrapper over the canonical one-liner from
[`docs/RECON_PLAYBOOK.md`](../../docs/RECON_PLAYBOOK.md), with scope
verification + tool-availability + structured logging prepended.

## Quick start

```bash
export TARGET=acme.com
export SCOPE_FILE=scopes/acme.json
export GITHUB_TOKEN=ghp_...            # for github-subdomains, trufflehog github
export INTERACTSH_URL=                 # filled by Phase 13 if you run that first
./master-pipeline.sh 2>&1 | tee run.log
```

That runs all 21 phases in order. Each phase writes its own subdir under
`$RECONFORGE_OUTPUT_DIR/$TARGET/<YYYY-MM-DD-HHMM>/`.

## Phase index

| # | Phase | Tools | Output | Skip-safe? |
|---|---|---|---|---|
| 00 | scope-check       | scope_guard / hacker-scoper                 | — (exit 3 on refusal) | no |
| 01 | passive-enum      | subfinder, amass, assetfinder, findomain, github-subdomains, crt.sh, chaos | `subs.txt` | rarely |
| 02 | resolve           | puredns (preferred) / dnsx + alterx          | `resolved.txt` | no |
| 03 | tls-cdn           | tlsx, cdncheck                              | `tls.txt`, `non-cdn.txt` | yes |
| 04 | port-scan         | naabu (preferred) / nmap                    | `ports.txt` | yes |
| 05 | http-probe        | httpx                                       | `alive.txt`, `httpx.jsonl` | no |
| 06 | crawl             | katana (preferred) / hakrawler              | `urls.txt`, `js.txt` | yes |
| 07 | js-analyze        | jsluice, trufflehog, mantra                 | `js-secrets.jsonl` | yes |
| 08 | content-discovery | ffuf / feroxbuster / gobuster               | per-host `*.txt` | yes (heavy) |
| 09 | archive-urls      | gau, waybackurls, unfurl                    | `archive-urls.txt`, `params.txt` | yes |
| 10 | param-discovery   | paramspider, arjun, x8                      | per-tool `.txt` | yes |
| 11 | pattern-filter    | gf (xss/sqli/ssrf/idor/lfi/...)             | `gf-<pattern>.txt` | yes |
| 12 | payload-replace   | qsreplace                                   | per-pattern payload URLs | yes |
| 13 | oob-callback      | interactsh-client (background daemon)        | `session-url.txt`, `callbacks.txt` | yes |
| 14 | vuln-scan         | nuclei (severity ≥ medium + KEV pass)       | `nuclei.jsonl`, `reports/` | yes |
| 15 | xss-targeted      | Gxss → dalfox → hard-confirm grep            | `confirmed.txt` | yes |
| 16 | crlf              | crlfuzz                                     | `crlf.txt` | yes |
| 17 | sqli              | sqlmap (gated — SQLI_CONFIRM=yes)            | `sqlmap-out/` | yes |
| 18 | screenshot        | gowitness v3                                | local SQLite + PNGs | yes |
| 19 | secrets           | trufflehog (fs / github / git)               | `*.jsonl` | yes |
| 20 | alert             | notify (Slack/Discord/etc)                   | `summary.txt` | yes |

## Environment knobs

Defaults are set in `_lib.sh`; override per-run via env or
`~/.config/reconforge/settings.json`.

| Variable | Default | Purpose |
|---|---|---|
| `TARGET` | (required) | Root domain in scope |
| `SCOPE_FILE` | unset | Path to ReconForge scope JSON; if unset, scope check is logged-only |
| `RECONFORGE_OUTPUT_DIR` | `~/Documents/CyberBrain/03-Research/Recon` | Run root |
| `DATESTAMP` | `YYYY-MM-DD-HHMM` | Per-run dir name (override for reruns) |
| `THREADS` | `10` | Tool-wide thread cap |
| `RATE_LIMIT_RPS` | `50` | Tool-wide req/s cap (matches ReconForge default) |
| `WORDLIST_DIR` | `/usr/share/seclists` | Root for content/param wordlists |
| `RESOLVERS_FILE` | `~/wordlists/resolvers.txt` | puredns/shuffledns input |
| `GITHUB_TOKEN` | unset | github-subdomains, trufflehog github |
| `CHAOS_KEY` | unset | PD Chaos API |
| `BLIND_XSS_URL` | unset | dalfox `-b` |
| `INTERACTSH_URL` | unset | filled by Phase 13 |
| `OOB_SERVER` | `oast.pro` | Interactsh server (self-host for mature targets) |
| `SQLI_CONFIRM` | `no` | Phase 17 (sqlmap) refuses without `=yes` |
| `SKIP_PHASES` | unset | Comma-separated phase numbers to skip (e.g. `08,17`) |

## Inter-phase data flow

Each script reads from canonical paths under
`$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/<phase>/` so phases can be
re-run individually. Example: after rebuilding the subdomain spine,
re-run only phases 02+:

```bash
SKIP_PHASES="00,01" ./master-pipeline.sh
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | `$TARGET` unset |
| 3 | scope refused (master pipeline aborts hard) |
| 4 | required tool missing |
| 5 | required input file missing (run earlier phase first) |
| 6 | runtime error in tool invocation |

## OPSEC defaults

- **Rate limit**: `RATE_LIMIT_RPS=50` and `THREADS=10` are conservative.
  Bump only after reading the program's policy URL.
- **User-Agent**: Most tools accept a UA; for Intigriti targets, also set
  `X-Intigriti-Username: grover` upstream (see ReconForge scope_guard).
- **OOB callbacks** via the public `oast.pro` server are increasingly
  blocklisted; self-host `interactsh-server` on your own VPS via
  `scripts/c2/interactsh-server-deploy.sh`.
- **No persistence on targets.** These scripts read; they don't plant.
  C2/foothold work lives under `scripts/c2/` and is gated to home-lab
  scope.

## Continuous monitoring

For watch-it-like-a-hawk targets, use `scripts/monitor/`:

```bash
scripts/monitor/install-cron.sh acme.com
```

That installs hourly subdomain re-enumeration with md5-diff against the
last run; on diff, fires nuclei only against the new hosts.
