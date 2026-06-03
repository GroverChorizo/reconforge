# `scripts/` — ReconForge default workflow hub

Five categories, each with its own README. Pipeline: **recon → vuln →
chain → report**, with **monitor** running continuously in the
background and **c2** off to the side for authorized engagements.

```
scripts/
├── recon/      00-scope-check → 20-alert + master-pipeline.sh
├── vuln/       idor / ssrf / xss-deep / graphql / jwt / race / ...
├── chain/      selfxss-csrf / idor-ssrf / ssrf-cloud-creds / ...
├── monitor/    continuous-enum + template-watcher + install-cron
├── report/     draft-report / cvss-calc / evidence-pack / dup-check
└── c2/         sliver / msf / interactsh-server / ngrok
                (authorized engagements ONLY — see c2/README.md)
```

## Hunting-ready in one command

```bash
export TARGET=acme.com
export SCOPE_FILE=scopes/acme.json
export GITHUB_TOKEN=ghp_...
./recon/master-pipeline.sh 2>&1 | tee run.log
```

That's the spine. After it finishes, layer the per-vuln deep dives:

```bash
# Pull DATESTAMP from the run.log so vuln scripts attach to the same run
DATESTAMP=$(grep -oE 'run root:.*DATESTAMP=([0-9-]+)' run.log | tail -1 | sed 's/.*=//')
export DATESTAMP

./vuln/idor.sh           # needs AUTH_A + AUTH_B
./vuln/xss-deep.sh
./vuln/graphql.sh        # auto-detected if /graphql is alive
./vuln/broken-access.sh
```

Confirmed singles → check for chains:

```bash
./chain/idor-ssrf.sh
./chain/ssrf-cloud-creds.sh
./chain/selfxss-csrf-stored.sh
```

Write the report:

```bash
PLATFORM=intigriti VULN_CLASS=ssrf ./report/draft-report.sh
./report/cvss-calc.sh
./report/dup-check.sh ssrf acme.com
./report/evidence-pack.sh
```

Set up continuous monitoring for the long tail:

```bash
./monitor/install-cron.sh acme.com
```

## Environment knobs (shared)

| Variable | Default | Used by |
|---|---|---|
| `TARGET` | (required) | all |
| `SCOPE_FILE` | unset | recon, vuln, chain, c2 (refuse) |
| `RECONFORGE_OUTPUT_DIR` | `~/Documents/ResearchVault/03-Research/Recon` | all |
| `DATESTAMP` | auto | per-run dir name |
| `THREADS` | `10` | most tool wrappers |
| `RATE_LIMIT_RPS` | `50` | nuclei, naabu, httpx |
| `GITHUB_TOKEN` | unset | github-subdomains, trufflehog |
| `INTERACTSH_URL` | unset | ssrf, xxe, chain/idor-ssrf |
| `AUTH_A` / `AUTH_B` | unset | idor, broken-access |
| `BLIND_XSS_URL` | unset | dalfox callback |
| `WORDLIST_DIR` | `/usr/share/seclists` | content discovery, kiterunner |

Set them once in `~/.config/reconforge/settings.json` (the wizard prompts
for most), or per-shell with `export`.

## Exit code conventions

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | required input/env var missing |
| 3 | scope refused (fatal) |
| 4 | required tool not installed |
| 5 | required upstream phase didn't produce its output |
| 6 | runtime failure in a tool invocation |
| 8 | c2/ authorization not present |
| 9 | c2/ refused because target is in a bug-bounty scope |

`master-pipeline.sh` treats codes 4, 5, 6 as **skippable** (logs WARN
and continues to the next phase). Codes 3, 8, 9 are **fatal** for the
whole run.

## What's NOT here

- **GUI** — every script is bash. The ReconForge web UI exposes the
  same tools via the registry; these scripts are the CLI mirror.
- **Per-engagement playbooks** — those live in your notes vault under
  `05-Playbooks/`.
- **Tool wordlists** — pulled via the Dockerfile (SecLists + gf-patterns).
- **Custom payloads** — payload libraries belong in the vault, not the
  repo. Reference them from scripts via `WORDLIST_DIR`.

## Building on top of these scripts

The scripts are intentionally compact and operator-readable. To add
new ones:

1. Follow the existing file's structure (source `_lib.sh`, call
   `require_target` + `ensure_scope`, write to `out_dir`).
2. Use the standard exit-code conventions.
3. Document inputs/outputs at the top of the file.
4. Add a README entry in the relevant subdirectory.

The ReconForge agent layer (`agents/*.py`) can call these scripts via
`subprocess` for any workflow the registry doesn't model directly.
