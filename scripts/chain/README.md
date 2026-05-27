# `scripts/chain/` — multi-vuln chain recipes

Single-class findings get downgraded as "low impact" all the time. The
real payouts come from **chains**: weak primitives composed into critical
outcomes. Each script in this directory orchestrates a known chain
pattern — confirming each link before continuing.

## Index

| Script | Chain | Typical CVSS | Payout band |
|---|---|---|---|
| `selfxss-csrf-stored.sh` | self-XSS + CSRF + stored render = admin takeover | 8.5–9.5 | $2k–$10k |
| `idor-ssrf.sh` | IDOR-writes-URL + server-fetch = SSRF-as-victim | 7.5–9.0 | $3k–$15k |
| `open-redirect-oauth.sh` | open redirect + OAuth redirect_uri = account takeover | 8.0–8.8 | $5k–$25k |
| `takeover-chain.sh` | subdomain takeover + cookie scope = session hijack | 8.5–9.5 | $2k–$10k |
| `ssrf-cloud-creds.sh` | SSRF + IMDS = AWS creds → CloudFox enum | 9.0–10.0 | $5k–$50k |
| `graphql-mass-assign.sh` | GraphQL introspection + mass-assignment on mutations | 7.0–9.0 | $1k–$10k |

## Mindset

These scripts are **scaffolding**, not magic. Each one:

1. Asserts the pre-conditions (e.g. an IDOR that writes a URL field).
2. Wires the primitives together with the operator's actual inputs.
3. Confirms each step before continuing — no chain proceeds past a
   failed link, so a wasted run is short.
4. Drops a `REPORT-template.md` or `CHAIN-REPORT.md` at the end with
   CVSS guidance + remediation language.

## Pre-conditions checklist

Most chains require one or more of:

- A confirmed single-class finding from `scripts/vuln/*` (the
  primitive on which the chain layers)
- Two accounts you own (for IDOR / BAC / multi-tenant chains)
- A working OOB callback (`recon/13-oob-callback.sh` running)
- Auth headers for both attacker and victim contexts
- For `graphql-mass-assign.sh`: an introspected schema from
  `vuln/graphql.sh`

## Reporting after a confirmed chain

1. **Stop.** Don't escalate further than confirmation. Take the screenshot.
2. **Reproduce twice** from a clean state — chains lose credibility when
   the triager can't reproduce on the first try.
3. **Use the generated `*-REPORT.md`** as the report skeleton. Replace
   placeholders, attach the per-step evidence files from `OUTDIR/`.
4. **CVSS the chain**, not the weakest link. A self-XSS is a 4.0; the
   chain to admin takeover is a 9.0+.
5. **Note remediation per link** — the program may want to fix only the
   weakest link, but you've shown the system-level impact.

## What's NOT here

- Lateral movement / post-exploitation beyond credential extraction.
  That's `scripts/c2/` and only applies inside authorized pentest /
  CTF scope.
- Persistence on target systems. Bug-bounty programs do not permit it,
  and `scripts/c2/` enforces a refusal if the target matches the
  program's scope file.

## Adding a new chain

Pattern:

```bash
#!/usr/bin/env bash
PHASE="chain-<name>"
. "$(dirname "$0")/../vuln/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

# Step 1: validate pre-condition (the primitive exists)
# Step 2: invoke the primitive script(s) from scripts/vuln/
# Step 3: confirm the chained outcome (callback, response, side-effect)
# Step 4: drop REPORT-template.md with CVSS + remediation
```
