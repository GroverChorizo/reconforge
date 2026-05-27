# `scripts/vuln/` — per-class deep-dive playbooks

Once recon has produced URL corpora + gf-filtered candidates + JS
inventory, the per-class scripts in this directory drive the actual
vulnerability hunt. Each script reads from the canonical recon paths
under `$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/` and writes findings
to `$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/vuln/<class>/`.

## Index

| Script | Vuln class | XSSRat ref | Key inputs |
|---|---|---|---|
| `idor.sh`           | IDOR (BAC: object) | 00x10-03 | `AUTH_A`, `AUTH_B`, `gf-idor.txt` |
| `ssrf.sh`           | SSRF                 | 00x10-11 | `gf-ssrf.txt`, `INTERACTSH_URL` |
| `xss-deep.sh`       | XSS (DOM/stored/CSP) | 00x10-04* | URL corpus, JS bodies |
| `graphql.sh`        | GraphQL              | —        | `GQL_URL` (defaults `/graphql`) |
| `jwt.sh`            | JWT                  | —        | `TOKEN`, `ENDPOINT`, optional `PUB_KEY` |
| `race.sh`           | Race conditions      | —        | `TARGET_URL`, `AUTH`, `BODY` |
| `open-redirect.sh`  | Open redirect        | 00x10-01 | `gf-redirect.txt`, `EVIL_URL` |
| `csrf.sh`           | CSRF surface         | 00x10-02 | URL corpus, optional `AUTH` |
| `xxe.sh`            | XXE                  | 00x10-06 | XML endpoints, `INTERACTSH_URL` |
| `ssti.sh`           | SSTI                 | 00x10-07 | `gf-ssti.txt` (or URL corpus) |
| `broken-access.sh`  | BAC (URL/method)     | 00x10-03 | URL corpus, optional auth |
| `captcha-bypass.sh` | CAPTCHA bypass       | 00x10-10 | `ENDPOINT`, `CAPTCHA_PARAM` |

## Typical invocation

```bash
export TARGET=acme.com
export DATESTAMP=2026-05-27-0400
export SCOPE_FILE=scopes/acme.json
export AUTH_A='Cookie: session=alice_token'
export AUTH_B='Cookie: session=bob_token'

./idor.sh
./xss-deep.sh
./graphql.sh GQL_URL=https://api.acme.com/graphql
./broken-access.sh
```

## Output convention

```
$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/vuln/<class>/
  findings.{csv,txt,json}    # primary results
  <other artifacts>          # raw probe responses, intermediate files
```

`findings.*` columns include a `confidence` field (0–100). Anything
≥80 is high-confidence and should go to the report draft queue.
Anything 50–79 is mid-confidence and goes to manual review.

## Common env knobs

| Variable | Purpose |
|---|---|
| `SCOPE_FILE` | Path to ReconForge scope JSON — refuses out-of-scope |
| `RECONFORGE_OUTPUT_DIR` | Where recon output lives + where findings get written |
| `DATESTAMP` | Pick a specific recon run to layer on top of |
| `AUTH_A` / `AUTH_B` | Two-account credentials for IDOR + BAC |
| `INTERACTSH_URL` | OOB callback target (filled by recon Phase 13) |
| `BLIND_XSS_URL` | dalfox `-b` callback |
| `EVIL_URL` | open-redirect destination |
| `RATE_LIMIT_RPS` | inherits from `_lib.sh` |

## Chains

Several of these scripts feed each other naturally — see
`scripts/chain/` for prebuilt multi-class recipes:

- `idor.sh + ssrf.sh` → cross-tenant data exfil
- `xss-deep.sh + csrf.sh` → admin-takeover stored chain
- `graphql.sh + idor.sh` → mutation-IDOR enumeration
- `ssrf.sh + cloudfox` → AWS credential extraction
