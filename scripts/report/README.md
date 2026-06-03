# `scripts/report/` — submission scaffolding

Tools that turn a confirmed finding into a submittable report. Each
script is platform-aware and reads from the same `$RECONFORGE_OUTPUT_DIR`
structure the recon/vuln/chain scripts write to.

## Index

| Script | What | Inputs |
|---|---|---|
| `draft-report.sh`  | Generate platform-specific report skeleton    | `PLATFORM` (h1/intigriti/bugcrowd/yeswehack/synack), `TARGET`, `VULN_CLASS` |
| `cvss-calc.sh`     | CVSS 4.0 calculator (interactive or vector arg) | optional vector string |
| `evidence-pack.sh` | Bundle screenshots, req/resp, JSONL findings into a sanitized zip | `TARGET`, `DATESTAMP` |
| `dup-check.sh`     | Query the findings DB for prior reports on this target | `<vuln_class>` `<target>` |

## End-to-end report flow

```bash
# 1. Pick the platform
export PLATFORM=intigriti
export TARGET=acme.com
export DATESTAMP=2026-05-27-0400
export VULN_CLASS=ssrf

# 2. Check for dups first — don't write a report you'll dupe to
./dup-check.sh ssrf acme.com

# 3. Compute CVSS
./cvss-calc.sh "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

# 4. Generate the skeleton
./draft-report.sh
# → writes to: $RECONFORGE_OUTPUT_DIR/acme.com/2026-05-27-0400/reports/draft-intigriti.md

# 5. Fill in placeholders. Reproduction steps, exact request/response,
#    impact, remediation. The skeleton names what each section needs.

# 6. Pack evidence
./evidence-pack.sh
# → produces: $RECONFORGE_OUTPUT_DIR/acme.com/2026-05-27-0400/reports/evidence-acme.com-2026-05-27-0400.zip

# 7. Upload via the platform UI; attach the zip; paste the draft body.
```

## Per-platform notes

### HackerOne
- Title format strict: `[VulnClass] in [asset] allows [impact]`
- Severity is researcher-set but triager-overridable
- CVSS 4.0 vector goes in a dedicated field

### Intigriti
- Header MUST include `X-Intigriti-Username: researcher-handle` on all PoCs
- They explicitly want the bullet structure in the body (Exec / Tech / Repro / CVSS / Impact / Remediation / Evidence)
- Inline screenshots welcome

### Bugcrowd
- Pick the VRT category FIRST — the dropdown determines base severity
- 25,000 char body limit; rich-text editor
- **No edits after submission** — get it right the first time
- Video PoC strongly preferred for chains

### YesWeHack
- Business-impact narrative for non-technical readers
- OWASP Top 10 + CWE both required
- French programs often restrict scope by country/region; check before testing source

### Synack
- Invite-only — verify you're enrolled before testing
- Structured JSON-like fields, follow the template exactly
- Sequential screenshots numbered to match reproduction steps
- Highest payouts on the platform — worth extra effort on report quality

## What `evidence-pack.sh` redacts

A regex sweep over the bundled text artifacts replaces:

- `Bearer <token>` → `<REDACTED>`
- `session=<value>` → `<REDACTED>`
- `ghp_*` (GitHub tokens)
- `AKIA[A-Z0-9]{16}` (AWS access keys)
- `aws_secret_access_key`, `password`, `api_key` followed by a value

This is **best-effort**. Always `unzip -l` and spot-check before
uploading — the regex won't catch every leaked secret format.

## Authorship etiquette

When chains reuse another researcher's primitive (e.g. a published
methodology, a tool's example payload), cite them in the report's
acknowledgement section. Triagers notice; it builds reputation.
