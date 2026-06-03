# ReconForge Hunting Playbook

Once recon has produced the URL corpus, the JS inventory, the
fingerprinted alive list, and the gf-bucketed candidates, the hunt
proper begins. This document covers everything **after**
[`RECON_PLAYBOOK.md`](RECON_PLAYBOOK.md):

- **Per-vuln deep dives** — confirm specific classes
- **Chaining** — compose weak findings into critical impact
- **Continuous monitoring** — catch new attack surface as it ships
- **Reporting** — turn confirmed findings into accepted submissions
- **Authorized post-exploitation** — C2 and persistence, home-lab / CTF / pentest only

**TL;DR:**
- Recon is the first 80% of the work. Hunting is the next 15%. Reporting is the final 5%, but it's the part that pays.
- Singles get downgraded all the time. **Chains** are where the 5-figure bounties live. The same self-XSS that's a $0 lone finding becomes a $5k chain when paired with a CSRF and a stored render.
- Bug-bounty work stops at vulnerability confirmation. C2, persistence, and post-exploitation belong to authorized pentest / CTF / your own home lab. ReconForge enforces this at the script layer (`scripts/c2/_lib.sh:require_authorization`).

---

## Table of contents

1. [The kill chain](#the-kill-chain)
2. [Per-vuln deep dives](#per-vuln-deep-dives)
3. [Chaining](#chaining)
4. [Continuous monitoring](#continuous-monitoring)
5. [Reporting](#reporting)
6. [Authorized post-exploitation](#authorized-post-exploitation)
7. [Mindset](#mindset)

---

## The kill chain

```
recon ──→ vuln deep dive ──→ chain attempt ──→ confirm ──→ report
   ↑                                                          │
   └────────────── continuous monitoring ─────────────────────┘
```

`scripts/recon/master-pipeline.sh` produces everything to the right of
"recon". `scripts/vuln/`, `scripts/chain/`, `scripts/monitor/`, and
`scripts/report/` are each a stage in this loop.

---

## Per-vuln deep dives

`scripts/vuln/` ships 12 per-class playbooks. Each one reads from the
canonical recon paths and emits findings under
`$RECONFORGE_OUTPUT_DIR/<target>/<datestamp>/vuln/<class>/`.

### IDOR

```bash
AUTH_A='Cookie: session=alice' AUTH_B='Cookie: session=bob' \
  scripts/vuln/idor.sh
```

Method: two-account differential replay. Identical 200 responses
across both auth contexts = high-confidence IDOR (85%). Different-
length 200s = mid-confidence (55%; partial leak).

**Top-paying flavor:** mutation IDOR on GraphQL. Many implementations
authorize *that you can call the mutation* but not *that you own the
resource it touches*. Pair `scripts/vuln/graphql.sh` (introspection /
schema rebuild) with `scripts/chain/graphql-mass-assign.sh`.

### SSRF

```bash
# Recon Phase 13 must be running OR INTERACTSH_URL set
scripts/vuln/ssrf.sh
```

Method: spray gf-ssrf candidates with Interactsh-token URLs;
correlate callbacks. Bug-bounty payouts scale with what the SSRF
reaches:

- Same-host file:// → low (info disclosure)
- Internal HTTP → medium (lateral SSRF)
- Cloud metadata service (169.254.169.254) → critical (IAM cred theft → `scripts/chain/ssrf-cloud-creds.sh`)
- Internal admin panel → critical (auth bypass)

### XSS — beyond the gf bucket

`scripts/recon/15-xss-targeted.sh` handles the easy reflectors.
`scripts/vuln/xss-deep.sh` adds:

- **CSP audit** — find weak directives that turn a reflected XSS into a working `alert(1)`
- **DOM-sink mining** via jsluice (extracts `document.write` / `innerHTML` / `eval` source-sink pairs from JS bodies)
- **dalfox deep-mode** with `--mining-dom --deep-domxss`
- **Stored-XSS candidate selection** — endpoints with `comment` / `bio` / `note` / `message` / `review` in the path

The highest-payout XSS is stored, in an admin-visible context. The
deep-dive script surfaces those candidates explicitly.

### GraphQL

```bash
GQL_URL=https://api.target.com/graphql scripts/vuln/graphql.sh
```

Five-step pipeline:
1. graphw00f fingerprint (Apollo / Hasura / Lighthouse / etc.)
2. introspection probe (if on, dump schema)
3. clairvoyance field-suggestion fallback (when introspection is disabled)
4. InQL query / mutation enumeration
5. alias-batching DoS check (50 aliased `__typename` in one request)

If introspection is on, every mutation that touches user records is
an IDOR candidate. The `scripts/chain/graphql-mass-assign.sh` recipe
probes them.

### JWT

```bash
TOKEN=eyJ... ENDPOINT=https://api.target.com/me scripts/vuln/jwt.sh
```

Three probes:
1. **alg=none** — strip the signature; if the server accepts, auth is broken
2. **RS256→HS256 confusion** — if a `PUB_KEY` is provided, re-sign with HS256 using the public key as the HMAC secret
3. **Weak secret advisory** — for HS256 tokens, the script outputs the hashcat command for offline cracking (`hashcat -m 16500`)

The implementation lives in `attack/jwt.py`; the shell script is a
thin wrapper that surfaces the result.

### Race conditions

```bash
TARGET_URL=https://target.com/redeem AUTH='Cookie: session=...' \
  BODY='{"code":"BONUS123"}' N=30 \
  scripts/vuln/race.sh
```

Method: thread-barrier-synchronized parallel POSTs. >1 successful
response on a presumably single-shot gate = race window confirmed.
Not a true single-packet attack (TCP last-byte sync) but catches
most app-layer races.

Targets: one-time codes, referral bonuses, limited inventory checkout,
concurrent session limits.

### Open redirect

```bash
EVIL_URL=https://example.evil/ scripts/vuln/open-redirect.sh
```

Tests plain payload replacement + the standard bypass set
(`//example.evil`, `/\\example.evil`, `//google.com@example.evil`,
`https:example.evil`, `/%2f%2fexample.evil`, etc.).

Standalone open-redirect = low. Open redirect chained with OAuth
`redirect_uri` allowlist domain match = full account takeover.
`scripts/chain/open-redirect-oauth.sh` covers the chain.

### CSRF

```bash
AUTH='Cookie: session=...' scripts/vuln/csrf.sh
```

Method: probe state-changing endpoints for anti-CSRF tokens, SameSite
cookie attrs, and Referer enforcement. Outputs a CSV with confidence
score per endpoint.

Bug-bounty CSRF is increasingly rare on first-party sites (SameSite=Lax
default in modern browsers helps a lot), but vendor / iframe / mobile
APIs frequently lack proper anti-CSRF.

### XXE

```bash
scripts/vuln/xxe.sh
```

Probes every XML-accepting endpoint with both in-band classic
(`/etc/passwd` via SYSTEM entity) and OOB (Interactsh-fetched DTD)
payloads. Requires Phase 13 (`13-oob-callback`) for OOB confirmation.

### SSTI

```bash
scripts/vuln/ssti.sh
```

Tests common engine markers across the top 50 gf-ssti candidates:
`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`. Hits on `49` in the
response body = engine identified.

### Broken access control (URL / method)

```bash
scripts/vuln/broken-access.sh
```

Probes admin-protected endpoints with the standard bypass vector
library:
- `X-Original-URL`, `X-Rewrite-URL` (Apache/IIS bypass)
- `X-Forwarded-For: 127.0.0.1` (origin allowlist bypass)
- `X-HTTP-Method-Override: DELETE`
- Case manipulation (`/Admin` vs `/admin`)
- Trailing slash / double slash variants

### CAPTCHA bypass

```bash
ENDPOINT=https://target.com/login CAPTCHA_PARAM=g-recaptcha-response \
  CAPTCHA_TOKEN=03AGdBq25... scripts/vuln/captcha-bypass.sh
```

Four classic bypasses:
1. Drop the captcha param entirely
2. Send empty token
3. Send literal `true` / `1` (some servers parse loosely)
4. Replay one valid token N times

---

## Chaining

Six prebuilt chain recipes in `scripts/chain/`:

| Recipe | Pre-condition | Outcome |
|---|---|---|
| `selfxss-csrf-stored.sh`  | Self-XSS + weak CSRF + stored render to admin | Admin session takeover |
| `idor-ssrf.sh`            | IDOR writes a URL field that the server fetches | SSRF-as-victim |
| `open-redirect-oauth.sh`  | Open redirect on the OAuth allowlist domain | OAuth account takeover |
| `takeover-chain.sh`       | Subdomain takeover candidate + parent-domain cookie | Session hijack |
| `ssrf-cloud-creds.sh`     | SSRF that reaches `169.254.169.254` | AWS/GCP/Azure cred theft → CloudFox |
| `graphql-mass-assign.sh`  | Introspected schema with `*Update*` / `*Create*` mutations | Mass-assignment privilege escalation |

Each chain confirms each link before continuing — a failed link
aborts the chain early, so wasted runs are cheap. The successful
chains drop a `REPORT-template.md` or `CHAIN-REPORT.md` in the output
dir with CVSS guidance + remediation language pre-filled.

### Reporting a chain

1. **Stop at confirmation.** Don't escalate beyond what's necessary
   to prove impact. The screenshot is the trophy.
2. **Reproduce twice from clean state** before writing the report.
   Triagers downgrade flaky reproductions.
3. **CVSS the chain, not the weakest link.** A self-XSS is 4.0; the
   chain to admin takeover is 9.0+. Per-link CVSS goes in the
   technical-details section; chain CVSS is the headline.
4. **Per-link remediation.** The program may want to fix only the
   weakest link, but you've shown the system-level impact.

---

## Continuous monitoring

`scripts/monitor/install-cron.sh acme.com` wires hourly enum + 6-hourly
template watch into the user's crontab. The XSSRat-style md5-diff
pattern means expensive nuclei sweeps fire **only when the subdomain
list or the template library changes** — never on a no-op.

State layout: `~/.local/share/reconforge/monitor/<target>/`

| File | Purpose |
|---|---|
| `subs.txt` | rolling deduped subdomain master list |
| `subs.md5` | md5 of subs.txt this run |
| `subs.prev.md5` | md5 of the previous run |
| `subs.delta.txt` | NEW subdomains this run (the actionable set) |
| `templates.md5` | nuclei templates dir md5 |
| `last-scan-iso` | timestamp of last template-watcher pass |
| `delta-nuclei-<epoch>.jsonl` | nuclei output keyed by epoch |
| `log` | rolling append-only diagnostic log |

Alerts via `notify` (Slack/Discord/Telegram) on:
- New subdomains discovered
- Nuclei medium/high/critical hits

### Why two daemons?

XSSRat's vulnerability-testing-strategy chapter draws the line: the
subdomain list and the template library are independent inputs. Each
deserves its own change-detection loop. **continuous-enum** catches
new attack surface; **template-watcher** catches new attack
techniques against existing surface. Their union covers both axes.

---

## Reporting

`scripts/report/` provides four tools:

1. **`draft-report.sh`** — generates a platform-specific skeleton.
   Pass `PLATFORM=hackerone | intigriti | bugcrowd | yeswehack | synack`.
2. **`cvss-calc.sh`** — interactive or vector-arg CVSS 4.0 calculator.
3. **`evidence-pack.sh`** — bundles screenshots + req/resp + JSONL
   findings into a zip with a regex secret scrub.
4. **`dup-check.sh`** — queries the local findings DB for prior
   reports on this target / vuln class.

### Per-platform discipline

- **HackerOne**: title format strict (`[VulnClass] in [asset] allows [impact]`); CVSS 4.0 vector in dedicated field.
- **Intigriti**: header MUST include `X-Intigriti-Username: researcher-handle` on PoCs. Use the bullet structure (Exec / Tech / Repro / CVSS / Impact / Remediation / Evidence).
- **Bugcrowd**: pick the VRT category FIRST — the dropdown determines base severity. **No edits after submission.** Video PoC strongly preferred.
- **YesWeHack**: business-impact narrative for non-technical readers. OWASP Top 10 + CWE both required.
- **Synack**: invite-only. Structured JSON-like fields. Sequential screenshots numbered to match reproduction steps.

### Evidence hygiene

`evidence-pack.sh` redacts an allowlist of secret formats from text
artifacts before zipping. The redaction is **best-effort**: always
`unzip -l` and spot-check before uploading. The regex sweep covers
`Bearer`, `session=`, `ghp_*`, `AKIA*`, AWS secret keys, and common
`password=` / `api_key=` patterns. It will miss novel formats.

---

## Authorized post-exploitation

`scripts/c2/` provides setup helpers for:

- **Sliver C2 server** (Bishop Fox) — modern, actively maintained
- **Metasploit multi-handler** — classic catcher
- **Self-hosted Interactsh server** — replaces public oast.pro for OOB callbacks against hardened targets
- **ngrok tunnel** — CTF / quick exposure

**Hard authorization gate.** Every script in `c2/` refuses to run
without one of:

- `HOME_LAB=yes` — your own lab infrastructure
- `CTF=yes CTF_NAME=<name>` — named CTF competition
- `PENTEST_AUTH=<path>` — path to your letter of authorization

The exception is `interactsh-server-deploy.sh`, which is bug-bounty-
relevant (you self-host on infrastructure you own; the server itself
plants nothing on a target). It still requires authorization but
does not refuse on bug-bounty `SCOPE_FILE`.

A second gate (`refuse_if_bug_bounty_target`) hard-refuses if
`SCOPE_FILE` points at a bug-bounty program covering the target.
Bug-bounty work stops at vulnerability confirmation — period.

### Pentest playbook (foothold → privesc → lateral)

For authorized pentests, the standard sequence:

1. **Foothold via web** — chain a confirmed vuln (RCE / SQLi-RCE / file-upload) to a shell
2. **Local enum** — `linpeas.sh` / `winpeas.exe`, manual SUID / capability / cron audit
3. **Privesc** — kernel exploits, sudo misconfig, service abuse
4. **C2 establishment** — `scripts/c2/sliver-start.sh` or `msf-handler.sh`
5. **Persistence** — out of scope for bug-bounty; standard for pentest
6. **Lateral** — credential harvesting + `impacket` / `crackmapexec`

These tools and playbooks belong to the engagement, not to ReconForge
itself. The repository ships the orchestration; per-engagement
implants and TTPs are operator territory.

---

## Mindset

The XSSRat / OccupyTheWeb / Mitnick consensus, distilled:

- **Methodology beats inspiration.** Same checklist every time.
  Coverage compounds; cleverness doesn't.
- **Recon is 80–90% of the work.** A target you've enumerated
  thoroughly will give up bugs even with average exploitation skill;
  a target you haven't will resist the best exploitation.
- **Patience is the multiplier.** The bug is there. Most reports
  miss because the hunter stopped two steps shy.
- **Read raw bytes, not summaries.** Burp's "interesting" tab is a
  model. The request/response pair is the truth.
- **Document or it didn't happen.** Every payload tried, every null
  result. The notes compound into your asymmetric advantage.
- **Operate under observation.** Defenders watch. Rate-limit by
  default. Use identifying headers where the program requires them.
- **Honesty compounds.** Padding a report buys nothing and costs
  reputation. Triagers reward clean reports with faster triage and
  private-program invites.

These show up in code: `scope_guard.py` enforces them, the agent
prompts in `agents/*.py` thread them, the per-script `_lib.sh`
files implement them.

---

## See also

- [`docs/RECON_PLAYBOOK.md`](RECON_PLAYBOOK.md) — the recon kill chain
- [`scripts/README.md`](../scripts/README.md) — script-hub quick start
- [`CLAUDE.md`](../CLAUDE.md) — operator + agent doctrine
- [`scope_guard.py`](../scope_guard.py) — the authoritative scope check
