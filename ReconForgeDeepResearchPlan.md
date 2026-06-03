# ReconForge research, modern recon tooling, and an Arch Linux bug bounty lab

> **Important up-front finding on Deliverable 1.** The repository at `https://github.com/example-org/reconforge` could not be retrieved by any means available during this research: the repo page, the GitHub API endpoint, raw README URLs on both `main` and `master`, the user profile page, and every search engine query for `"example-org" reconforge` all returned no data. The most likely explanations are that the repository is **private**, was **renamed/deleted**, or the **username/repo spelling differs** from what was provided. No third-party site references it either. To unblock a faithful README, please verify the URL/spelling, make the repo public, or paste the entry script + install script into a follow-up so the analysis can be grounded in real code.
>
> Because the user explicitly asked for a *comprehensive README and user guide* anyway, this report includes a **production-quality README template** (Deliverable 1) built around the conventions of comparable recon frameworks (reconftw, Reconx, Reconator, FinalRecon). Replace the bracketed `[…]` placeholders once the actual scripts are visible. Deliverables 2 and 3 are fully grounded in current research.

---

## Deliverable 1 — README.md template for ReconForge

Save the block below as `README.md` at the repo root and adjust placeholders. It is structured so each section maps cleanly to whatever scripts the repo turns out to contain.

````markdown
<h1 align="center">ReconForge</h1>
<p align="center">
  <i>An opinionated, modular reconnaissance pipeline for bug bounty and offensive-security workflows.</i>
</p>
<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
  <img alt="Shell" src="https://img.shields.io/badge/shell-bash%20%7C%20zsh-informational">
  <img alt="Status" src="https://img.shields.io/badge/status-active-success">
</p>

## Overview

ReconForge automates the unglamorous early hours of a bug bounty engagement: subdomain discovery, live-host probing, port scanning, content discovery, JavaScript mining, screenshotting, and template-based vulnerability scanning. It glues together best-of-breed open-source tools — the ProjectDiscovery suite (`subfinder`, `httpx`, `nuclei`, `naabu`, `katana`, `dnsx`), classics (`amass`, `ffuf`, `gau`, `waybackurls`), and a small amount of bespoke parsing — into a phased, idempotent pipeline whose output you can pipe into Burp Suite, Faraday, or your notes vault.

It is **not** an exploit framework. It does not pop shells. It surfaces attack surface; you decide what to do with it.

## Highlights

- **Phased pipeline.** Subdomain enum → resolution → probe → port scan → crawl → fuzz → vuln scan → report. Each phase reads the previous phase's output, so you can resume or rerun individual phases without redoing everything.
- **Tool-agnostic where it matters.** Wrapper functions select the fastest installed tool (e.g., `rustscan` if present, else `naabu`, else `nmap`).
- **Stealth knobs.** Global rate-limit, jitter, and a `--gentle` flag that throttles every tool to bug-bounty-safe defaults.
- **Per-target workspace.** All artifacts go to `~/bb/<target>/<YYYY-MM-DD>/<phase>.txt` so reruns are diff-able.
- **Notify-friendly.** Optional Slack/Discord/Telegram delivery via ProjectDiscovery `notify`.

## Quick start

```bash
# 1. Clone
git clone https://github.com/example-org/reconforge.git
cd reconforge

# 2. Install dependencies (Arch / Debian / macOS auto-detected)
./install.sh

# 3. Run a full scan
./reconforge.sh -d example.com -o ~/bb/example.com
```

## Requirements

| Layer        | Required                                                                                                                            |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| OS           | Linux (Arch, Debian/Ubuntu, Kali, Parrot, BlackArch). macOS works with Homebrew.                                                    |
| Shell        | `bash >= 5.0` or `zsh`                                                                                                              |
| Toolchains   | `go >= 1.22`, `python >= 3.11` (with `pipx`), optional `cargo` for Rust tools                                                       |
| External CLI | `subfinder`, `httpx`, `nuclei`, `naabu`, `katana`, `dnsx`, `ffuf`, `gau`, `waybackurls`, `amass`, `gowitness`, `jq`, `anew`, `curl` |
| Optional     | `rustscan`, `feroxbuster`, `puredns`, `alterx`, `notify`, `interactsh-client`, `BBOT`                                               |
| API keys     | `~/.config/subfinder/provider-config.yaml` for Censys, Shodan, GitHub, VirusTotal, SecurityTrails, Chaos                            |

The bundled `install.sh` runs OS detection and uses `pacman`/`yay`, `apt`, or `brew` accordingly, then `go install`s anything missing.

## Repository layout

> Replace placeholders with actual paths once the repo is accessible.

```
reconforge/
├── reconforge.sh          # main entry point, orchestrates phases
├── install.sh             # OS-aware dependency installer
├── config/
│   ├── reconforge.conf    # default flags, rate limits, paths
│   └── api-keys.conf.example
├── modules/               # per-phase scripts, sourced by reconforge.sh
│   ├── 01_subdomains.sh
│   ├── 02_resolve.sh
│   ├── 03_probe.sh
│   ├── 04_ports.sh
│   ├── 05_crawl.sh
│   ├── 06_content.sh
│   ├── 07_jsmine.sh
│   ├── 08_screens.sh
│   ├── 09_vuln.sh
│   └── 99_report.sh
├── lib/
│   ├── log.sh             # colored logging helpers
│   ├── util.sh             # tool-presence checks, retries
│   └── stealth.sh          # rate-limit / jitter helpers
├── wordlists/             # symlinks to SecLists or curated lists
├── templates/             # custom nuclei templates
├── docs/
│   └── METHODOLOGY.md
└── README.md
```

## Workflow

```
   ┌────────────┐
   │  Target -d │
   └─────┬──────┘
         ▼
[1] Subdomain enum   →  subfinder -all  +  amass -passive  +  github-subdomains  +  chaos
         ▼                                                            (subs.raw)
[2] Resolve / wildcard filter →  dnsx + puredns                       (subs.resolved)
[3] HTTP probe       →  httpx -title -tech-detect -status-code        (alive.txt)
[4] Port scan        →  rustscan|naabu  →  nmap -sV on open ports     (ports.txt)
[5] Crawl & URL mine →  katana + gau + waybackurls + urlfinder        (urls.txt)
[6] Content discovery→  feroxbuster|ffuf with SecLists                (content.txt)
[7] JS analysis      →  subjs + jsluice + mantra                       (js.txt, secrets.txt)
[8] Screenshots      →  gowitness on alive.txt                         (screens/)
[9] Vuln scan        →  nuclei -severity medium,high,critical          (nuclei.out)
[*] Report           →  markdown + optional notify webhook             (REPORT.md)
```

Each phase's outputs feed the next. Phases can be skipped:

```bash
./reconforge.sh -d example.com --skip ports,content
./reconforge.sh -d example.com --only subdomains,probe
```

## Configuration

`config/reconforge.conf` exposes:

```bash
# Global concurrency & stealth
THREADS=50
RATE_LIMIT=150        # req/sec (httpx, nuclei)
JITTER_MS=200
GENTLE_MODE=false     # if true, halves THREADS and RATE_LIMIT

# Tool preferences
PORT_SCANNER="rustscan"   # rustscan|naabu|nmap
CONTENT_TOOL="feroxbuster"

# Wordlists
SUBDOMAIN_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
CONTENT_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"

# Notifications (optional)
NOTIFY_PROVIDER=""    # slack|discord|telegram|empty
```

API keys live in `~/.config/subfinder/provider-config.yaml` and `~/.config/notify/provider-config.yaml`. Never commit these.

## CLI usage

```
Usage: reconforge.sh [-d DOMAIN | -l LIST] [-o OUTDIR] [options]

Targets:
  -d DOMAIN          Single root domain
  -l LIST            File containing one domain per line

Output:
  -o OUTDIR          Output base directory (default: ~/bb/<domain>/<date>)

Phase control:
  --only PHASES      Comma-separated list of phases to run
  --skip PHASES      Comma-separated list of phases to skip
  --resume           Pick up where the last run stopped

Stealth:
  --gentle           Halve concurrency, double jitter, lower rate-limit
  --rate-limit N     Override req/sec
  --threads N        Override worker count
  --user-agent S     Custom UA string

Misc:
  --notify           Send a summary via configured notify channel
  -h, --help
  -v, --version
```

## Examples

```bash
# Aggressive single-target run
./reconforge.sh -d acme.tld

# Polite multi-target run with notifications
./reconforge.sh -l scope.txt --gentle --notify

# Just refresh subdomain & probe phases on a known target
./reconforge.sh -d acme.tld --only subdomains,resolve,probe --resume

# Override port scanner
PORT_SCANNER=naabu ./reconforge.sh -d acme.tld --only ports
```

## Output

```
~/bb/<target>/<YYYY-MM-DD>/
├── subs.raw            # union of all sources
├── subs.resolved       # after dnsx + wildcard filtering
├── alive.txt           # httpx output, one URL per line
├── ports.txt           # host:port[:service]
├── urls.txt            # crawl + wayback union, deduped
├── content.txt         # feroxbuster/ffuf hits
├── js.txt              # JS file URLs
├── secrets.txt         # jsluice/mantra hits
├── nuclei.out          # findings (jsonl by default)
├── screens/            # gowitness PNGs + report.html
└── REPORT.md           # auto-generated summary
```

## Stealth notes

- `--gentle` is the default for **public bug bounty programs**. Aggressive defaults are intended for authorized internal pentests.
- Use a recognizable UA string (`--user-agent "yourhandle (h1.com/yourhandle)"`) so triagers can attribute traffic.
- Run `cdncheck` before any port scan to avoid hammering Cloudflare/Akamai edges.
- Respect program scope. Wildcard scope ≠ permission to scan ASN neighbors.

## Troubleshooting

| Symptom                            | Fix                                                                                      |
| ---------------------------------- | ---------------------------------------------------------------------------------------- |
| `subfinder: command not found`     | Re-source shell rc; ensure `~/go/bin` is on `PATH`                                       |
| `httpx` shows Python's HTTP client | The PyPI `httpx` shadows ProjectDiscovery's. Rename one; install PD's via `pacman`/`go`. |
| nuclei templates missing/old       | `nuclei -update-templates -ut`                                                           |
| Naabu fails with permission error  | `sudo setcap cap_net_raw,cap_net_admin=eip $(which naabu)`                               |
| Wildcard subdomains spam results   | Ensure `puredns` is installed; ReconForge will auto-filter when present                  |
| Got banned / WAF triggered         | Re-run with `--gentle --rate-limit 25 --jitter-ms 500`                                   |

## Contributing

PRs welcome. Please:

1. Match the existing module pattern (`modules/NN_phase.sh` exporting a single `run_phase()` function).
2. Avoid introducing tools without an `install.sh` entry.
3. Run `shellcheck modules/*.sh` before opening a PR.

## License

MIT (placeholder — confirm against the actual LICENSE in the repo).

## Acknowledgements

ReconForge stands on the shoulders of ProjectDiscovery, OWASP Amass, Bishop Fox (jsluice, cloudfox), Black Lantern Security (BBOT), Tom Hudson (`anew`, `gau`, `waybackurls`), Jason Haddix (TBHM methodology), and six2dez (reconftw).
````

**Suggested companion docs to add to `docs/`:**

- `METHODOLOGY.md` — what each phase tries to find and why.
- `STEALTH.md` — full breakdown of rate-limit math and jitter rationale.
- `EXTENDING.md` — how to add a new phase module.
- `TROUBLESHOOTING.md` — extended version of the table above.

---

## Deliverable 2 — Tool recommendations: faster, stealthier, more capable alternatives

The recon landscape in 2026 is dominated by three forces: ProjectDiscovery's pipeline-friendly Go binaries, Black Lantern Security's recursive **BBOT** scanner, and a quiet shift toward AI-augmented and distributed pipelines (Ax Framework, Claude Code plugins, AI-generated nuclei templates). Most of the legacy tools are still good — but several are now strictly dominated.

### The 2026 baseline toolkit

A practical bug-bounty workstation should ship with these, in roughly this order of importance: **BBOT, Nuclei v3, Subfinder v2, httpx, Katana, Naabu (or Rustscan), JSLuice, Feroxbuster, Kiterunner, CloudFox.** Anything beyond that is genre-specific. Honorable mentions: reconftw, Ax Framework (the Axiom successor), InQL, Clairvoyance, TruffleHog, gowitness, alterx, dnsx, puredns, interactsh, uncover, cvemap.

### Direct upgrades to the legacy stack

For **passive subdomain enumeration**, the single biggest leap is **BBOT** (`pipx install bbot`). Where subfinder/amass return what their data sources already know, BBOT runs a recursive event graph that feeds discoveries back into more modules — a TLS cert from one host triggers SAN extraction, which triggers probing, which triggers more brute-forcing. Independent comparisons consistently report 20–50% more unique subdomains than a `subfinder + amass + assetfinder | anew` chain. Subfinder v2.6.3+ remains the right tool when you just want fast passive results to pipe into the next stage; chain it with **chaos** (ProjectDiscovery's curated dataset), **github-subdomains**, and **cero** (TLS SAN harvester) for breadth without BBOT's overhead.

For **DNS resolution and bruteforce**, **puredns** has effectively replaced raw `massdns` because it handles wildcard DNS robustly, and **alterx** (PD) generates target-specific permutations from observed patterns rather than blasting static lists. ProjectDiscovery's **dnsx** and **shuffledns** plug straight into the rest of the PD pipeline.

For **HTTP probing**, **httpx** (Go, ProjectDiscovery — not the Python library of the same name) is still the standard, with DSL filters, screenshot mode, ASN input, CDN detection, and TLSx integration. **fingerprintx** (Praetorian) is a useful complement for non-HTTP service banners.

For **port scanning**, the choice is between **Rustscan** (fastest async TCP, ~6.7s for a full local sweep) and **Naabu** (slightly slower but native to the PD pipeline and supports passive mode via Shodan). For internet-scale work, **masscan** still wins. **smap** sends zero packets — it queries Shodan and emits nmap-style XML, perfect for purely passive workflows.

For **vulnerability scanning**, **Nuclei v3** with the v10.3.x templates is unchallenged in the bug-bounty space; recent ProjectDiscovery binaries ship with profile-guided optimization and Go's experimental Green Tea garbage collector for measurable speed gains. Pair it with **BBOT's `web-thorough` preset** for recursive discovery of vuln-bearing assets, **jaeles** for custom signatures, and **BadDNS** (a BBOT module) for modern subdomain takeover detection.

For **crawling and URL discovery**, **Katana** has displaced gospider and hakrawler thanks to its headless mode for SPAs, JSLuice integration (`-jsl`), URL normalization filtering (`-fst`), and clean JSONL output. **urlfinder** (PD) is now the one-binary replacement for `waybackurls + gau + gauplus`.

For **content and parameter discovery**, **ffuf v2** is still the most flexible (header/POST/parameter fuzzing, raw-request import); **feroxbuster** (Rust) wins for recursive directory busting and respects `robots.txt`; **x8** (Rust) replaces Arjun for hidden-parameter discovery; and **Kiterunner** (Assetnote) is in a class of its own for APIs because it sends contextually correct method+headers+params from a corpus of 67,500+ Swagger specs at ~30k req/s, finding endpoints traditional fuzzers miss entirely.

For **JavaScript analysis**, the modern winner is **jsluice** (Bishop Fox / Tom Hudson) — it parses JS as an AST instead of regexing it, so it understands variable usage and call sites. Pair it with **mantra** for additional secret patterns, **TruffleHog** to *verify* whether discovered secrets are still live (its 2025 cloud-analyze features are excellent), and **gitleaks** for fast pre-commit scanning of source you have access to.

### Specialty toolkits

**GraphQL** testing in 2026 means **graphw00f** for engine fingerprinting, **InQL v5** (Burp extension) for query/mutation generation and live testing, **Clairvoyance** for schema reconstruction when introspection is disabled, **GraphQLmap** for injection scripting, and **GraphCrawler** for automated authz testing. The `Escape-Technologies/awesome-graphql-security` list is the curated index. Note that `graphql-cop` is unmaintained since 2022 — useful for quick checks but not a primary tool.

**API security** workflows revolve around **Kiterunner** (discovery), **swagger-jacker / sj** (auditing exposed Swagger files), **Akto** (open-source platform that auto-generates tests from observed traffic), **APIClarity** (OpenAPI reconstruction from traffic), **mitmproxy** (live interception with Python addons), and **OWASP ZAP**'s API scan mode for OpenAPI/SOAP. **Postman + Newman** remain the standard for chaining authentication flows in CI.

**WAF detection and bypass** starts with **wafw00f** to identify the vendor, then branches: **bypass-firewalls-by-DNS-history** and **CloudFail** for origin-IP discovery via historical DNS and Cloudflare-specific tricks; **nowafpls** (Assetnote, Burp plugin) for body-padding overflow attacks against WAFs that limit inspection size; **h2csmuggler** for HTTP/2 cleartext upgrade smuggling; and the `0xInfection/Awesome-WAF` reference for current encoding-based bypasses (charset flips like `Content-Type: ...; charset=ibm037`, NFKC Unicode normalization, HTTP/0.9 fallback).

### All-in-one frameworks

| Framework        | Architecture                                          | Best for                                                                       |
| ---------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------ |
| **BBOT**         | Python, recursive event-driven, 100+ modules          | Deepest single-host recursive recon and continuous attack-surface monitoring   |
| **reconftw**     | Bash + Go, linear pipeline of best-of-breed tools     | Bug-bounty hunters who want one command, walk away, return to a Faraday import |
| **osmedeus**     | Go (V4), declarative YAML workflow engine + Redis     | Teams building custom pipelines, continuous monitoring, multi-tenant ops       |
| **Ax Framework** | Bash + cloud orchestration (Linode/DO/AWS)            | Distributing single-IP-rate-limited tools across short-lived VPS fleets        |
| **Sn1per**       | Python/Bash, mature but community sentiment moved on  | Legacy users; new hunters should pick BBOT or reconftw                         |

A common 2026 pattern is **BBOT or reconftw running on top of an Ax fleet, results piped into nuclei + custom modules, notifications via PD's `notify`, vulnerabilities tracked in Faraday or BBRF**.

### Stealth and OPSEC best practices

The biggest mindset shift since 2022 is treating **rate-limit adaptivity** as table stakes. reconftw added an `ADAPTIVE_RATE_LIMIT` that backs off on 429/503 responses; mirror this in your own pipelines or you will get banned. Equally important is **scope hygiene**: use `asnmap → tlsx -cn` to confirm ownership before scanning IP ranges, and pre-filter through `cdncheck` so you do not waste payloads on Cloudflare/Akamai edges (which both burns bandwidth and triggers vendor-side blocking that will follow you between targets).

A few specific habits that separate competent hunters from banned ones:

1. Use a recognizable User-Agent that ties traffic to your handle and a contact URL — generic Go/Python UAs are auto-blocked on most prod WAFs and triagers cannot whitelist anonymous traffic.
2. Distribute via cloud fleets (**Ax Framework** has displaced legacy Axiom as the orchestrator of choice — `ax.attacksurge.com`) to spread load over many short-lived VPS instances rather than hammering one IP.
3. Add jitter to every tool that supports it: `nuclei -rl/-rlm`, `httpx -rl`, `ffuf -p`, `katana -rd`. Avoid scanning at exact intervals — anomaly-detection systems flag clockwork.
4. Never run BBOT's "deadly" modules or `-p kitchen-sink --allow-deadly` against bug bounty targets. Several deadly modules perform intrusive checks that violate most program rules.
5. Origin-IP discovery via historical DNS and direct attack of the origin is *technically* possible but **typically out of scope** even when the WAF-fronted target is in scope. Read the program rules.

The most common WAF-ban mistakes are: running ffuf/feroxbuster at default high threads on production; recursive crawlers (Katana, BBOT spider) running unbounded into logout endpoints and triggering account lockouts; submitting unfiltered nuclei output as bugs (severity-filter first); and using residential-proxy networks to evade blocks, which most programs explicitly prohibit.

### 2025–2026 emerging trends

AI is now a real component of recon, not just hype. **claude-bug-bounty** (`shuvonsec/claude-bug-bounty`) is a Claude Code plugin with `/recon`, `/hunt`, `/validate`, `/report`, and `/autopilot` slash commands and integrates Burp's MCP server and HackerOne's MCP server. ProjectDiscovery's PDCP cloud now offers **AI-driven Nuclei template generation from a CVE/PoC URL** (10/day free tier), and the `projectdiscovery/nuclei-templates-ai` repo curates community AI-generated templates. reconftw ships a `reconftw_ai` mode that uses local Ollama models (e.g. `llama3:8b`) to generate human-readable engagement summaries. Anthropic's November 2025 disclosure of the "first AI-orchestrated cyberattack" against ~30 targets, and Claude-credited CVEs (CVE-2026-4747 FreeBSD RPCSEC_GSS RCE; CVE-2026-31402 Linux NFS kernel heap overflow), are concrete public evidence that AI is finding real bugs end-to-end. ProjectDiscovery's **Neo** (commercial, March 2026) is marketed as an autonomous pentesting platform built on 30+ "agent-native" tools in sandboxes; treat the capability claims as marketing until independent benchmarks exist.

HackerOne's 2026 report cites **210% growth in valid AI-vulnerability reports** (mostly prompt injection) and added a dedicated "AI Model" asset type. Bugcrowd's 2026 *Inside the Mind of a Hacker* reports that **~82% of hackers use AI in their workflows.** Whatever you think of the trend, you are competing against AI-augmented hunters now.

### Quick install one-liners

```bash
# ProjectDiscovery toolchain (entire suite via the official manager)
go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -ia    # install all PD tools

# All-in-one frameworks
pipx install bbot
git clone https://github.com/six2dez/reconftw && cd reconftw && ./install.sh
curl -sSL http://www.osmedeus.org/install.sh | bash
git clone https://github.com/attacksurge/ax ~/.axiom/

# DNS / subdomain
go install github.com/d3mondev/puredns/v2@latest
go install github.com/glebarez/cero@latest

# Content & parameter discovery
cargo install feroxbuster
cargo install --locked x8
git clone https://github.com/assetnote/kiterunner && cd kiterunner && make build

# JS analysis
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/Brosck/mantra@latest

# Cloud asset discovery
go install github.com/BishopFox/cloudfox@latest
pip install cloud_enum
go install github.com/sa7mon/s3scanner@latest
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# WAF / GraphQL
pipx install wafw00f graphw00f clairvoyance
git clone https://github.com/doyensec/inql           # Burp extension
git clone https://github.com/vincentcox/bypass-firewalls-by-DNS-history

# AI-augmented (Claude Code plugin)
git clone https://github.com/shuvonsec/claude-bug-bounty
cd claude-bug-bounty && ./install_tools.sh && ./install.sh
```

---

## Deliverable 3 — Tutorial: Building an Arch Linux bug bounty home lab

This tutorial walks from a fresh Arch install to a fully equipped, encrypted, snapshotted, virtualization-capable bug bounty workstation. Total time is **5–7 hours** for someone comfortable with Linux but new to Arch. Save it as `arch-bb-lab.md`.

### 1. Plan the host

The single biggest mistake new Arch hunters make is under-provisioning RAM. **Burp Suite Pro alone wants 8–12 GB on large engagements**, and you will routinely run Burp + a target VM + Chrome + a recon pipeline simultaneously. Recommended baseline for 2026 is **8+ CPU cores with VT-x/AMD-V (and nested virt support), 32–64 GB RAM, 1 TB NVMe** (SecLists alone is ~1 GB, plus VM images and tool caches), and wired 1 Gbps networking — many recon tools are throughput-bound. An optional NVIDIA GPU helps with `hashcat` for password-cracking side quests.

Decide your deployment model honestly. **Bare-metal Arch** gives the best performance and full hardware access (essential for Wi-Fi pentest dongles, USB devices, and raw KVM) at the cost of rolling-release breakage risk before a hunt window. **Arch in QEMU/KVM on a Linux host** trades 5–10% performance for snapshot rollback. **Arch in VirtualBox/VMware on Windows or macOS** is the slowest path with the worst USB and nested-virt support. **Proxmox VE host with an Arch VM** is the ideal permanent home-lab server. **WSL2 Arch** is fine for one-off `httpx`/`nuclei` invocations but unsuitable as a primary recon environment — no real KVM, no raw sockets, and Burp CA installation gets weird across the WSL2 NAT.

The opinionated answer: run Arch bare-metal as the host, do offensive work in nested KVM VMs or Distrobox containers, and keep WSL2 only as a convenience layer if you must stay on Windows.

For dual-boot with Windows: install Windows first, shrink its partition, install Arch into the free space with systemd-boot or GRUB, and **disable Windows Fast Startup** (`powercfg /h off`) — it locks the NTFS partition and can corrupt it across reboots. On Apple Silicon, use Asahi Linux instead of trying to wrestle Arch ARM onto unsupported hardware.

### 2. Install with encryption and snapshots

Use `archinstall`'s guided installer with the **btrfs + LUKS** preset. **LUKS is non-negotiable for bug bounty** — you will hold scope documents, intercepted traffic, customer artifacts, screenshots, and possibly PII; encrypt them at rest. If you prefer manual cryptsetup:

```bash
cryptsetup luksFormat --type luks2 --pbkdf argon2id /dev/nvme0n1p2
cryptsetup open /dev/nvme0n1p2 cryptroot
mkfs.btrfs /dev/mapper/cryptroot
```

Add the `encrypt` hook to `/etc/mkinitcpio.conf` `HOOKS` array before `filesystems`. For unattended boot, `systemd-cryptenroll --tpm2-device=auto` enrolls a TPM2 key alongside the password.

Choose **btrfs over ext4**. Copy-on-write snapshots are perfect for security research: take one before installing experimental tooling or untrusted PKGBUILDs, roll back instantly if it breaks. Built-in zstd compression saves real space on wordlists. Use a subvolume layout that supports `snapper rollback`:

```
@           -> /
@home       -> /home
@.snapshots -> /.snapshots
@var_log    -> /var/log
@var_cache  -> /var/cache    (nodatacow)
```

Exclude `/var/lib/docker`, `/var/lib/libvirt/images`, `/var/lib/containers`, and `/var/cache/pacman/pkg` from snapshots — they snapshot themselves and waste space. Then install snapper with auto pacman hooks:

```bash
sudo pacman -S snapper snap-pac
yay -S snap-pac-grub grub-btrfs btrfs-assistant
sudo snapper -c root create-config /
sudo systemctl enable --now snapper-timeline.timer snapper-cleanup.timer grub-btrfsd.service
sudo snapper list   # verify a snapshot exists
```

Set up a non-root user and lock the root account:

```bash
useradd -m -G wheel,users -s /bin/zsh hunter
passwd hunter
EDITOR=nvim visudo            # uncomment %wheel ALL=(ALL:ALL) ALL
passwd -l root
```

### 3. Configure pacman

Edit `/etc/pacman.conf` once, before installing anything else:

```ini
[options]
Color
ILoveCandy
VerbosePkgLists
ParallelDownloads = 10
CheckSpace
DisableDownloadTimeout

[multilib]
Include = /etc/pacman.d/mirrorlist
```

Uncomment `[multilib]` so 32-bit binaries (some legacy security tools, Burp's bundled Chromium for x86) work. Then refresh and update:

```bash
sudo pacman -Syyu
```

**Memorize three rules.** First, **never `pacman -Sy package`** — partial upgrades on a rolling distro desync the database from installed binaries and break shared libraries. Always `-Syu`. Second, after long downtime fix signature errors with `sudo pacman -Sy archlinux-keyring && sudo pacman -Su`. Third, slow mirrors are usually the bottleneck — install `reflector` and let it pick the fastest local mirrors automatically:

```bash
sudo pacman -S reflector
sudo reflector --country "United States,Canada" --age 12 --protocol https \
    --sort rate --latest 20 --save /etc/pacman.d/mirrorlist
sudo systemctl enable --now reflector.timer
```

### 4. Install yay for the AUR

The official repos lack many security tools (Burp Suite, gowitness, dirsearch, ysoserial, latest nuclei-templates, Caido). The AUR fills the gap. **Pick `yay` over `paru`** — yay is more stable across libalpm bumps; paru's late-2025 build failures made it a poor beginner default.

```bash
sudo pacman -S --needed base-devel git
git clone https://aur.archlinux.org/yay-bin.git ~/build/yay-bin
cd ~/build/yay-bin && makepkg -si
yay -Y --gendb && yay -Y --devel --save
```

PKGBUILDs are bash scripts that run as your user during install. **Read the diff yay shows you**, especially for low-popularity packages — a hostile maintainer can `curl evil | sh` during build. For high-value workstations, use `aurutils` to vet PKGBUILDs once into a signed local repo and reuse.

Useful AUR security packages: `burpsuite`, `burpsuite-pro`, `caido-bin`, `dirsearch`, `gowitness`, `seclists`, `interactsh-client`, `subjs-bin`, `ffuf-bin`, `kiterunner-bin`, `nuclei-templates-git`, `feroxbuster-bin`, `rustscan-bin`, `ysoserial`, `crackmapexec`, `bloodhound`, `responder`, `impacket`, `metasploit`.

### 5. Add the BlackArch overlay

BlackArch is **not a separate distro** like Kali — it is a pacman repo overlay (~2,800 tools as of 2026) that sits next to `[core]` and `[extra]`. You keep your Arch base, kernel, and systemd, and just gain access to more packages. The official install procedure:

```bash
curl -O https://blackarch.org/strap.sh
# Verify SHA1 against https://blackarch.org/downloads.html — it changes periodically
sha1sum strap.sh
chmod +x strap.sh
sudo ./strap.sh
sudo pacman -Syu
pacman -Sl blackarch | wc -l   # expect >2800
```

BlackArch organizes tools into pacman groups; the bug-bounty-relevant ones are `blackarch-recon`, `blackarch-scanner`, `blackarch-webapp`, `blackarch-fuzzer`, `blackarch-crawler`, `blackarch-proxy`, and `blackarch-fingerprint`. Install a category like this:

```bash
sudo pacman -Syu --needed --overwrite='*' blackarch-recon
# Or the upstream-curated subset:
sudo pacman -S --needed blackarch-officials
```

**Never run `pacman -S blackarch`** (the meta group). Upstream explicitly warns against it — it pulls thousands of conflicting dependencies and can wedge the system. The right mental model is: **official repo first, then AUR for currency, then `go install`/`pipx install` for cutting-edge upstream releases, and BlackArch last for breadth**. Take a snapper snapshot before any large BlackArch group install so you can roll back.

### 6. Set up language toolchains and the recon stack

For Go, keep it simple:

```bash
sudo pacman -S go go-tools libpcap
mkdir -p ~/go/{bin,src,pkg}
# Append to ~/.zshrc
export GOPATH="$HOME/go"
export GOBIN="$GOPATH/bin"
export PATH="$PATH:$GOBIN"
```

Then install the ProjectDiscovery suite via `pdtm`, which pins compatible versions and updates them all in one command:

```bash
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install-all
```

Add Tom Hudson's classics and the rest:

```bash
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/{anew,assetfinder,waybackurls,gf,unfurl,httprobe,qsreplace}@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/PentestPad/subzy@latest
```

**Important Python gotcha.** Arch ships Python 3.11+ marked `EXTERNALLY-MANAGED` (PEP 668). `pip install foo` fails by design. **Never use `--break-system-packages`** — it overwrites pacman-managed libraries and silently corrupts your system. Use `pipx` for isolated CLI tools, or a venv per project:

```bash
sudo pacman -S python-pipx python-pip python-virtualenv uv
pipx ensurepath
pipx install bbot
pipx install dirsearch
pipx install arjun
pipx install wafw00f
pipx install truffleHog
pipx install sqlmap
```

`uv` (Rust-based, in `[extra]`) is a 10× faster drop-in replacement for pip/venv/pipx; `uv tool install bbot` is identical in effect to `pipx install bbot`.

For Rust, **prefer rustup over the pacman `rust` package** for security work. The system Go/Rust packages can lag and fight cargo's per-project crates:

```bash
sudo pacman -S rustup
rustup default stable
cargo install rustscan feroxbuster
cargo install --locked x8
```

Add `~/.cargo/bin` to `PATH`.

A subtle bug: the PyPI library `httpx` installs an `httpx` CLI that **shadows ProjectDiscovery's**. If `which httpx` shows `~/.local/bin/httpx`, rename Python's: `mv ~/.local/bin/httpx ~/.local/bin/py-httpx`.

For Burp Suite (the AUR `burpsuite` and `burpsuite-pro` packages bundle the JAR but require Java 21+):

```bash
yay -S burpsuite jre21-openjdk
sudo archlinux-java set java-21-openjdk
burpsuite                                # first run sets up the CA
# HiDPI fix:
java -Dsun.java2d.uiScale=2.0 -jar /usr/share/burpsuite/burpsuite.jar
```

On Wayland, install `xorg-xwayland` and let Burp run via XWayland — the experimental Wakefield JDK works but is still fragile in 2026.

### 7. Configure the network for stealth

A bug bounty workstation needs three network primitives: a **VPN with a killswitch** (so you never leak source IP if the tunnel drops), **DNS leak prevention**, and **Burp as a transparent upstream proxy** for browsers and CLI tools.

Install WireGuard and drop your config in `/etc/wireguard/wg0.conf`:

```bash
sudo pacman -S wireguard-tools
sudo systemctl enable --now wg-quick@wg0
wg show
```

For commercial VPNs, `yay -S mullvad-vpn` or `proton-vpn-gtk-app` work, but many users find raw WireGuard configs from those providers' dashboards more reliable than the GUI clients on Arch.

A **killswitch** is mandatory. The simplest approach is to embed it in `wg-quick`:

```ini
[Interface]
PrivateKey = ...
Address    = 10.x.y.z/32
DNS        = 10.64.0.1
PostUp  = iptables  -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && \
          ip6tables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
PreDown = iptables  -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && \
          ip6tables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT

[Peer]
PublicKey  = ...
Endpoint   = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
```

Test by stopping `wg0` — `curl -m5 ifconfig.me` should fail. For a system-wide nftables solution see the Arch Wiki "WireGuard" page.

For DNS leak prevention, force traffic through systemd-resolved with DNS-over-TLS:

```bash
sudo systemctl enable --now systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

```ini
# /etc/systemd/resolved.conf
[Resolve]
DNS=10.64.0.1
DNSOverTLS=yes
DNSSEC=allow-downgrade
FallbackDNS=
Domains=~.
```

Verify at https://dnsleaktest.com — only the VPN's resolver should appear. For paranoia, swap in `dnscrypt-proxy`.

For **Burp as upstream proxy**, the canonical pattern is browser/CLI → `127.0.0.1:8080` (Burp) → internet (or → `127.0.0.1:1080` SOCKS for pivoting). In Firefox, install **FoxyProxy** with two profiles: a `Burp` HTTP profile pointing at `127.0.0.1:8080` *only for in-scope hosts* (URL/regex patterns), and `Direct` for everything else. This keeps Burp's history clean and avoids leaking unrelated browsing into intercepted traffic. Always set Burp's `Target → Scope` to match the program's RoE and toggle `Settings → Proxy → Stop logging out-of-scope items`.

For **proxychains-ng**:

```bash
sudo pacman -S proxychains-ng
sudoedit /etc/proxychains.conf
```

```conf
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5  127.0.0.1 1080
# socks5  127.0.0.1 9050   # optional Tor for OSINT
```

Use it for tunneling tools that lack native proxy support: `proxychains nmap -sT -Pn -p 80,443 10.0.0.0/24` (the `-sT -Pn` is **required** because proxychains is TCP-only). Note that `strict_chain` will route Burp's `127.0.0.1:8080` *through* the SOCKS proxy and fail; for Burp+SOCKS, set Burp's upstream SOCKS in *Settings → Network* directly instead of layering proxychains.

For per-tool VPN isolation (run one tool through a program-specific VPN while the rest of the system stays on the default route), use Linux network namespaces:

```bash
sudo ip netns add hunt
sudo ip -n hunt link set lo up
sudo ip link set wg0 netns hunt
sudo ip netns exec hunt nuclei -l targets.txt
```

For OSINT only, `pacman -S tor torsocks torbrowser-launcher` and prefix passive lookups with `torsocks`. Do not blast scans through Tor — it is slow and the exit nodes are widely blocked.

### 8. Containerize tools with Docker, Podman, and Distrobox

Docker is the easiest way to run untrusted tools or pinned versions without polluting the host:

```bash
sudo pacman -S docker docker-compose docker-buildx
sudo systemctl enable --now docker.service
sudo usermod -aG docker $USER
newgrp docker
docker run --rm hello-world
```

`docker` group membership is effectively root, so for sensitive workflows prefer **Podman** (rootless, daemonless, drop-in CLI):

```bash
sudo pacman -S podman podman-compose buildah skopeo aardvark-dns netavark
podman info | grep rootless
alias docker=podman
```

The single most useful container tool on Arch for hunters is **Distrobox**, which lets you run Kali, Parrot, or Ubuntu inside a container with a shared `$HOME` and exported applications:

```bash
sudo pacman -S distrobox podman
distrobox create --image docker.io/kalilinux/kali-rolling --name kali
distrobox enter kali
sudo apt update && sudo apt install -y kali-linux-headless
exit

# Run a Kali tool from your Arch shell:
distrobox enter kali -- gobuster dir -u https://target -w /usr/share/wordlists/dirb/common.txt
distrobox enter kali -- distrobox-export --app burpsuite     # appears in your menu
```

This gives you per-target isolation (one Distrobox per program), the entire `apt`-only Kali catalog without breaking your Arch base, and easy disposal: `distrobox rm kali`. A typical lab keeps `kali`, `parrot`, `u24` (Ubuntu 24.04), and `arch-clean` containers around.

For testing internal apps, a Docker bridge network running vulnerable targets is the fastest setup:

```bash
docker network create --driver bridge --subnet 172.30.0.0/16 lab
docker run -d --network lab --name local-lab  example/vulnerable-lab
docker run -d --network lab --name dvwa   vulnerables/web-dvwa
docker run -d --network lab --name webgoat webgoat/goatandwolf
```

Burp can intercept LAN traffic to those container IPs natively.

### 9. Set up nested virtualization for full lab targets

For full-VM targets (Active Directory labs, Vulnhub OVAs, retired HackTheBox boxes), use **QEMU/KVM with libvirt** — it is faster than VirtualBox, integrates with snapshot tooling, and supports nested virt cleanly:

```bash
# Confirm hardware virt is enabled
lscpu | grep -E 'vmx|svm'
# Enable nested
echo 'options kvm_intel nested=1' | sudo tee /etc/modprobe.d/kvm.conf

sudo pacman -S qemu-full virt-manager libvirt edk2-ovmf dnsmasq \
               iptables-nft openbsd-netcat swtpm dmidecode bridge-utils
sudo systemctl enable --now libvirtd.socket
sudo usermod -aG libvirt,kvm $USER
newgrp libvirt
sudo virsh net-autostart default
sudo virsh net-start default
virt-manager
```

For UEFI guests, the OVMF firmwares are at `/usr/share/edk2/x64/`; virt-manager auto-detects them. **VirtualBox and KVM modules cannot be active simultaneously** without juggling — pick one. If you need VirtualBox specifically: `sudo pacman -S virtualbox virtualbox-host-modules-arch virtualbox-guest-iso`.

A canonical snapshot workflow for clean retesting:

```bash
virsh snapshot-create-as --domain target1 clean --description "fresh boot" --atomic
virsh snapshot-list target1
virsh snapshot-revert target1 clean
```

Convention: snapshot **before** firing exploits, revert **after each chain** to confirm reproducibility.

### 10. Productivity layer

For shell, **zsh + starship + zinit** is the standard pairing:

```bash
sudo pacman -S zsh zsh-completions starship fzf zoxide eza bat ripgrep fd \
               git-delta lazygit tmux htop btop ncdu wl-clipboard
chsh -s /usr/bin/zsh
```

Useful `~/.zshrc` essentials and recon aliases:

```zsh
eval "$(starship init zsh)"
eval "$(zoxide init zsh)"
source <(fzf --zsh)
export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

alias bb="cd ~/bb"
alias subs='subfinder -all -silent'
alias alive='httpx -silent -title -tech-detect -status-code'
alias bbnuclei='nuclei -silent -severity medium,high,critical -stats'

recon() {
  local t=$1; mkdir -p ~/bb/$t/$(date +%F) && cd $_
  subfinder -d $t -all -silent | anew subs.txt | httpx -silent | anew alive.txt
}
```

Long-running scans belong in tmux or zellij so you can detach safely:

```bash
sudo pacman -S tmux zellij
tmux new -s recon       # detach: Ctrl-b d ; reattach: tmux a -t recon
```

For notes, a markdown vault with git-backed sync is the strongest pick. Local-first note tools and plain markdown + an editor are reasonable alternatives.

A standardized workspace layout makes diffing reruns trivial:

```
~/bb/
├── _wordlists/                 # symlink to /usr/share/seclists/...
├── _tools/                     # custom scripts, gf-patterns
├── _notes/                     # global methodology
└── <target>/
    ├── README.md               # scope, RoE, creds, contacts
    ├── scope.txt
    ├── 2026-04-26/
    │   ├── subs.txt
    │   ├── alive.txt
    │   ├── nuclei.out
    │   └── burp/<target>.burp
    ├── reports/
    └── loot/
```

Back up findings — not wordlists — with `restic`:

```bash
sudo pacman -S restic rsync
restic -r /mnt/backup/bb init
restic -r /mnt/backup/bb backup ~/bb ~/.config/BurpSuite ~/.config/nuclei
```

### 11. Maintenance and what to avoid

The single most useful Arch habit for hunters is **don't update before a hunt window**. A rolling-release distro can ship a kernel, glibc, or Java bump that breaks Burp or KVM right when you need them. Take a snapper snapshot, work, then update afterwards. `yay -S informant` forces you to read Arch news before upgrading, which catches manual-intervention items.

Routine maintenance condenses to one weekly script:

```bash
#!/usr/bin/env bash
set -e
yay -Syu --noconfirm
sudo paccache -rk2
sudo paccache -ruk0
yay -Yc --noconfirm
sudo journalctl --vacuum-size=500M
nuclei -update-templates
pipx upgrade-all || true
gup -u                    # updates Go-installed binaries
rustup update
echo "[+] bbmaint complete $(date)"
```

The most common breakages and their fixes:

| Symptom                                          | Fix                                                                  |
| ------------------------------------------------ | -------------------------------------------------------------------- |
| `failed to commit transaction (corrupted package)` | `sudo pacman -Sy archlinux-keyring && sudo pacman -Su`             |
| `.pacnew` / `.pacsave` warnings                    | `sudo pacdiff` (from `pacman-contrib`); merge changes              |
| Burp won't start after a Java update              | `sudo archlinux-java set java-21-openjdk`                          |
| `command not found: subfinder`                    | `~/go/bin` not on `PATH`; re-source shell rc                       |
| `httpx` runs the wrong binary                     | Python httpx shadows PD's; rename to `py-httpx`                    |
| KVM "device busy" after VirtualBox                | `sudo rmmod vboxdrv vboxnetadp vboxnetflt; sudo modprobe kvm_intel` |
| BlackArch file conflicts                          | `sudo pacman -Syu --needed --overwrite='*' <pkg>`                  |
| `error: externally-managed-environment`           | Use `pipx install` or a venv; never `--break-system-packages`      |

### 12. Final verification and baseline snapshot

Run this checklist after install. If every line returns sensible output, the workstation is ready:

```bash
uname -r && pacman -Q | wc -l
sudo snapper list
yay -Syu
go version && rustc --version && python --version && pipx --version
for t in subfinder httpx nuclei naabu katana dnsx ffuf feroxbuster amass gau waybackurls; do
  command -v $t && $t -version 2>/dev/null | head -1
done
java -jar /usr/share/burpsuite/burpsuite.jar -v
virsh list --all
docker ps -a
distrobox list
sudo wg show
curl -s ifconfig.me              # should be VPN IP
dig +short whoami.akamai.net     # should resolve via VPN DNS
```

Then take a baseline snapshot you can always return to:

```bash
sudo snapper -c root create --description "bb-baseline"
```

### Setup timeline

| Phase                                                       | Time     |
| ----------------------------------------------------------- | -------- |
| Base Arch install (archinstall, btrfs+luks)                 | 60–90 min |
| Pacman config + reflector + first `-Syu`                    | 10 min   |
| yay + AUR essentials                                        | 10 min   |
| Snapper + grub-btrfs                                        | 15 min   |
| Shell + tmux + dotfiles                                     | 30 min   |
| Go/Rust/Python toolchains + ProjectDiscovery suite          | 30 min   |
| Burp Suite + browsers + FoxyProxy                           | 20 min   |
| Docker + Podman + Distrobox + Kali container                | 20 min   |
| QEMU/KVM + libvirt + first lab VM                           | 30 min   |
| WireGuard + killswitch + DNS leak test                      | 30 min   |
| (Optional) BlackArch overlay + `blackarch-recon` group      | 30 min   |
| Workspace tree, notes vault, backups                        | 15 min   |
| **Total**                                                   | **5–7 hours** |

---

## Closing notes and caveats

Three caveats to flag for the user before action:

1. **The ReconForge README above is a high-quality template, not documentation of the actual repository.** It mirrors the conventions of comparable frameworks (reconftw, Reconx, Reconator) and will fit ~80% of any phased recon project, but the `Repository layout`, `CLI usage`, `Configuration`, and `Output` sections must be reconciled against the real scripts. Once the repo is reachable (verify URL/spelling, make public, or paste the entry script and install script), a faithful README can be produced in one pass.

2. **Treat 2026 vendor announcements (ProjectDiscovery Neo, Anthropic AI-orchestrated attack, AI-credited CVEs) as evidence of direction, not as battle-tested capability.** They are real and significant, but independent benchmarks for autonomous-pentest claims are still scarce. Build your workflow around BBOT, the ProjectDiscovery pipeline, and Nuclei v3 as the proven core; add AI-augmented tools as accelerators, not replacements.

3. **For the Arch tutorial, the BlackArch `strap.sh` SHA1 changes periodically.** Verify it against the live blackarch.org/downloads page at install time rather than hard-coding the value seen here. Equally, never run `pacman -S blackarch` (the meta-group) — upstream warns against it and it can wedge a system. Snapshot before any large group install.

The combination of these three deliverables gives a hunter a documented framework, a current toolkit that beats the legacy stack on speed and stealth, and a reproducible environment to run it in.
