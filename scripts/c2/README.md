# `scripts/c2/` — home-lab + authorized-engagement infrastructure

> **Read this first.** These scripts establish listener infrastructure
> (C2 servers, OOB callback receivers, tunnels). They are for the
> **operator's own infrastructure** in support of:
>
> - **Home lab** training (`HOME_LAB=yes`)
> - **CTF** competitions (`CTF=yes CTF_NAME=hackthebox-october`)
> - **Pentest engagements** with written authorization (`PENTEST_AUTH=/path/to/loa.pdf`)
>
> They are **not** for bug-bounty work. Bug-bounty work stops at
> vulnerability confirmation; the report is the deliverable. Every
> script in this folder refuses to run without one of the three
> authorization signals above, and refuses outright if `SCOPE_FILE`
> points at a bug-bounty program that covers the target host.

## Index

| Script | Purpose | Authorization | Notes |
|---|---|---|---|
| `sliver-start.sh`             | Sliver C2 server (Bishop Fox) | required | Modern, actively maintained C2 |
| `msf-handler.sh`              | Metasploit multi-handler      | required | Classic catcher for meterpreter etc. |
| `interactsh-server-deploy.sh` | Self-hosted Interactsh OOB    | required (but bug-bounty exemption — see below) | Replaces oast.pro for hardened targets |
| `ngrok-tunnel.sh`             | Tunnel local listener via ngrok | required | CTF / quick exposure; not for prod |

## Authorization gate

The three signals are enforced by `_lib.sh:require_authorization`:

```bash
HOME_LAB=yes
# OR
CTF=yes CTF_NAME=<name>
# OR
PENTEST_AUTH=/path/to/letter-of-authorization.pdf
```

If none of those is set, every script in this folder exits with code 8
before doing anything.

A second gate (`refuse_if_bug_bounty_target`) refuses if the target host
matches an active `SCOPE_FILE` from a bug-bounty program. The intent is
hard fail-closed: if you accidentally point a C2 listener at a HackerOne
target, the script stops you.

## Special case: `interactsh-server-deploy.sh`

Interactsh is **bug-bounty-relevant** (it's how blind SSRF, OOB XXE, and
DNS-exfil-style probes get confirmed), so this script does require
authorization (you must own the VPS + the wildcard domain), but does
**not** invoke `refuse_if_bug_bounty_target`. The server itself never
plants anything on a target — it just receives callbacks.

Standard flow:
1. Buy a throwaway domain (e.g. `oast.yourdomain.com`).
2. Run this script on your VPS with `OAST_DOMAIN=oast.yourdomain.com`.
3. Set NS records on the domain registrar (the script prints what's needed).
4. In your day-to-day recon, set `OOB_SERVER=oast.yourdomain.com OOB_TOKEN=...`.

## State layout

```
~/.local/share/reconforge/c2/
├── sliver/
│   ├── sliver.pid          # daemon pid
│   ├── sliver.log
│   └── operator.cfg        # connect with `sliver-client import`
├── msf/
│   └── handler.rc          # multi-handler resource script
├── interactsh-server/
│   ├── interactsh-server.pid
│   └── interactsh-server.log
└── ngrok/
    ├── ngrok.pid
    └── url.txt             # current tunnel URL
```

## OPSEC notes

- **Sliver beacons** survive system reboots only if you implant
  persistence — which you should not do on shared hosts.
- **MSF reverse-shells** are the canonical CTF catch — never use a
  staged meterpreter against any host you don't own.
- **ngrok tunnels** leak your laptop's outbound IP in the tunnel
  metadata. Use a VPS for anything beyond CTF.
- **Self-hosted Interactsh** logs every callback. Audit-friendly,
  retention should be configured per your retention policy.

## What's intentionally NOT here

- Beacon implant generators (msfvenom, sliver generate, etc.) —
  those live in the framework, not here. Generate per-engagement.
- Persistence mechanisms (cron, systemd, registry keys).
- Privilege escalation exploits — those live in pentest playbooks per
  target OS, see `docs/HUNTING_PLAYBOOK.md` §Post-foothold.
- Lateral movement tools (impacket, crackmapexec, etc.) — out of
  scope; install separately when an authorized engagement demands them.
