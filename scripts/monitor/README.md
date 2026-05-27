# `scripts/monitor/` — continuous bug-bounty monitoring

Cron-driven daemons that turn ReconForge from "scan-and-sleep" into
"alert-and-triage". Two independent loops:

1. **`continuous-enum.sh`** — re-runs passive subdomain enumeration on a
   schedule. On md5-diff against the previous run, emits the delta and
   (by default) fires nuclei against only the new hosts.
2. **`template-watcher.sh`** — when ProjectDiscovery ships new nuclei
   templates, re-scans the tracked subdomain list against just those
   new templates. Catches CVE drops within minutes.

Both write structured state under `$MONITOR_STATE/<target>/` so the
daemons are crash-safe and resumable.

## Install for a target

```bash
./install-cron.sh acme.com
```

That writes two crontab entries (hourly enum, 6-hourly template watch).
Logs append to `~/.local/share/reconforge/monitor/<target>/log`.

Uninstall:

```bash
./install-cron.sh --uninstall acme.com
```

## State layout

```
$MONITOR_STATE/<target>/
├── subs.txt             # rolling deduped subdomain master list
├── subs.md5             # md5 of subs.txt this run
├── subs.prev.md5        # md5 of the previous run
├── subs.delta.txt       # subs present this run but not last (the "new" set)
├── templates.md5        # md5 of nuclei templates dir at last check
├── last-scan-iso        # ISO timestamp of last template-watcher pass
├── delta-nuclei-<ts>.jsonl   # nuclei output keyed by epoch
└── log                  # rolling append-only diagnostic log
```

## Knobs

| Variable | Default | Purpose |
|---|---|---|
| `TARGET` | (required) | Root domain to watch |
| `MONITOR_STATE` | `~/.local/share/reconforge/monitor` | State root |
| `NUCLEI_TEMPLATES` | `~/nuclei-templates` | Where the template-watcher hashes |
| `FIRE_NUCLEI` | `1` | Set to `0` to detect-only, no scan |
| `RATE_LIMIT_RPS` | `50` | nuclei `-rl` |
| `NOTIFY_ID` | `monitor-<target>` | provider-config.yaml entry to push to |

## Alert wiring

If `notify` is installed and `~/.config/notify/provider-config.yaml`
has Slack/Discord/Telegram configured, both daemons push:

- new-subdomain announcements (with up to 20 examples)
- nuclei hits keyed by severity + URL

## Multi-target rotation

`install-cron.sh` accepts multiple targets — entries are tagged so
the script can later `--uninstall` cleanly:

```bash
./install-cron.sh acme.com bcde.com fgh.example
```

That stagger-runs all three; nuclei contention is handled by the
per-tool ToolGate in main.py when invoked through ReconForge's
dispatcher (cron path runs the binaries directly, so just space your
targets out across the schedule).

## XSSRat methodology lineage

The md5-diff design comes from
[`docs/HUNTING_PLAYBOOK.md`](../../docs/HUNTING_PLAYBOOK.md) §"Continuous
monitoring" — paraphrased from the XSSRat pentesting-course chapter
*B. Vulnerability testing strategy*. The principle: expensive scans
fire only on actual change.
