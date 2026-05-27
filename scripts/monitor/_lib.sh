#!/usr/bin/env bash
# scripts/monitor/_lib.sh — shared helpers for the continuous-monitoring
# daemons. Sourced by every script under scripts/monitor/.
#
# Layout:
#   $MONITOR_STATE/<target>/
#     subs.txt           # current rolling deduped subdomain list
#     subs.md5           # md5 of subs.txt (last seen)
#     subs.prev.md5      # previous md5 (for diff)
#     subs.delta.txt     # subdomains present this run but not last
#     templates.md5      # md5 of nuclei templates dir
#     last-scan-iso      # ISO date of last nuclei sweep
#     log                # rolling append-only log
#
# The design follows the XSSRat "checking if new domains exist" pattern:
# cheap md5 compare → only fire expensive scans on diff.

set -o pipefail

: "${MONITOR_STATE:=$HOME/.local/share/reconforge/monitor}"
: "${NUCLEI_TEMPLATES:=$HOME/nuclei-templates}"
: "${RECON_DIR:=$(cd "$(dirname "$0")/../recon" && pwd)}"

log() {
    local level="$1"; shift
    local ts
    ts=$(date '+%Y-%m-%dT%H:%M:%S%z')
    local target_log="$MONITOR_STATE/${TARGET:-_global}/log"
    mkdir -p "$(dirname "$target_log")"
    local line
    line=$(printf '[%s][%-4s] %s' "$ts" "$level" "$*")
    printf '%s\n' "$line" | tee -a "$target_log" >&2
}

require_target() {
    if [ -z "${TARGET:-}" ]; then
        echo "ERR: TARGET required (usage: TARGET=acme.com $0)" >&2
        exit 2
    fi
    STATE_DIR="$MONITOR_STATE/$TARGET"
    mkdir -p "$STATE_DIR"
}

md5_of_file() {
    [ -f "$1" ] || { echo ""; return; }
    md5sum "$1" | awk '{print $1}'
}

md5_of_dir_contents() {
    # Hash of the sorted file listing (cheap, catches add/remove of templates).
    local dir="$1"
    [ -d "$dir" ] || { echo ""; return; }
    find "$dir" -type f -name '*.yaml' 2>/dev/null | sort | md5sum | awk '{print $1}'
}
