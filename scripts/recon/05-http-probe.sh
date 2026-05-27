#!/usr/bin/env bash
# Phase 5 — httpx probe + fingerprint.

PHASE="05-http-probe"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
PORTS="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/04-port-scan/ports.txt"
RESOLVED="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/02-resolve/resolved.txt"
INPUT="$PORTS"
[ ! -s "$INPUT" ] && INPUT="$RESOLVED"

if [ ! -s "$INPUT" ] || ! command -v httpx >/dev/null 2>&1; then
    log ERR "httpx missing or no input host list"
    exit 4
fi

ALIVE="$OUTDIR/alive.txt"
JSONL="$OUTDIR/httpx.jsonl"

log INFO "httpx enrichment (threads=$THREADS rl=$RATE_LIMIT_RPS)"
httpx -l "$INPUT" -silent -title -tech-detect -status-code -follow-redirects \
    -ip -cname -cdn -jarm -hash sha256 -websocket \
    -threads "$THREADS" -rl "$RATE_LIMIT_RPS" -timeout 10 -fep \
    -j -o "$JSONL" 2>/dev/null \
    | tee "$ALIVE" > /dev/null || true

# Plain alive.txt for the simple-list consumers downstream
if [ -s "$JSONL" ]; then
    jq -r 'select(.url) | .url' "$JSONL" 2>/dev/null | sort -u > "$ALIVE" || true
fi

log INFO "Phase 5 done — $(wc -l < "$ALIVE" 2>/dev/null || echo 0) live HTTP hosts"
