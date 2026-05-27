#!/usr/bin/env bash
# Phase 16 — CRLF injection probe.

PHASE="16-crlf"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
ALIVE="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/05-http-probe/alive.txt"

if [ ! -s "$ALIVE" ] || ! command -v crlfuzz >/dev/null 2>&1; then
    log ERR "crlfuzz missing or no alive hosts"
    exit 4
fi

log INFO "crlfuzz scan"
crlfuzz -l "$ALIVE" -o "$OUTDIR/crlf.txt" -s 2>/dev/null || true
log INFO "Phase 16 done — $(wc -l < "$OUTDIR/crlf.txt" 2>/dev/null || echo 0) CRLF candidates"
