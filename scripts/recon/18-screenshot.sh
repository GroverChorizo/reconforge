#!/usr/bin/env bash
# Phase 18 — gowitness screenshots (v3 syntax).

PHASE="18-screenshot"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
ALIVE="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/05-http-probe/alive.txt"

if [ ! -s "$ALIVE" ] || ! command -v gowitness >/dev/null 2>&1; then
    log ERR "gowitness missing or no alive hosts"
    exit 4
fi

# gowitness v3 — `scan file` writes to a SQLite DB under PWD by default.
# Anchor the DB to OUTDIR so artifacts cluster with the rest of the run.
cd "$OUTDIR" || exit 5
log INFO "gowitness scan file -f $ALIVE --write-db -t $THREADS"
gowitness scan file -f "$ALIVE" --write-db -t "$THREADS" 2>/dev/null || true

log INFO "Phase 18 done — view with: gowitness report server -A (then http://localhost:7171)"
log INFO "Phase 18 artifacts in: $OUTDIR/"
