#!/usr/bin/env bash
# Phase 11 — gf pattern-filter URLs into vuln-class candidate buckets.

PHASE="11-pattern-filter"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
URLS="${URLS:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/09-archive-urls/archive-urls.txt}"

if [ ! -s "$URLS" ]; then
    log ERR "no URL corpus; run 09-archive-urls.sh first"
    exit 5
fi
if ! command -v gf >/dev/null 2>&1; then
    log ERR "gf not installed"
    exit 4
fi

for pattern in xss sqli ssrf idor lfi ssti redirect rce; do
    out="$OUTDIR/gf-$pattern.txt"
    cat "$URLS" | gf "$pattern" 2>/dev/null | sort -u > "$out" || true
    log INFO "gf $pattern → $(wc -l < "$out" 2>/dev/null || echo 0) candidates"
done

log INFO "Phase 11 done — per-pattern buckets under $OUTDIR/"
