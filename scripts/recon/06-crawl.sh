#!/usr/bin/env bash
# Phase 6 — katana crawl with JS extraction; hakrawler fallback.

PHASE="06-crawl"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
ALIVE="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/05-http-probe/alive.txt"

if [ ! -s "$ALIVE" ]; then
    log ERR "no alive hosts at $ALIVE — run 05-http-probe.sh first"
    exit 5
fi

URLS="$OUTDIR/urls.txt"
JS="$OUTDIR/js.txt"

if command -v katana >/dev/null 2>&1; then
    log INFO "katana depth=3 (JS-aware + xhr)"
    katana -list "$ALIVE" -silent -nc -jc -kf all -fx -xhr \
        -ef woff,css,png,svg,jpg,woff2,jpeg,gif \
        -d 3 -aff -o "$URLS" 2>/dev/null || true
elif command -v hakrawler >/dev/null 2>&1; then
    log WARN "katana unavailable; hakrawler fallback (less depth)"
    : > "$URLS"
    while read -r host; do
        hakrawler -url "$host" -depth 2 -plain 2>/dev/null >> "$URLS" || true
    done < "$ALIVE"
else
    log ERR "neither katana nor hakrawler installed"
    exit 4
fi

# Extract JS file URLs for Phase 7
grep -E '\.js(\?|$)' "$URLS" 2>/dev/null | sort -u > "$JS" || true

log INFO "Phase 6 done — $(wc -l < "$URLS" 2>/dev/null || echo 0) URLs, $(wc -l < "$JS" 2>/dev/null || echo 0) JS files"
