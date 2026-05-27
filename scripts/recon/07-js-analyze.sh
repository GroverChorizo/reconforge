#!/usr/bin/env bash
# Phase 7 — jsluice URL + secret extraction; mantra + trufflehog corroborate.

PHASE="07-js-analyze"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
JS="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/06-crawl/js.txt"

if [ ! -s "$JS" ]; then
    log ERR "no JS file list at $JS — run 06-crawl.sh first"
    exit 5
fi

# Download JS bodies once so subsequent tools don't re-fetch.
JS_DIR="$OUTDIR/js-bodies"
mkdir -p "$JS_DIR"
log INFO "fetching $(wc -l < "$JS") JS files"
while read -r url; do
    [ -z "$url" ] && continue
    local_name=$(echo "$url" | sha256sum | cut -c1-16).js
    curl -sS --max-time 15 -o "$JS_DIR/$local_name" "$url" 2>/dev/null || true
done < "$JS"

JS_URLS="$OUTDIR/js-extracted-urls.txt"
JS_SECRETS="$OUTDIR/js-secrets.jsonl"
: > "$JS_URLS"
: > "$JS_SECRETS"

if command -v jsluice >/dev/null 2>&1; then
    log INFO "jsluice URL + secret extraction"
    for f in "$JS_DIR"/*.js; do
        [ -f "$f" ] || continue
        jsluice urls "$f" 2>/dev/null >> "$JS_URLS" || true
        jsluice secrets "$f" 2>/dev/null >> "$JS_SECRETS" || true
    done
    sort -u -o "$JS_URLS" "$JS_URLS"
fi

if command -v trufflehog >/dev/null 2>&1; then
    log INFO "trufflehog filesystem scan on JS bodies"
    trufflehog filesystem "$JS_DIR" --json --no-update --only-verified \
        > "$OUTDIR/trufflehog.jsonl" 2>/dev/null || true
fi

# mantra runs against live URLs (it fetches its own content)
if command -v mantra >/dev/null 2>&1; then
    log INFO "mantra live JS scan (10 URLs max for default speed)"
    head -10 "$JS" | while read -r url; do
        mantra -ua ReconForge -p "$url" 2>/dev/null >> "$OUTDIR/mantra.txt" || true
    done
fi

log INFO "Phase 7 done — $(wc -l < "$JS_URLS" 2>/dev/null || echo 0) extracted URLs, $(wc -l < "$JS_SECRETS" 2>/dev/null || echo 0) secret candidates"
