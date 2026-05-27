#!/usr/bin/env bash
# Phase 14 — nuclei sweep.
#
# Tech-detect first, then template-spray with severity gating. Skip
# template categories irrelevant to the detected stack (avoids WAF lockouts).

PHASE="14-vuln-scan"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
ALIVE="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/05-http-probe/alive.txt"
HTTPX_JSONL="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/05-http-probe/httpx.jsonl"
URLS="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/06-crawl/urls.txt"

if [ ! -s "$ALIVE" ] || ! command -v nuclei >/dev/null 2>&1; then
    log ERR "nuclei missing or no alive hosts; run Phases 5-6 first"
    exit 4
fi

# Build tech-targeted input from httpx fingerprinting (avoid blind spraying)
TECHY="$OUTDIR/techy.txt"
if [ -s "$HTTPX_JSONL" ] && command -v jq >/dev/null 2>&1; then
    log INFO "extracting hosts with fingerprinted tech"
    jq -r 'select(.tech) | .url' "$HTTPX_JSONL" 2>/dev/null | sort -u > "$TECHY" || true
fi

INPUT="$ALIVE"
[ -s "$TECHY" ] && INPUT="$TECHY"

# Severity-tiered scan (medium+ for the main sweep; KEV for high-priority)
log INFO "nuclei main sweep (severity >= medium, rate=$RATE_LIMIT_RPS, c=5)"
nuclei -l "$INPUT" \
    -es info,unknown -ept ssl \
    -ss template-spray \
    -severity medium,high,critical \
    -rl "$RATE_LIMIT_RPS" -c 5 \
    -markdown-export "$OUTDIR/reports/" \
    -include-rr -jsonl -o "$OUTDIR/nuclei.jsonl" \
    2>/dev/null || true

log INFO "nuclei KEV pass (known-exploited)"
nuclei -l "$INPUT" -tags kev,vkev -rl "$RATE_LIMIT_RPS" -c 5 \
    -jsonl -o "$OUTDIR/kev.jsonl" 2>/dev/null || true

# Scan crawled URLs separately (per-URL hits, e.g. takeover/exposure templates)
if [ -s "$URLS" ]; then
    log INFO "nuclei URL pass (exposure + takeover tags)"
    nuclei -l "$URLS" -tags exposure,takeover,cve \
        -rl "$RATE_LIMIT_RPS" -c 5 \
        -jsonl -o "$OUTDIR/urls.jsonl" 2>/dev/null || true
fi

count=$(cat "$OUTDIR"/*.jsonl 2>/dev/null | wc -l)
log INFO "Phase 14 done — $count nuclei findings total; markdown reports under $OUTDIR/reports/"
