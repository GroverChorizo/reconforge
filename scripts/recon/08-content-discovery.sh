#!/usr/bin/env bash
# Phase 8 — content discovery (ffuf preferred, feroxbuster + gobuster fallback).
# Heavy traffic — gated on program rate-limit and operator opt-in.

PHASE="08-content-discovery"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
ALIVE="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/05-http-probe/alive.txt"
WORDLIST="${WORDLIST:-$WORDLIST_DIR/Discovery/Web-Content/raft-medium-directories.txt}"

if [ ! -s "$ALIVE" ]; then
    log ERR "no alive hosts at $ALIVE — run 05-http-probe.sh first"
    exit 5
fi
if [ ! -f "$WORDLIST" ]; then
    log ERR "wordlist not found at $WORDLIST (set WORDLIST or WORDLIST_DIR)"
    exit 5
fi

log WARN "Phase 8 is mod_active — burns request budget. Confirm rate limit honors program policy."

while read -r host; do
    [ -z "$host" ] && continue
    safe=$(echo "$host" | sed 's|https\?://||; s|/|_|g')
    out="$OUTDIR/$safe.txt"
    if command -v ffuf >/dev/null 2>&1; then
        log INFO "ffuf: $host"
        ffuf -w "$WORDLIST" -u "$host/FUZZ" -fc 404,301 -ac \
             -rate "$RATE_LIMIT_RPS" -t "$THREADS" -s -o "$out.json" -of json 2>/dev/null || true
        jq -r '.results[]?.url' "$out.json" 2>/dev/null | sort -u > "$out" || true
    elif command -v feroxbuster >/dev/null 2>&1; then
        log INFO "feroxbuster (ffuf unavailable): $host"
        feroxbuster -u "$host" -w "$WORDLIST" -s 200,301,302,401,403 \
                    --silent --no-state -o "$out" 2>/dev/null || true
    elif command -v gobuster >/dev/null 2>&1; then
        log INFO "gobuster (ffuf+ferox unavailable): $host"
        gobuster dir -u "$host" -w "$WORDLIST" -t "$THREADS" -o "$out" --no-error 2>/dev/null || true
    fi
done < "$ALIVE"

log INFO "Phase 8 done — per-host results under $OUTDIR/"
