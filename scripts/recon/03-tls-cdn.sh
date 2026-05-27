#!/usr/bin/env bash
# Phase 3 — TLS / CDN / network surface.
#
# Inputs:  RESOLVED (Phase 2 output)
# Outputs: tls.txt (SAN/CN additions), cdn.txt (provider tags), non-cdn.txt

PHASE="03-tls-cdn"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
RESOLVED="${RESOLVED:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/02-resolve/resolved.txt}"

if [ ! -s "$RESOLVED" ]; then
    log ERR "no resolved hosts at $RESOLVED — run 02-resolve.sh first"
    exit 5
fi

# tlsx: harvest SANs/CNs as additional subdomain candidates
if command -v tlsx >/dev/null 2>&1; then
    log INFO "tlsx SAN/CN harvest"
    tlsx -l "$RESOLVED" -san -cn -silent -resp-only -o "$OUTDIR/tls.txt" 2>/dev/null || true
    log INFO "tlsx → $(wc -l < "$OUTDIR/tls.txt" 2>/dev/null || echo 0) new SAN/CN names"
fi

# cdncheck: tag CDN-fronted IPs so downstream port scans skip them
if command -v cdncheck >/dev/null 2>&1; then
    log INFO "cdncheck classification"
    # Extract IPs from resolved.txt (format: "sub [ip]" or just hosts)
    awk -F'[][]' '/\[/{print $2}' "$RESOLVED" 2>/dev/null > "$OUTDIR/ips.txt" || true
    if [ -s "$OUTDIR/ips.txt" ]; then
        cdncheck -resp -fcdn cloudflare,fastly,akamai,cloudfront,google,leaseweb \
            -i "$OUTDIR/ips.txt" -o "$OUTDIR/non-cdn.txt" 2>/dev/null || true
        cdncheck -i "$OUTDIR/ips.txt" -resp -mcdn cloudflare,fastly,akamai \
            -mcloud aws,google -mwaf cloudflare,akamai,incapsula -jsonl \
            > "$OUTDIR/cdn.jsonl" 2>/dev/null || true
    fi
fi

log INFO "Phase 3 done — see $OUTDIR/{tls,cdn,non-cdn}.*"
