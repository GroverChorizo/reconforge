#!/usr/bin/env bash
# Phase 4 — port scan. naabu preferred; masscan for huge surfaces (gated).
#
# Inputs:  RESOLVED or NON_CDN (preferred)
# Outputs: ports.txt — host:port lines

PHASE="04-port-scan"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
NON_CDN="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/03-tls-cdn/non-cdn.txt"
RESOLVED="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/02-resolve/resolved.txt"

# Prefer the CDN-filtered list to avoid burning shared infra.
INPUT="$NON_CDN"
[ ! -s "$INPUT" ] && INPUT="$RESOLVED"

if [ ! -s "$INPUT" ]; then
    log ERR "no input host list — run 02-resolve.sh and 03-tls-cdn.sh first"
    exit 5
fi

PORTS="$OUTDIR/ports.txt"

# naabu (top-1000, rate-limited)
if command -v naabu >/dev/null 2>&1; then
    log INFO "naabu top-1000 (rate=$RATE_LIMIT_RPS pps)"
    naabu -l "$INPUT" -tp 1000 -rate "$RATE_LIMIT_RPS" -silent -o "$PORTS" 2>/dev/null || true
else
    log WARN "naabu not installed; falling back to nmap fast scan"
    if command -v nmap >/dev/null 2>&1; then
        nmap -iL "$INPUT" -F --open -oG - 2>/dev/null \
            | awk '/Ports:/{split($0,a,"Host: "); split(a[2],b," "); host=b[1]; \
                   for(i=1;i<=NF;i++) if($i~/\/open/){split($i,p,"/"); print host":"p[1]}}' \
            > "$PORTS"
    fi
fi

log INFO "Phase 4 done — $(wc -l < "$PORTS" 2>/dev/null || echo 0) open ports in $PORTS"
