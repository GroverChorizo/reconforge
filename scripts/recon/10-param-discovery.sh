#!/usr/bin/env bash
# Phase 10 — parameter discovery (arjun, paramspider, x8).

PHASE="10-param-discovery"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
ALIVE="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/05-http-probe/alive.txt"

if [ ! -s "$ALIVE" ]; then
    log ERR "no alive hosts; run 05-http-probe.sh first"
    exit 5
fi

# paramspider (passive, uses archives)
# ParamSpider v3 removed --exclude/--output and always writes results/<domain>.txt;
# -s streams the parameterized URLs to stdout, which we capture into OUTDIR.
if command -v paramspider >/dev/null 2>&1; then
    log INFO "paramspider"
    paramspider -d "$TARGET" -s > "$OUTDIR/paramspider.txt" 2>/dev/null || true
fi

# arjun (active, behavioral diff). Throttle aggressively.
if command -v arjun >/dev/null 2>&1; then
    log INFO "arjun (rate-limited, top-5 hosts)"
    head -5 "$ALIVE" > "$OUTDIR/arjun-input.txt"
    arjun -i "$OUTDIR/arjun-input.txt" -t "$THREADS" --rate-limit 5 \
        -oT "$OUTDIR/arjun.txt" 2>/dev/null || true
fi

# x8 — hidden param discovery on first ~5 hosts
if command -v x8 >/dev/null 2>&1; then
    WORDLIST="${WORDLIST:-$WORDLIST_DIR/Discovery/Web-Content/burp-parameter-names.txt}"
    if [ -f "$WORDLIST" ]; then
        log INFO "x8 hidden parameter probe"
        head -5 "$ALIVE" | while read -r host; do
            x8 -u "$host" -w "$WORDLIST" --output-format url 2>/dev/null \
                >> "$OUTDIR/x8.txt" || true
        done
    fi
fi

log INFO "Phase 10 done — see $OUTDIR/{paramspider,arjun,x8}.txt"
