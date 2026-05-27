#!/usr/bin/env bash
# Phase 2 — DNS resolution + wildcard filter + permutation.
#
# Inputs:  $TARGET, $SUBS (default = $OUTDIR-of-phase-1/subs.txt)
# Outputs: resolved.txt (validated subs with at least one A/CNAME)

PHASE="02-resolve"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
SUBS="${SUBS:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/01-passive-enum/subs.txt}"
RESOLVED="$OUTDIR/resolved.txt"

if [ ! -s "$SUBS" ]; then
    log ERR "no subs at $SUBS — run 01-passive-enum.sh first"
    exit 5
fi

# puredns wildcard-filter + bulk resolve (preferred)
if command -v puredns >/dev/null 2>&1 && [ -f "$RESOLVERS_FILE" ]; then
    log INFO "puredns resolve (rate=1000)"
    puredns resolve "$SUBS" -r "$RESOLVERS_FILE" --rate-limit 1000 -w "$RESOLVED" 2>/dev/null || true
elif command -v dnsx >/dev/null 2>&1; then
    log INFO "dnsx fallback (puredns unavailable)"
    dnsx -l "$SUBS" -a -resp -rl 100 -o "$RESOLVED" 2>/dev/null || true
else
    log ERR "neither puredns nor dnsx installed"
    exit 4
fi

# Optional permutation pass
if command -v alterx >/dev/null 2>&1; then
    log INFO "alterx permutations"
    alterx -enrich -l "$SUBS" -o "$OUTDIR/perms.txt" 2>/dev/null || true
    if [ -s "$OUTDIR/perms.txt" ] && command -v puredns >/dev/null 2>&1; then
        puredns resolve "$OUTDIR/perms.txt" -r "$RESOLVERS_FILE" --rate-limit 1000 \
            -w "$OUTDIR/perms-resolved.txt" 2>/dev/null || true
        cat "$OUTDIR/perms-resolved.txt" | anew_or_tee "$RESOLVED" >/dev/null
    fi
fi

log INFO "Phase 2 done — $(wc -l < "$RESOLVED" 2>/dev/null || echo 0) resolved hosts in $RESOLVED"
