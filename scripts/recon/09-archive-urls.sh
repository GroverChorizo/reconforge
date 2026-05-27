#!/usr/bin/env bash
# Phase 9 — pull URL history from archive sources (gau, waybackurls).

PHASE="09-archive-urls"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
ARCHIVE_URLS="$OUTDIR/archive-urls.txt"
: > "$ARCHIVE_URLS"

if command -v gau >/dev/null 2>&1; then
    log INFO "gau --subs"
    echo "$TARGET" | gau --subs --threads "$THREADS" 2>/dev/null | anew_or_tee "$ARCHIVE_URLS" >/dev/null
fi

if command -v waybackurls >/dev/null 2>&1; then
    log INFO "waybackurls"
    echo "$TARGET" | waybackurls 2>/dev/null | anew_or_tee "$ARCHIVE_URLS" >/dev/null
fi

# Extract param-name wordlist + sensitive-file matches
if command -v unfurl >/dev/null 2>&1; then
    cat "$ARCHIVE_URLS" | unfurl -u keys 2>/dev/null | sort -u > "$OUTDIR/params.txt"
fi
grep -E "\.(xls|xlsx|json|pdf|sql|doc|docx|pptx|env|log|bak|7z|zip|tar\.gz|secret|db|config)(\?|$)" \
    "$ARCHIVE_URLS" > "$OUTDIR/interesting-files.txt" 2>/dev/null || true

log INFO "Phase 9 done — $(wc -l < "$ARCHIVE_URLS") archive URLs, $(wc -l < "$OUTDIR/params.txt" 2>/dev/null || echo 0) params, $(wc -l < "$OUTDIR/interesting-files.txt" 2>/dev/null || echo 0) interesting files"
