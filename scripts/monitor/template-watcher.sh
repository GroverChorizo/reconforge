#!/usr/bin/env bash
# scripts/monitor/template-watcher.sh — detect new nuclei templates and
# re-scan existing subdomains against ONLY the new templates.
#
# XSSRat methodology: if a fresh template lands while your subdomain list
# is steady, you still want to know if any of your tracked hosts match it.
# This is the "check if new templates exist" half of the cron pattern.

. "$(dirname "$0")/_lib.sh"
require_target

if ! command -v nuclei >/dev/null 2>&1; then
    log ERR "nuclei not installed"
    exit 4
fi

# Refresh templates first (silent — no log spam on no-op)
nuclei -update-templates -silent 2>/dev/null || true

NEW_MD5=$(md5_of_dir_contents "$NUCLEI_TEMPLATES")
OLD_MD5=$(cat "$STATE_DIR/templates.md5" 2>/dev/null || echo "")

if [ -z "$NEW_MD5" ]; then
    log WARN "nuclei templates dir not found at $NUCLEI_TEMPLATES"
    exit 5
fi
if [ "$NEW_MD5" = "$OLD_MD5" ]; then
    log INFO "no new templates"
    exit 0
fi

# Find which templates changed since last scan (mtime-based)
LAST_SCAN_TS=$(cat "$STATE_DIR/last-scan-iso" 2>/dev/null || echo "1970-01-01")
NEW_TEMPLATES=$(mktemp)
find "$NUCLEI_TEMPLATES" -name '*.yaml' -newermt "$LAST_SCAN_TS" 2>/dev/null > "$NEW_TEMPLATES"
n=$(wc -l < "$NEW_TEMPLATES")

log INFO "$n new templates since $LAST_SCAN_TS"

if [ "$n" -eq 0 ]; then
    echo "$NEW_MD5" > "$STATE_DIR/templates.md5"
    exit 0
fi

# Scan our tracked subdomains against ONLY the new templates
SUBS="$STATE_DIR/subs.txt"
if [ ! -s "$SUBS" ]; then
    log WARN "no tracked subdomains yet — run continuous-enum.sh first"
    rm -f "$NEW_TEMPLATES"
    exit 0
fi

ALIVE=$(mktemp)
if command -v httpx >/dev/null 2>&1; then
    httpx -l "$SUBS" -silent -follow-redirects -o "$ALIVE" 2>/dev/null || true
else
    cp "$SUBS" "$ALIVE"
fi

if [ -s "$ALIVE" ]; then
    OUT="$STATE_DIR/template-pass-$(date +%s).jsonl"
    log INFO "scanning $(wc -l < "$ALIVE") hosts against $n new templates"
    nuclei -l "$ALIVE" \
        -t "$NEW_TEMPLATES" \
        -severity medium,high,critical \
        -rl "${RATE_LIMIT_RPS:-50}" -c 5 \
        -jsonl -o "$OUT" \
        2>/dev/null || true
    hits=$(wc -l < "$OUT" 2>/dev/null || echo 0)
    log INFO "template-watcher found $hits hits"
    if [ "$hits" -gt 0 ] && command -v notify >/dev/null 2>&1; then
        jq -r '"[" + .info.severity + "] " + .info.name + " — " + .matched_at' "$OUT" 2>/dev/null \
            | notify -bulk -id "${NOTIFY_ID:-monitor-$TARGET}" 2>/dev/null || true
    fi
fi

# Update state
echo "$NEW_MD5" > "$STATE_DIR/templates.md5"
date -u '+%Y-%m-%dT%H:%M:%S%z' > "$STATE_DIR/last-scan-iso"
rm -f "$NEW_TEMPLATES" "$ALIVE"
