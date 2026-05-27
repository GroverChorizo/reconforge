#!/usr/bin/env bash
# scripts/monitor/continuous-enum.sh — re-run passive enumeration and
# detect new subdomains via md5-diff against the last run.
#
# Designed for cron:
#   * */1 * * * TARGET=acme.com /path/to/scripts/monitor/continuous-enum.sh
#
# On diff detection, the new subdomains are written to subs.delta.txt
# and (if FIRE_NUCLEI=1) a nuclei pass is queued on just those hosts.

. "$(dirname "$0")/_lib.sh"
require_target

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

NEW_SUBS="$WORKDIR/fresh.txt"
: > "$NEW_SUBS"

# Run the same passive enumerators the recon/01 script uses, but in this
# context we only care about diff-able output.
if command -v subfinder >/dev/null 2>&1; then
    subfinder -d "$TARGET" -all -silent 2>/dev/null >> "$NEW_SUBS" || true
fi
if command -v assetfinder >/dev/null 2>&1; then
    assetfinder --subs-only "$TARGET" 2>/dev/null >> "$NEW_SUBS" || true
fi
if command -v amass >/dev/null 2>&1; then
    amass enum -passive -norecursive -d "$TARGET" 2>/dev/null >> "$NEW_SUBS" || true
fi
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' >> "$NEW_SUBS" || true
fi

sort -u -o "$NEW_SUBS" "$NEW_SUBS"
new_count=$(wc -l < "$NEW_SUBS")
log INFO "enum harvested $new_count unique subdomains"

# Diff vs current state
SUBS="$STATE_DIR/subs.txt"
if [ ! -f "$SUBS" ]; then
    cp "$NEW_SUBS" "$SUBS"
    log INFO "first run — seeding subs.txt with $new_count entries"
    exit 0
fi

# What's new this time?
DELTA="$STATE_DIR/subs.delta.txt"
comm -23 "$NEW_SUBS" "$SUBS" > "$DELTA"
delta_count=$(wc -l < "$DELTA")

# Refresh the rolling master list with the union
sort -u "$SUBS" "$NEW_SUBS" -o "$SUBS"

# Bump the md5 cycle
[ -f "$STATE_DIR/subs.md5" ] && cp "$STATE_DIR/subs.md5" "$STATE_DIR/subs.prev.md5"
md5_of_file "$SUBS" > "$STATE_DIR/subs.md5"

log INFO "delta: +$delta_count new subdomains (total now $(wc -l < "$SUBS"))"

if [ "$delta_count" -eq 0 ]; then
    exit 0
fi

# Notify on new subdomains
if command -v notify >/dev/null 2>&1; then
    {
        echo "[$TARGET] $delta_count new subdomain(s)"
        head -20 "$DELTA"
        [ "$delta_count" -gt 20 ] && echo "...and $((delta_count - 20)) more"
    } | notify -bulk -id "${NOTIFY_ID:-monitor-$TARGET}" 2>/dev/null || true
fi

# Optionally fire nuclei on just the new hosts
if [ "${FIRE_NUCLEI:-1}" = "1" ] && command -v nuclei >/dev/null 2>&1 && command -v httpx >/dev/null 2>&1; then
    log INFO "firing nuclei on $delta_count fresh hosts"
    ALIVE=$(mktemp)
    httpx -l "$DELTA" -silent -follow-redirects -o "$ALIVE" 2>/dev/null || true
    if [ -s "$ALIVE" ]; then
        nuclei -l "$ALIVE" \
            -severity medium,high,critical \
            -es info,unknown \
            -rl "${RATE_LIMIT_RPS:-50}" -c 5 \
            -jsonl -o "$STATE_DIR/delta-nuclei-$(date +%s).jsonl" \
            2>/dev/null \
            | tee -a "$STATE_DIR/log" \
            | notify -id "${NOTIFY_ID:-monitor-$TARGET}" 2>/dev/null || true
    fi
    rm -f "$ALIVE"
fi
