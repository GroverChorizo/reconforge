#!/usr/bin/env bash
# vuln/idor.sh — IDOR detection via two-account differential replay.
#
# Inputs:
#   AUTH_A — Cookie or Authorization header for account A (full owner)
#   AUTH_B — same shape, different account (the attacker)
#   ENDPOINTS — file of URLs to test (defaults to gf-idor.txt from recon)
#
# Method: replay each endpoint under both auth contexts; identical 200
# responses are the high-confidence signal. Different-length 200s are
# medium-confidence (partial leak — e.g. paginated lists).

PHASE="idor"
. "$(dirname "$0")/_lib.sh"

require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

if [ -z "${AUTH_A:-}" ] || [ -z "${AUTH_B:-}" ]; then
    log ERR "AUTH_A and AUTH_B required (e.g. AUTH_A='Cookie: session=...' AUTH_B='Cookie: session=...')"
    exit 2
fi

ENDPOINTS="${ENDPOINTS:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/11-pattern-filter/gf-idor.txt}"
if [ ! -s "$ENDPOINTS" ]; then
    log ERR "no endpoint list at $ENDPOINTS — run recon/11-pattern-filter.sh first or set ENDPOINTS"
    exit 5
fi

REPORT="$OUTDIR/idor-findings.csv"
echo "url,status_a,len_a,status_b,len_b,signal,confidence" > "$REPORT"

while read -r url; do
    [ -z "$url" ] && continue
    resp_a=$(curl -s -o /tmp/a.body -w "%{http_code} %{size_download}" \
        -H "$AUTH_A" --max-time 12 "$url" 2>/dev/null || echo "0 0")
    resp_b=$(curl -s -o /tmp/b.body -w "%{http_code} %{size_download}" \
        -H "$AUTH_B" --max-time 12 "$url" 2>/dev/null || echo "0 0")
    read -r sa la <<<"$resp_a"
    read -r sb lb <<<"$resp_b"

    signal="none"; confidence=0
    if [[ "$sa" == 2* ]] && [[ "$sb" == 2* ]]; then
        if [ "$la" = "$lb" ]; then
            signal="identical-200"; confidence=85
            log INFO "HIGH-CONF IDOR: $url (A:${sa}/${la}B == B:${sb}/${lb}B)"
        else
            signal="differential-200"; confidence=55
            log INFO "MID-CONF IDOR:  $url (A:${sa}/${la}B vs B:${sb}/${lb}B)"
        fi
    elif [[ "$sa" == 2* ]] && [[ "$sb" == 3* || "$sb" == 4* ]]; then
        signal="proper-acl"; confidence=0
    fi

    echo "$url,$sa,$la,$sb,$lb,$signal,$confidence" >> "$REPORT"
done < "$ENDPOINTS"

n_high=$(awk -F, '$7 >= 80' "$REPORT" | wc -l)
n_mid=$(awk -F, '$7 >= 50 && $7 < 80' "$REPORT" | wc -l)
log INFO "done — $n_high high-confidence IDOR, $n_mid mid-confidence in $REPORT"
rm -f /tmp/a.body /tmp/b.body
