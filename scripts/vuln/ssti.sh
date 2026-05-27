#!/usr/bin/env bash
# vuln/ssti.sh — Server-Side Template Injection sweep.
#
# Tests common template engine markers and grep for arithmetic in response.

PHASE="ssti"
. "$(dirname "$0")/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

CANDIDATES="${SSTI_LIST:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/11-pattern-filter/gf-ssti.txt}"
if [ ! -s "$CANDIDATES" ]; then
    # Fallback: try every URL with a query string
    URLS=$(resolve_urls_input)
    CANDIDATES="$OUTDIR/candidates.txt"
    grep '=' "$URLS" | sort -u > "$CANDIDATES"
fi

# Engine probes: each probe is (payload, expected_marker)
declare -A PROBES=(
    ['{{7*7}}']='49'
    ['${7*7}']='49'
    ['{{7*"7"}}']='7777777'                # Jinja2
    ['${{<%[%\x27\x22}}%\\<']='error'      # marker-soup — engines often error
    ['#{7*7}']='49'                        # Ruby ERB / smarty
    ['<%= 7*7 %>']='49'                    # ERB
    ['{7*7}']='49'                         # Smarty / Twig
)

REPORT="$OUTDIR/findings.csv"
echo "url,engine_marker,payload,confidence" > "$REPORT"

log INFO "scanning $(wc -l < "$CANDIDATES") SSTI candidates (top 50)"
head -50 "$CANDIDATES" | while read -r u; do
    [ -z "$u" ] && continue
    for payload in "${!PROBES[@]}"; do
        marker="${PROBES[$payload]}"
        # URL-encode the payload roughly
        enc=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
        forged=$(echo "$u" | sed "s|=[^&]*|=$enc|" | head -c 2000)
        resp=$(curl -sS --max-time 8 "$forged" 2>/dev/null | head -c 5000)
        if echo "$resp" | grep -qF "$marker"; then
            log INFO "SSTI HIT ($payload): $forged"
            echo "$forged,$marker,$payload,80" >> "$REPORT"
        fi
    done
done

n=$(awk -F, 'NR>1' "$REPORT" | wc -l)
log INFO "ssti done — $n hits in $REPORT"
