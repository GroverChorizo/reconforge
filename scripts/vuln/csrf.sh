#!/usr/bin/env bash
# vuln/csrf.sh — CSRF surface mapping.
#
# Method: identify state-changing endpoints with weak or no anti-CSRF.
# Cookie SameSite=None + no anti-CSRF token = exploitable.

PHASE="csrf"
. "$(dirname "$0")/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

AUTH="${AUTH:-}"
if [ -z "$AUTH" ]; then
    log WARN "no AUTH set — CSRF detection works best authenticated"
fi

ENDPOINTS="${ENDPOINTS:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/06-crawl/urls.txt}"
[ ! -s "$ENDPOINTS" ] && { log ERR "no endpoint list"; exit 5; }

REPORT="$OUTDIR/csrf-surface.csv"
echo "url,method,has_csrf_token_in_response,samesite,referrer_required,confidence" > "$REPORT"

# Look for state-changing endpoints (POST/PUT/PATCH/DELETE that the
# crawl found, plus form actions).
CANDIDATES=$(grep -iE 'POST|PUT|PATCH|DELETE|/api/|/admin/|update|create|delete|save' "$ENDPOINTS" | head -100)

while IFS= read -r u; do
    [ -z "$u" ] && continue
    headers=$(curl -sI --max-time 8 -H "${AUTH:-X-Dummy: 1}" "$u" 2>/dev/null | tr -d '\r')
    body=$(curl -sS --max-time 8 -H "${AUTH:-X-Dummy: 1}" "$u" 2>/dev/null | head -c 5000)

    # Token presence (form inputs, meta tags, custom headers in response)
    has_token="no"
    echo "$body" | grep -qiE '(csrf|xsrf|authenticity_token|_token).{1,5}=' && has_token="yes"
    echo "$headers" | grep -qiE 'x-csrf-token|x-xsrf-token' && has_token="yes"

    samesite=$(echo "$headers" | awk -F'samesite=' 'tolower($0) ~ /set-cookie/ {print $2}' | awk '{print $1}' | tr -d ';"' | head -1)
    [ -z "$samesite" ] && samesite="missing"

    # Does the server reject without a Referer? (some apps gate purely on Origin)
    no_ref=$(curl -sI --max-time 6 -H "${AUTH:-X-Dummy: 1}" -H 'Referer:' "$u" 2>/dev/null | head -1 | awk '{print $2}')
    if [ "$no_ref" = "200" ] || [ "$no_ref" = "302" ]; then
        ref_required="no"
    else
        ref_required="maybe"
    fi

    confidence=0
    if [ "$has_token" = "no" ] && [ "$samesite" != "Strict" ] && [ "$samesite" != "Lax" ]; then
        confidence=70
    elif [ "$has_token" = "no" ]; then
        confidence=40
    fi
    echo "$u,?,$has_token,$samesite,$ref_required,$confidence" >> "$REPORT"
done <<< "$CANDIDATES"

n=$(awk -F, 'NR>1 && $6 >= 50' "$REPORT" | wc -l)
log INFO "csrf done — $n high-confidence CSRF surface entries in $REPORT"
