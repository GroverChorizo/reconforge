#!/usr/bin/env bash
# vuln/race.sh — race-condition probe via attack/race.py primitive.
#
# Inputs:
#   TARGET_URL — the gated endpoint (one-time code redeem, referral, etc.)
#   AUTH       — Authorization or Cookie header
#   METHOD     — POST | PUT | PATCH (default POST)
#   BODY       — JSON body or form data (optional)
#   N          — parallel count (default 30)

PHASE="race"
. "$(dirname "$0")/_lib.sh"
require_target
OUTDIR=$(out_dir "$PHASE")

TARGET_URL="${TARGET_URL:-}"
[ -z "$TARGET_URL" ] && { log ERR "TARGET_URL required"; exit 2; }
ensure_scope "$TARGET_URL"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export TARGET_URL
python3 - >"$OUTDIR/result.json" 2>&1 <<PY
import json, os, sys
sys.path.insert(0, "$REPO_ROOT")
from attack import race

headers = {}
auth = os.environ.get("AUTH", "")
if auth:
    k, _, v = auth.partition(":")
    headers[k.strip()] = v.strip()
body_raw = os.environ.get("BODY", "")
body = None
if body_raw:
    try:
        body = json.loads(body_raw)
    except Exception:
        body = body_raw

opts = {
    "method":  os.environ.get("METHOD", "POST"),
    "headers": headers,
    "body":    body,
    "n":       int(os.environ.get("N", "30")),
    "success_status": int(os.environ.get("SUCCESS_STATUS", "200")),
}
result = race.run(os.environ["TARGET_URL"], opts)
print(json.dumps(result.to_dict(), indent=2))
PY

if grep -q '"success": true' "$OUTDIR/result.json" 2>/dev/null; then
    log INFO "RACE WINDOW CONFIRMED — see $OUTDIR/result.json"
else
    log INFO "gate appears atomic — see $OUTDIR/result.json"
fi
