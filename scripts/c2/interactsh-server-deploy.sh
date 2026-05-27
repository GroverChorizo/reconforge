#!/usr/bin/env bash
# c2/interactsh-server-deploy.sh — self-host Interactsh for OOB callbacks.
#
# Mature bug-bounty programs increasingly blocklist oast.pro / oast.me
# / oast.live (the public Interactsh servers). Self-hosting on your own
# VPS / domain bypasses the blocklist and gives you full control of the
# callback corpus.
#
# This script is C2-adjacent (server-side infra you control) but is
# fundamentally a bug-bounty enabler — Interactsh itself never plants
# anything on a target.

PHASE="c2-interactsh-server"
. "$(dirname "$0")/_lib.sh"

# Special-case: this is the ONE script in c2/ that's bug-bounty-relevant.
# It still requires authorization (you must own the VPS + domain) but
# does not refuse on bug-bounty SCOPE_FILE.
require_authorization

if ! command -v interactsh-server >/dev/null 2>&1; then
    log ERR "interactsh-server not installed."
    log ERR "  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest"
    exit 4
fi

DOMAIN="${OAST_DOMAIN:-}"
[ -z "$DOMAIN" ] && {
    log ERR "OAST_DOMAIN required (the wildcard DNS domain you own)"
    log ERR "  example: OAST_DOMAIN=oast.yourdomain.com"
    exit 2
}

TOKEN="${OAST_TOKEN:-$(openssl rand -hex 16)}"
D=$(state_dir interactsh-server)
PIDFILE="$D/interactsh-server.pid"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    log INFO "interactsh-server already running (pid $(cat "$PIDFILE"))"
    exit 0
fi

log INFO "starting interactsh-server"
log INFO "  domain: $DOMAIN"
log INFO "  token:  $TOKEN   ← save this, client needs it"

# Run with HTTP+DNS+SMTP listeners. Add -tls if you have a cert/key.
nohup interactsh-server \
    -domain "$DOMAIN" \
    -token "$TOKEN" \
    > "$D/interactsh-server.log" 2>&1 &
echo $! > "$PIDFILE"

sleep 3

if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    log ERR "interactsh-server failed to start — see $D/interactsh-server.log"
    exit 6
fi

# Save the client config so bug-bounty recon scripts can pick it up
mkdir -p ~/.config/reconforge
cat >> ~/.config/reconforge/settings.json.fragment <<EOF
{
  "oob_server": "$DOMAIN",
  "oob_token":  "$TOKEN"
}
EOF

log INFO ""
log INFO "self-hosted Interactsh is up:"
log INFO "  client cmd: interactsh-client -server $DOMAIN -token $TOKEN"
log INFO "  set in env: OOB_SERVER=$DOMAIN OOB_TOKEN=$TOKEN"
log INFO "  ReconForge: settings.json fragment saved to ~/.config/reconforge/settings.json.fragment"
log INFO ""
log INFO "DNS prerequisites (set ONCE, on the domain registrar):"
log INFO "  NS  $DOMAIN  → ns1.$DOMAIN ns2.$DOMAIN"
log INFO "  A   ns1.$DOMAIN  → <this VPS IP>"
log INFO "  A   ns2.$DOMAIN  → <this VPS IP>"
log INFO ""
log INFO "stop with: kill \$(cat $PIDFILE)"
