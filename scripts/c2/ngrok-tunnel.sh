#!/usr/bin/env bash
# c2/ngrok-tunnel.sh — expose a local listener via ngrok.
#
# Use cases:
#   - Reaching back to your laptop from inside a CTF VPN without
#     spinning up a public VPS
#   - OOB callback when self-hosting Interactsh isn't worth it
#   - Quick C2 listener for a home-lab box NAT'd behind your router
#
# ngrok is not approved for bug-bounty work (their public URLs are
# routinely blocklisted, and the metadata leak surface is wide). Use
# self-hosted Interactsh + your own VPS for production work.

PHASE="c2-ngrok"
. "$(dirname "$0")/_lib.sh"
require_authorization

if ! command -v ngrok >/dev/null 2>&1; then
    log ERR "ngrok not installed (https://ngrok.com/download)"
    exit 4
fi

PORT="${PORT:-$LISTEN_PORT}"
PROTO="${PROTO:-tcp}"   # tcp | http | tls

D=$(state_dir ngrok)
PIDFILE="$D/ngrok.pid"
URLFILE="$D/url.txt"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    log INFO "ngrok already running (pid $(cat "$PIDFILE"))"
    [ -f "$URLFILE" ] && log INFO "  tunnel URL: $(cat "$URLFILE")"
    exit 0
fi

log INFO "starting ngrok $PROTO tunnel → local:$PORT"
nohup ngrok "$PROTO" --log=stdout "$PORT" > "$D/ngrok.log" 2>&1 &
echo $! > "$PIDFILE"

sleep 4

# Pull the tunnel URL from ngrok's local API
URL=$(curl -s http://127.0.0.1:4040/api/tunnels 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['tunnels'][0]['public_url'])" 2>/dev/null || echo "")
if [ -z "$URL" ]; then
    log ERR "couldn't extract tunnel URL — check $D/ngrok.log"
    exit 6
fi

echo "$URL" > "$URLFILE"
log INFO "tunnel up: $URL"
log INFO "  inspect: http://127.0.0.1:4040"
log INFO "  stop:    kill \$(cat $PIDFILE)"
