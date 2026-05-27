#!/usr/bin/env bash
# c2/sliver-start.sh — start a Sliver C2 server in daemon mode.
#
# Bishop Fox Sliver — open-source, modern C2 framework. Default Phase-Aleph
# choice for authorized engagements because it's actively maintained and
# its operator UX is the cleanest of the open-source options.

PHASE="c2-sliver"
. "$(dirname "$0")/_lib.sh"
require_authorization

if ! command -v sliver-server >/dev/null 2>&1; then
    log ERR "sliver-server not installed."
    log ERR "  curl https://sliver.sh/install | sudo bash    (Linux)"
    log ERR "  brew install sliver                            (macOS)"
    exit 4
fi

D=$(state_dir sliver)
PIDFILE="$D/sliver.pid"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    log INFO "sliver-server already running (pid $(cat "$PIDFILE"))"
    log INFO "  attach with: sliver-client import $D/operator.cfg"
    exit 0
fi

log INFO "starting sliver-server (state: $D)"
nohup sliver-server daemon --lhost "$LISTEN_HOST" --lport "$LISTEN_PORT" \
    > "$D/sliver.log" 2>&1 &
echo $! > "$PIDFILE"

sleep 3

if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    log ERR "sliver-server failed to start — see $D/sliver.log"
    exit 6
fi

# Generate an operator config (run once)
if [ ! -f "$D/operator.cfg" ]; then
    log INFO "generating operator config"
    sliver-server operator --name "$(whoami)" --lhost "$LISTEN_HOST" \
        --save "$D/operator.cfg" 2>/dev/null || true
fi

log INFO "sliver running:"
log INFO "  pid:       $(cat "$PIDFILE")"
log INFO "  daemon:    $LISTEN_HOST:$LISTEN_PORT"
log INFO "  logs:      $D/sliver.log"
log INFO "  operator:  $D/operator.cfg"
log INFO ""
log INFO "next steps:"
log INFO "  sliver-client import $D/operator.cfg"
log INFO "  sliver-client            # interactive console"
log INFO ""
log INFO "stop with:  kill \$(cat $PIDFILE)"
