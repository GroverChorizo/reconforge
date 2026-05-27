#!/usr/bin/env bash
# Phase 13 — Interactsh OOB callback session.
#
# Starts an interactsh-client in the background, prints the session URL,
# and tails callbacks to $OUTDIR/callbacks.txt. Intended to be run while
# Phase 14+ probes fire payloads containing the session URL.

PHASE="13-oob-callback"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
SERVER="${OOB_SERVER:-oast.pro}"
TOKEN="${OOB_TOKEN:-}"

if ! command -v interactsh-client >/dev/null 2>&1; then
    log ERR "interactsh-client not installed (go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest)"
    exit 4
fi

CALLBACKS="$OUTDIR/callbacks.txt"
PIDFILE="$OUTDIR/interactsh.pid"

# If a previous session is still running, reuse its URL.
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    log INFO "existing interactsh session still running (pid $(cat "$PIDFILE"))"
    [ -f "$OUTDIR/session-url.txt" ] && cat "$OUTDIR/session-url.txt"
    exit 0
fi

ARGS=(-server "$SERVER" -n 5 -o "$CALLBACKS" -v)
[ -n "$TOKEN" ] && ARGS+=(-token "$TOKEN")

log INFO "starting interactsh-client (server=$SERVER)"
nohup interactsh-client "${ARGS[@]}" >"$OUTDIR/interactsh.log" 2>&1 &
echo $! > "$PIDFILE"

# Wait for the session URL to land in the log (~3s typical)
for _ in $(seq 1 10); do
    URL=$(grep -oE '[a-z0-9]+\.'"${SERVER}" "$OUTDIR/interactsh.log" 2>/dev/null | head -1)
    [ -n "$URL" ] && break
    sleep 1
done

if [ -z "${URL:-}" ]; then
    log ERR "couldn't extract OOB session URL — check $OUTDIR/interactsh.log"
    exit 6
fi

echo "$URL" > "$OUTDIR/session-url.txt"
log INFO "OOB session URL: http://$URL/"
log INFO "  pid:        $(cat "$PIDFILE")"
log INFO "  callbacks:  $CALLBACKS"
log INFO "  stop with:  kill \$(cat $PIDFILE)"
log INFO "set INTERACTSH_URL=$URL in Phase 12 / settings.json for SSRF payloads"
