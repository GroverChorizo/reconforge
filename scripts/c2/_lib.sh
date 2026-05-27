#!/usr/bin/env bash
# scripts/c2/_lib.sh — shared helpers for C2 / post-exploitation setup.
#
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  CRITICAL POLICY                                                     ║
# ║                                                                      ║
# ║  These scripts are for AUTHORIZED ENGAGEMENTS only:                  ║
# ║    - The operator's home lab (HOME_LAB=yes)                          ║
# ║    - CTF competitions (CTF=yes)                                      ║
# ║    - Pentest engagements with written authorization                  ║
# ║      (PENTEST_AUTH=path-to-letter-of-authorization)                  ║
# ║                                                                      ║
# ║  C2 establishment, persistence, and post-exploitation are NEVER      ║
# ║  permitted on bug-bounty targets, regardless of program tier or      ║
# ║  apparent permissiveness of scope. Bug-bounty work stops at          ║
# ║  vulnerability confirmation; the report is the deliverable.          ║
# ║                                                                      ║
# ║  Every script in this directory refuses to run unless one of the     ║
# ║  three authorization signals above is present.                       ║
# ╚══════════════════════════════════════════════════════════════════════╝

set -o pipefail

: "${C2_STATE:=$HOME/.local/share/reconforge/c2}"
: "${LISTEN_HOST:=0.0.0.0}"
: "${LISTEN_PORT:=8443}"

log() {
    local level="$1"; shift
    local ts
    ts=$(date '+%H:%M:%S')
    printf '[%s][%-4s][%s] %s\n' "$ts" "$level" "${PHASE:-c2}" "$*" >&2
}

require_authorization() {
    local ok=0

    if [ "${HOME_LAB:-no}" = "yes" ]; then
        log INFO "authorization: HOME_LAB=yes"
        ok=1
    fi
    if [ "${CTF:-no}" = "yes" ]; then
        log INFO "authorization: CTF=yes (named: ${CTF_NAME:-unnamed})"
        ok=1
    fi
    if [ -n "${PENTEST_AUTH:-}" ] && [ -f "$PENTEST_AUTH" ]; then
        log INFO "authorization: PENTEST_AUTH=$PENTEST_AUTH"
        ok=1
    fi

    if [ "$ok" -ne 1 ]; then
        cat >&2 <<EOF

ERROR: C2 / post-exploitation scripts require explicit authorization.

Set ONE of:
  HOME_LAB=yes               (your own lab infrastructure)
  CTF=yes CTF_NAME=<name>    (named CTF competition)
  PENTEST_AUTH=<path>        (path to your letter of authorization)

This is the wall between authorized testing and unauthorized access. It
is not bureaucracy — it is the wall that keeps you out of jail.

EOF
        exit 8
    fi
}

# Refuse to start C2 infrastructure targeting any in-scope bug-bounty
# domain. The bug-bounty scope file is loaded if SCOPE_FILE is set.
refuse_if_bug_bounty_target() {
    local target="${1:-}"
    [ -z "$target" ] && return 0
    [ -z "${SCOPE_FILE:-}" ] && return 0
    [ ! -f "$SCOPE_FILE" ] && return 0
    if python3 -c "import scope_guard" 2>/dev/null; then
        if python3 -c "
import json, sys, scope_guard
prog = json.load(open(sys.argv[1]))
r = scope_guard.check(sys.argv[2], prog)
sys.exit(0 if r.get('allowed') else 1)
" "$SCOPE_FILE" "$target" 2>/dev/null; then
            log ERR "REFUSING: $target appears in your bug-bounty scope file."
            log ERR "         Bug-bounty programs do not authorize C2 / persistence."
            log ERR "         Either remove SCOPE_FILE for home-lab work, or use a"
            log ERR "         different target. Aborting."
            exit 9
        fi
    fi
}

state_dir() {
    local name="${1:-default}"
    local d="$C2_STATE/$name"
    mkdir -p "$d"
    echo "$d"
}
