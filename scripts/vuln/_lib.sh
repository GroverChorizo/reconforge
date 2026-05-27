#!/usr/bin/env bash
# scripts/vuln/_lib.sh — shared helpers for per-vuln-class playbooks.
#
# Symlinked behavior with scripts/recon/_lib.sh — same env knobs, plus a
# few vuln-specific ones (BLIND_XSS_URL, INTERACTSH_URL, AUTH_A/AUTH_B).

set -o pipefail

: "${RECONFORGE_OUTPUT_DIR:=$HOME/Documents/CyberBrain/03-Research/Recon}"
: "${THREADS:=10}"
: "${RATE_LIMIT_RPS:=50}"
: "${DATESTAMP:=$(date +%Y-%m-%d-%H%M)}"
: "${SCOPE_FILE:=}"

log() {
    local level="$1"; shift
    local ts
    ts=$(date '+%H:%M:%S')
    printf '[%s][%-4s][%s] %s\n' "$ts" "$level" "${PHASE:-vuln}" "$*" >&2
}

require_target() {
    if [ -z "${TARGET:-}" ]; then
        log ERR "TARGET required (root domain or specific URL)"
        exit 2
    fi
}

ensure_scope() {
    local target="${1:-$TARGET}"
    if [ -z "$SCOPE_FILE" ] || [ ! -f "$SCOPE_FILE" ]; then
        log WARN "no SCOPE_FILE — proceeding under operator's manual scope verification"
        return 0
    fi
    if python3 -c "import scope_guard" 2>/dev/null; then
        if python3 -c "
import json, sys, scope_guard
prog = json.load(open(sys.argv[1]))
r = scope_guard.check(sys.argv[2], prog)
sys.exit(0 if r.get('allowed') else 1)
" "$SCOPE_FILE" "$target" 2>/dev/null; then
            log INFO "scope: $target IN-SCOPE"
        else
            log ERR "scope: $target OUT-OF-SCOPE — refusing"
            exit 3
        fi
    fi
}

out_dir() {
    local phase="${1:-vuln}"
    local d="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/vuln/$phase"
    mkdir -p "$d"
    echo "$d"
}

# Resolve URL list from a previous recon run (the URLS env var wins if set).
resolve_urls_input() {
    if [ -n "${URLS:-}" ] && [ -f "$URLS" ]; then
        echo "$URLS"; return
    fi
    local candidates=(
        "$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/06-crawl/urls.txt"
        "$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/09-archive-urls/archive-urls.txt"
    )
    for c in "${candidates[@]}"; do
        [ -s "$c" ] && { echo "$c"; return; }
    done
    echo ""
}
