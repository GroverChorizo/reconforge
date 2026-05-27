#!/usr/bin/env bash
# scripts/recon/_lib.sh — shared helpers for every phase script.
#
# Source this at the top of any phase script:
#   . "$(dirname "$0")/_lib.sh"
#
# Provides:
#   log INFO|WARN|ERR <msg>         — structured timestamped logging
#   require_target                  — exit 2 if $TARGET is empty
#   ensure_scope <target>           — exit 3 if scope_guard refuses
#   tool_check <tool> [<tool>...]   — WARN missing tools, exit 4 if none usable
#   out_dir <phase>                 — echo a per-phase output dir under
#                                     $RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/
#   anew_or_tee <path>              — pipe filter: dedupe if anew present, else tee
#
# Environment knobs (override in settings.json or shell):
#   RECONFORGE_OUTPUT_DIR  default ~/Documents/CyberBrain/03-Research/Recon
#   THREADS                default 10
#   RATE_LIMIT_RPS         default 50
#   WORDLIST_DIR           default /usr/share/seclists
#   RESOLVERS_FILE         default ~/wordlists/resolvers.txt
#   SCOPE_FILE             optional path to a JSON scope file; if absent the
#                          scope check is logged-only and never refuses

set -o pipefail

: "${RECONFORGE_OUTPUT_DIR:=$HOME/Documents/CyberBrain/03-Research/Recon}"
: "${THREADS:=10}"
: "${RATE_LIMIT_RPS:=50}"
: "${WORDLIST_DIR:=/usr/share/seclists}"
: "${RESOLVERS_FILE:=$HOME/wordlists/resolvers.txt}"
: "${DATESTAMP:=$(date +%Y-%m-%d-%H%M)}"
: "${SCOPE_FILE:=}"

# ── logging ──────────────────────────────────────────────────────
log() {
    local level="$1"; shift
    local ts
    ts=$(date '+%H:%M:%S')
    printf '[%s][%-4s][%s] %s\n' "$ts" "$level" "${PHASE:-recon}" "$*" >&2
}

# ── argument + scope gates ───────────────────────────────────────
require_target() {
    if [ -z "${TARGET:-}" ]; then
        log ERR "TARGET is required. Usage: TARGET=example.com $0"
        exit 2
    fi
}

ensure_scope() {
    local target="${1:-$TARGET}"
    if [ -z "$SCOPE_FILE" ] || [ ! -f "$SCOPE_FILE" ]; then
        log WARN "no SCOPE_FILE set — running without programmatic scope check"
        log WARN "you are responsible for verifying $target is in scope"
        return 0
    fi
    # Prefer the Python scope_guard (matches in-app behavior). Fall back to
    # hacker-scoper if scope_guard.py is not importable from PWD.
    if python3 -c "import scope_guard" 2>/dev/null; then
        local result
        result=$(python3 -c "
import json, sys, scope_guard
prog = json.load(open(sys.argv[1]))
r = scope_guard.check(sys.argv[2], prog)
print(json.dumps(r))
" "$SCOPE_FILE" "$target" 2>/dev/null) || {
            log ERR "scope_guard invocation failed; refusing"
            exit 3
        }
        if echo "$result" | grep -q '"allowed": *true'; then
            log INFO "scope: $target IN-SCOPE"
            return 0
        else
            log ERR "scope: $target OUT-OF-SCOPE — refusing"
            log ERR "scope_guard said: $result"
            exit 3
        fi
    elif command -v hacker-scoper >/dev/null 2>&1; then
        echo "$target" | hacker-scoper -f - -s "$SCOPE_FILE" >/dev/null 2>&1 || {
            log ERR "scope: $target OUT-OF-SCOPE (hacker-scoper)"
            exit 3
        }
        log INFO "scope: $target IN-SCOPE (hacker-scoper)"
    else
        log WARN "no scope checker available — proceeding without verification"
    fi
}

# ── tool availability ────────────────────────────────────────────
tool_check() {
    local missing=()
    local available=()
    for t in "$@"; do
        if command -v "$t" >/dev/null 2>&1; then
            available+=("$t")
        else
            missing+=("$t")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log WARN "missing tools (skipping): ${missing[*]}"
    fi
    if [ ${#available[@]} -eq 0 ]; then
        log ERR "no required tool available; abort"
        return 4
    fi
    # Echo available tools so callers can iterate
    printf '%s\n' "${available[@]}"
    return 0
}

# ── output paths ─────────────────────────────────────────────────
out_dir() {
    local phase="${1:-misc}"
    local d="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/$phase"
    mkdir -p "$d"
    echo "$d"
}

# ── dedupe helper ────────────────────────────────────────────────
anew_or_tee() {
    local path="$1"
    if command -v anew >/dev/null 2>&1; then
        anew "$path"
    else
        tee -a "$path"
    fi
}
