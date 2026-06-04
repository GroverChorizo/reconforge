#!/usr/bin/env bash
# scripts/recon/master-pipeline.sh — full recon kill chain in order.
#
#   TARGET=acme.com SCOPE_FILE=scopes/acme.json ./master-pipeline.sh
#
# Each phase runs to completion before the next starts (sequential).
# Each phase writes under $RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/
# and emits structured logs to stderr; pipe to `tee run.log` to capture.
#
# Phases (skip with SKIP_PHASES="08,17" — comma-separated):
#   00 scope-check        13 oob-callback
#   01 passive-enum       14 vuln-scan
#   02 resolve            15 xss-targeted
#   03 tls-cdn            16 crlf
#   04 port-scan          17 sqli (gated; SQLI_CONFIRM=yes to actually run)
#   05 http-probe         18 screenshot
#   06 crawl              19 secrets
#   07 js-analyze         20 alert
#   08 content-discovery
#   09 archive-urls
#   10 param-discovery
#   11 pattern-filter
#   12 payload-replace

set -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/_lib.sh"
require_target

SKIP="${SKIP_PHASES:-}"
should_run() {
    local n="$1"
    [[ ",$SKIP," == *",$n,"* ]] && return 1
    return 0
}

# Quoted string tokens — these are filename stems (matching NN-name.sh on
# disk), not numbers. Quoting keeps the zero-padded "08"/"09" from being read
# as invalid octal literals by linters or any arithmetic context.
PHASES=(
    "00-scope-check"
    "01-passive-enum"
    "02-resolve"
    "03-tls-cdn"
    "04-port-scan"
    "05-http-probe"
    "06-crawl"
    "07-js-analyze"
    "08-content-discovery"
    "09-archive-urls"
    "10-param-discovery"
    "11-pattern-filter"
    "12-payload-replace"
    "13-oob-callback"
    "14-vuln-scan"
    "15-xss-targeted"
    "16-crlf"
    "17-sqli"
    "18-screenshot"
    "19-secrets"
    "20-alert"
)

for phase in "${PHASES[@]}"; do
    num="${phase%%-*}"
    if ! should_run "$num"; then
        log INFO "skipping phase $phase (SKIP_PHASES)"
        continue
    fi
    script="$HERE/$phase.sh"
    if [ ! -x "$script" ]; then
        log WARN "phase script $script not executable; skipping"
        continue
    fi
    log INFO "═══ $phase ═══"
    if ! "$script"; then
        rc=$?
        # Scope failure (3) is fatal; tool/input failures (4, 5) are skippable
        if [ "$rc" -eq 3 ]; then
            log ERR "scope refused — aborting master pipeline"
            exit 3
        fi
        log WARN "$phase exited rc=$rc; continuing"
    fi
done

log INFO "═══ master-pipeline complete ═══"
log INFO "run root: $RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/"
