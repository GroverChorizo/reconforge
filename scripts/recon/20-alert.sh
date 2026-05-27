#!/usr/bin/env bash
# Phase 20 — alert relay via notify.
#
# Sweep the run's output dir for actionable findings, dedupe against the
# prior run, and push a summary to whatever providers are configured in
# ~/.config/notify/provider-config.yaml.

PHASE="20-alert"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
RUN_ROOT="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP"

if ! command -v notify >/dev/null 2>&1; then
    log ERR "notify not installed — set up ~/.config/notify/provider-config.yaml first"
    exit 4
fi

SUMMARY="$OUTDIR/summary.txt"
{
    echo "ReconForge run summary — $TARGET — $DATESTAMP"
    echo "================================================="
    echo "subdomains:    $(wc -l < "$RUN_ROOT/01-passive-enum/subs.txt" 2>/dev/null || echo 0)"
    echo "resolved:      $(wc -l < "$RUN_ROOT/02-resolve/resolved.txt" 2>/dev/null || echo 0)"
    echo "open ports:    $(wc -l < "$RUN_ROOT/04-port-scan/ports.txt" 2>/dev/null || echo 0)"
    echo "alive hosts:   $(wc -l < "$RUN_ROOT/05-http-probe/alive.txt" 2>/dev/null || echo 0)"
    echo "URLs:          $(wc -l < "$RUN_ROOT/06-crawl/urls.txt" 2>/dev/null || echo 0)"
    echo "JS files:      $(wc -l < "$RUN_ROOT/06-crawl/js.txt" 2>/dev/null || echo 0)"
    echo "secrets:       $(cat "$RUN_ROOT/19-secrets"/*.jsonl 2>/dev/null | wc -l)"
    echo "nuclei hits:   $(cat "$RUN_ROOT/14-vuln-scan"/*.jsonl 2>/dev/null | wc -l)"
    echo "XSS confirmed: $(wc -l < "$RUN_ROOT/15-xss-targeted/confirmed.txt" 2>/dev/null || echo 0)"
    echo "CRLF hits:     $(wc -l < "$RUN_ROOT/16-crlf/crlf.txt" 2>/dev/null || echo 0)"
} > "$SUMMARY"

log INFO "summary built; pushing via notify"
notify -bulk -data "$SUMMARY" -id "${NOTIFY_ID:-reconforge}" 2>/dev/null || true

log INFO "Phase 20 done — alerts pushed; summary at $SUMMARY"
