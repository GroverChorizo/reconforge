#!/usr/bin/env bash
# Phase 19 — secret hunting (TruffleHog).
#
# Three modes (auto-select based on inputs):
#   1. Filesystem on the JS bodies we already downloaded in Phase 7
#   2. GitHub org (when GITHUB_TOKEN + GH_ORG set)
#   3. Single repo (when GIT_REPO set)

PHASE="19-secrets"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")

if ! command -v trufflehog >/dev/null 2>&1; then
    log ERR "trufflehog not installed"
    exit 4
fi

# Mode 1: filesystem scan over JS bodies from Phase 7
JS_DIR="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/07-js-analyze/js-bodies"
if [ -d "$JS_DIR" ]; then
    log INFO "trufflehog filesystem $JS_DIR"
    trufflehog filesystem "$JS_DIR" --json --no-update --only-verified \
        > "$OUTDIR/fs.jsonl" 2>/dev/null || true
fi

# Mode 2: github org scan (most valuable — most secrets live here)
if [ -n "${GH_ORG:-}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
    log INFO "trufflehog github --org=$GH_ORG (verified only)"
    trufflehog github --org="$GH_ORG" --token="$GITHUB_TOKEN" \
        --only-verified --json > "$OUTDIR/gh-org.jsonl" 2>/dev/null || true
fi

# Mode 3: single-repo deep scan
if [ -n "${GIT_REPO:-}" ]; then
    log INFO "trufflehog git $GIT_REPO"
    trufflehog git "$GIT_REPO" --only-verified --json \
        > "$OUTDIR/repo.jsonl" 2>/dev/null || true
fi

count=$(cat "$OUTDIR"/*.jsonl 2>/dev/null | wc -l)
log INFO "Phase 19 done — $count verified secret hits"
[ "$count" -gt 0 ] && log INFO "→ analyze with: cat $OUTDIR/*.jsonl | jq 'select(.Verified==true)'"
