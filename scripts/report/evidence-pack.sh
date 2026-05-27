#!/usr/bin/env bash
# report/evidence-pack.sh — bundle evidence into a single uploadable zip.
#
# Sweeps the current run's output directories for screenshots, JSONL
# findings, raw req/resp pairs, and the report draft. Produces:
#
#   $OUTDIR/reports/evidence-<TARGET>-<DATESTAMP>.zip
#
# Strips secrets (cookies, API keys) from the bundled artifacts using a
# heuristic regex pass — verify the output before uploading.

set -o pipefail

: "${RECONFORGE_OUTPUT_DIR:=$HOME/Documents/CyberBrain/03-Research/Recon}"
[ -z "${TARGET:-}" ]    && { echo "TARGET required"; exit 2; }
[ -z "${DATESTAMP:-}" ] && { echo "DATESTAMP required"; exit 2; }

RUN_ROOT="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP"
[ ! -d "$RUN_ROOT" ] && { echo "no such run dir: $RUN_ROOT"; exit 5; }

OUT_ZIP="$RUN_ROOT/reports/evidence-$TARGET-$DATESTAMP.zip"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# What we pack (lightweight allowlist — avoid bundling 4GB of nuclei
# templates by accident):
PATTERNS=(
    'reports/*.md'
    'reports/*.json'
    '15-xss-targeted/confirmed.txt'
    '14-vuln-scan/nuclei.jsonl'
    '14-vuln-scan/kev.jsonl'
    '07-js-analyze/js-secrets.jsonl'
    '07-js-analyze/trufflehog.jsonl'
    '19-secrets/*.jsonl'
    'vuln/*/findings.csv'
    'vuln/*/result.json'
    'vuln/*/REPORT-template.md'
    'vuln/*/CHAIN-REPORT.md'
    '18-screenshot/*.png'
    '18-screenshot/*.sqlite'
)

mkdir -p "$STAGE/evidence/$TARGET"
for p in "${PATTERNS[@]}"; do
    # shellcheck disable=SC2086
    for f in $RUN_ROOT/$p; do
        [ -f "$f" ] || continue
        rel="${f#$RUN_ROOT/}"
        mkdir -p "$STAGE/evidence/$TARGET/$(dirname "$rel")"
        cp "$f" "$STAGE/evidence/$TARGET/$rel"
    done
done

# Sanitize: redact obvious secrets from text artifacts
echo "scrubbing secrets from text artifacts..."
SECRET_REGEX='(Bearer +[A-Za-z0-9._-]+|session=[A-Za-z0-9_-]+|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|aws_secret_access_key[ =:]+[A-Za-z0-9+/=]+|password[ =:]+[^[:space:]]+|api_key[ =:]+[A-Za-z0-9_-]+)'

find "$STAGE/evidence" -type f \( -name '*.txt' -o -name '*.md' -o -name '*.json' -o -name '*.jsonl' -o -name '*.csv' \) -print0 \
    | xargs -0 -I{} sed -E -i "s|${SECRET_REGEX}|<REDACTED>|gi" {} 2>/dev/null || true

# Manifest
{
    echo "ReconForge evidence bundle"
    echo "  target:    $TARGET"
    echo "  run:       $DATESTAMP"
    echo "  generated: $(date -Is)"
    echo
    echo "Contents:"
    cd "$STAGE/evidence/$TARGET" && find . -type f | sort
} > "$STAGE/evidence/$TARGET/MANIFEST.txt"

mkdir -p "$RUN_ROOT/reports"
(cd "$STAGE" && zip -r "$OUT_ZIP" "evidence" >/dev/null)

size=$(du -h "$OUT_ZIP" | cut -f1)
echo "evidence pack: $OUT_ZIP ($size)"
echo ""
echo "BEFORE UPLOAD:"
echo "  1. unzip -l $OUT_ZIP    # review what's in there"
echo "  2. grep -RE '<REDACTED>' $OUT_ZIP # confirm scrub ran"
echo "  3. spot-check that no live tokens remain"
