#!/usr/bin/env bash
# report/dup-check.sh — query ReconForge's findings DB for prior similar
# reports against the same target.
#
# Usage:
#   ./dup-check.sh <vuln_class> <target>
#
# Triagers downgrade duplicates (and remember the researcher). This
# script does NOT prevent duplicate submissions — it surfaces enough
# context for the operator to decide if their finding is genuinely new.

set -o pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

VULN_CLASS="${1:-}"
TARGET="${2:-}"

[ -z "$VULN_CLASS" ] || [ -z "$TARGET" ] && {
    echo "usage: $0 <vuln_class> <target>"
    echo "       e.g. $0 ssrf acme.com"
    exit 2
}

DB="${RECON_DATA_DIR:-$REPO_ROOT/recon_data}/recon.db"
[ ! -f "$DB" ] && {
    echo "no recon.db at $DB"
    echo "set RECON_DATA_DIR to the right path"
    exit 5
}

echo "── prior findings: target=$TARGET class=$VULN_CLASS ──"
sqlite3 -header -column "$DB" <<SQL 2>/dev/null
SELECT
    id,
    SUBSTR(created_at, 1, 10) AS date,
    title,
    severity,
    status
FROM findings
WHERE vuln_class = '$VULN_CLASS'
  AND (target = '$TARGET' OR target LIKE '%.$TARGET')
ORDER BY created_at DESC
LIMIT 20;
SQL

echo
echo "── ANY finding on this target (last 90 days) ──"
sqlite3 -header -column "$DB" <<SQL 2>/dev/null
SELECT
    SUBSTR(created_at, 1, 10) AS date,
    vuln_class,
    SUBSTR(title, 1, 60) AS title_excerpt,
    severity
FROM findings
WHERE (target = '$TARGET' OR target LIKE '%.$TARGET')
  AND DATE(created_at) >= DATE('now', '-90 days')
ORDER BY created_at DESC
LIMIT 20;
SQL

echo
echo "── ANY finding of this CLASS (any target, last 90 days) ──"
echo "(for cross-target pattern detection — same SSRF in multiple programs)"
sqlite3 -header -column "$DB" <<SQL 2>/dev/null
SELECT
    SUBSTR(created_at, 1, 10) AS date,
    target,
    SUBSTR(title, 1, 50) AS title_excerpt,
    severity,
    status
FROM findings
WHERE vuln_class = '$VULN_CLASS'
  AND DATE(created_at) >= DATE('now', '-90 days')
ORDER BY created_at DESC
LIMIT 20;
SQL

echo
echo "RULE OF THUMB:"
echo "  - Same target + same vuln_class in last 90d → almost certainly dup"
echo "  - Same vuln_class on different subdomain    → possibly distinct"
echo "  - Different parameter / different endpoint  → usually distinct"
echo "  - When in doubt, mention prior findings in your report header"
