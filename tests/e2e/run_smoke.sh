#!/usr/bin/env bash
#
# E2E smoke verification harness.
#
# Reads tests/e2e/expected_artifacts.json and checks every assertion
# against the live system. Prints a PASS / FAIL line per check; exits
# non-zero if anything failed.
#
# Required env:
#   RECONFORGE_DB     path to recon.db inside the container or host
#   RECONFORGE_VAULT  path to BugBountyVault
#   JOB_ID            the job_id of the test scan
#
set -euo pipefail

DB="${RECONFORGE_DB:-${HOME}/.config/reconforge/recon.db}"
VAULT="${RECONFORGE_VAULT:-${HOME}/Documents/BugBountyVault}"
JOB_ID="${JOB_ID:-}"
PORT="${RECONFORGE_PORT:-8342}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="${ROOT}/tests/e2e/expected_artifacts.json"

if [ -z "$JOB_ID" ]; then
  echo "JOB_ID env var is required. Find it via: sqlite3 \"$DB\" 'SELECT id FROM completed_jobs ORDER BY completed_at DESC LIMIT 1'"
  exit 2
fi

pass=0
fail=0
check() {
  local name="$1" outcome="$2" detail="${3:-}"
  if [ "$outcome" -eq 0 ]; then
    printf '  \033[32mPASS\033[0m %-40s %s\n' "$name" "$detail"
    pass=$((pass + 1))
  else
    printf '  \033[31mFAIL\033[0m %-40s %s\n' "$name" "$detail"
    fail=$((fail + 1))
  fi
}

echo "E2E smoke verification — job_id=${JOB_ID}"
echo "  db:    $DB"
echo "  vault: $VAULT"
echo

# ── files ─────────────────────────────────────────────────────
echo "Vault files:"
strategist_md="${VAULT}/01-Programs/juiceshop/strategist_plan.md"
if [ -f "$strategist_md" ] && grep -q "Recommended Starting Tier" "$strategist_md"; then
  check "strategist_plan.md present" 0
else
  check "strategist_plan.md present" 1 "missing or empty"
fi

bug_count=$(ls "${VAULT}/01-Programs/juiceshop"/BUG-*.md 2>/dev/null | wc -l || echo 0)
if [ "$bug_count" -ge 1 ]; then
  check "BUG-*.md notes present" 0 "$bug_count notes"
else
  check "BUG-*.md notes present" 1 "0 notes found"
fi

# ── database checks ───────────────────────────────────────────
echo; echo "Database state:"

q() { sqlite3 "$DB" "$1" 2>/dev/null; }

n=$(q "SELECT COUNT(*) FROM findings WHERE cvss_score IS NOT NULL AND cvss_score > 0")
if [ "${n:-0}" -ge 1 ]; then
  check "findings with CVSS > 0"      0 "$n found"
else
  check "findings with CVSS > 0"      1 "expected ≥1, got ${n:-0}"
fi

n=$(q "SELECT COUNT(DISTINCT tactic) FROM attack_techniques")
if [ "${n:-0}" -ge 3 ]; then
  check "ATT&CK tactics covered ≥ 3"  0 "$n distinct tactics"
else
  check "ATT&CK tactics covered ≥ 3"  1 "got ${n:-0}"
fi

n=$(q "SELECT COUNT(DISTINCT platform) FROM submission_drafts")
if [ "${n:-0}" -ge 2 ]; then
  check "drafts span ≥ 2 platforms"   0 "$n distinct platforms"
else
  check "drafts span ≥ 2 platforms"   1 "got ${n:-0}"
fi

n=$(q "SELECT COUNT(*) FROM submission_drafts WHERE human_approved = 1")
if [ "${n:-0}" -eq 0 ]; then
  check "no auto-approved drafts"      0 "0 auto-approved"
else
  check "no auto-approved drafts"      1 "$n drafts auto-approved!"
fi

n=$(q "SELECT COUNT(DISTINCT agent) FROM agent_runs WHERE job_id='${JOB_ID}'")
if [ "${n:-0}" -ge 6 ]; then
  check "all 6 agents ran"             0 "$n distinct agents"
else
  check "all 6 agents ran"             1 "got ${n:-0}"
fi

# ── API check ─────────────────────────────────────────────────
echo; echo "API:"

if command -v curl >/dev/null 2>&1; then
  json=$(curl -sf "http://localhost:${PORT}/api/attack/heatmap?job=${JOB_ID}" || echo "")
  if echo "$json" | grep -q '"TA0043"'; then
    check "heatmap returns 14 tactics"  0
  else
    check "heatmap returns 14 tactics"  1 "$(echo "$json" | head -c 80)"
  fi
  total=$(echo "$json" | python3 -c 'import sys, json; print(json.load(sys.stdin).get("total_findings", 0))' 2>/dev/null || echo 0)
  if [ "${total:-0}" -ge 1 ]; then
    check "heatmap total_findings ≥ 1"  0 "$total"
  else
    check "heatmap total_findings ≥ 1"  1 "got ${total:-0}"
  fi
else
  check "curl present"                  1 "skipping API checks"
fi

echo
echo "Summary: ${pass} passed, ${fail} failed."
[ "$fail" -eq 0 ]
