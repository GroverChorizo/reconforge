#!/usr/bin/env bash
# report/cvss-calc.sh — interactive CVSS 4.0 score calculator.
#
# Wraps core/cvss.py so the operator can compute the score from the CLI
# without the in-app modal.

set -o pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Non-interactive: pass a full vector string as argv[1].
#   ./cvss-calc.sh "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
VECTOR="${1:-}"

if [ -n "$VECTOR" ]; then
    REPO_ROOT="$REPO_ROOT" VECTOR="$VECTOR" python3 - <<'PY'
import os, sys
sys.path.insert(0, os.environ["REPO_ROOT"])
from core import cvss
v = os.environ["VECTOR"]
s = cvss.score(v)
print("Vector:", v)
print("Score: ", s)
print("Sev:   ", cvss.severity_label(s))
PY
    exit 0
fi

# Interactive mode — walk the operator through the standard CVSS 4.0
# base metrics. Realistic defaults for a typical bug-bounty web finding.
echo "CVSS 4.0 — Base Metrics"
echo "─────────────────────────"

ask() {
    local name="$1" prompt="$2" default="$3" options="$4"
    echo "$name ($options) [default $default]"
    printf "  > "
    read -r value
    echo "${value:-$default}"
}

AV=$(ask AV "Attack Vector"          "N" "N/A/L/P")
AC=$(ask AC "Attack Complexity"      "L" "L/H")
AT=$(ask AT "Attack Requirements"    "N" "N/P")
PR=$(ask PR "Privileges Required"    "N" "N/L/H")
UI=$(ask UI "User Interaction"       "N" "N/P/A")
VC=$(ask VC "Vulnerable Sys Confid"  "H" "N/L/H")
VI=$(ask VI "Vulnerable Sys Integ"   "H" "N/L/H")
VA=$(ask VA "Vulnerable Sys Avail"   "N" "N/L/H")
SC=$(ask SC "Subseq Sys Confid"      "N" "N/L/H")
SI=$(ask SI "Subseq Sys Integ"       "N" "N/L/H")
SA=$(ask SA "Subseq Sys Avail"       "N" "N/L/H")

VEC="CVSS:4.0/AV:$AV/AC:$AC/AT:$AT/PR:$PR/UI:$UI/VC:$VC/VI:$VI/VA:$VA/SC:$SC/SI:$SI/SA:$SA"
echo
echo "──────────────────────"
REPO_ROOT="$REPO_ROOT" VECTOR="$VEC" python3 - <<'PY' 2>/dev/null || { echo "core/cvss.py couldn't compute the score; falling back to vector only."; echo "Vector: $VEC"; }
import os, sys
sys.path.insert(0, os.environ["REPO_ROOT"])
from core import cvss
v = os.environ["VECTOR"]
s = cvss.score(v)
print("Vector:", v)
print("Score: ", s)
print("Sev:   ", cvss.severity_label(s))
PY
