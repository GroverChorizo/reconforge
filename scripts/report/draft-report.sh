#!/usr/bin/env bash
# report/draft-report.sh — generate a platform-specific report skeleton.
#
# Usage:
#   PLATFORM=hackerone VULN_CLASS=ssrf TARGET=acme.com ./draft-report.sh
#
# PLATFORM ∈ {hackerone, intigriti, bugcrowd, yeswehack, synack}
# VULN_CLASS — informational only, lands in the title hint
#
# Writes to: $RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/reports/draft-<PLATFORM>.md

set -o pipefail

: "${RECONFORGE_OUTPUT_DIR:=$HOME/Documents/CyberBrain/03-Research/Recon}"
: "${DATESTAMP:=$(date +%Y-%m-%d-%H%M)}"

[ -z "${TARGET:-}" ]   && { echo "TARGET required";   exit 2; }
[ -z "${PLATFORM:-}" ] && { echo "PLATFORM required"; exit 2; }
VULN_CLASS="${VULN_CLASS:-finding}"

OUTDIR="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/reports"
mkdir -p "$OUTDIR"
DRAFT="$OUTDIR/draft-$PLATFORM.md"

case "$PLATFORM" in
    hackerone)
        cat > "$DRAFT" <<'EOF'
**Title:** [VulnClass] in [asset] allows [impact]
**Severity:** TBD — CVSS 4.0 score: X.X
**Weakness:** CWE-XXX ([name])
**Asset type:** [URL / API endpoint / Mobile app / Source code]

## Summary

[2–3 sentence executive summary. What is it, where is it, what can an
attacker do. Triagers read this first; make every word earn its place.]

## Steps to Reproduce

1. [First action — set up state, log in as User A, etc.]
2. [Second action — the actual exploit step]
3. [Third action — observe the impact]
4. [Optional — recovery / cleanup]

## Proof of Concept

```http
POST /api/path HTTP/1.1
Host: <target>
Cookie: session=...
Content-Type: application/json

<payload>
```

Response:
```http
HTTP/1.1 200 OK
...
<response body showing the issue>
```

## Impact

[Specific data / access / action an attacker gains. Tie to business
risk: PII exposure, account takeover, financial loss, downstream
compromise.]

## CVSS 4.0 Justification

AV:N / AC:L / AT:N / PR:N / UI:N / VC:H / VI:H / VA:N / SC:N / SI:N / SA:N

- AV:N — exploit is over the network (internet-facing)
- AC:L — no special conditions required
- PR:N — no authentication required
- ...

## Remediation

[Specific fix. Reference OWASP / vendor docs where applicable. Avoid
hand-wavy "validate input" — propose the actual change.]
EOF
        ;;

    intigriti)
        cat > "$DRAFT" <<'EOF'
## Executive Summary
[1 paragraph. Asset, class, severity, business impact.]

## Technical Details
[Full technical explanation of root cause. Include affected endpoints,
parameters, expected vs actual behavior.]

### Reproduction Steps
1. [Step one]
2. [Step two]
3. [Step three]

### Proof of Concept
```http
[HTTP request]
```
```http
[HTTP response — abbreviated to relevant headers + first ~50 lines of body]
```

## CVSS Score
**Vector:** AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
**Score:** X.X / 10.0
- Per-metric justification (4-5 lines)

## Impact
[Specific attacker capability. Data exposed, privilege gained, blast
radius. State whether this affects Intigriti's confidentiality,
integrity, or availability obligations to their customer.]

## Remediation
[Concrete actionable fix]

## Evidence
[Inline screenshots with captions. Raw request/response pairs. Browser
console output if applicable.]

---
*X-Intigriti-Username: grover  |  Platform: Intigriti*
EOF
        ;;

    bugcrowd)
        cat > "$DRAFT" <<'EOF'
**VRT Category:** [SELECT FROM BUGCROWD VRT DROPDOWN — get this right
the first time, you can't edit after submission]

**Title:** [VRT category] — [specific description]

## Summary
[2-3 sentences]

## Steps to Reproduce
1. [Step]
2. [Step]
3. [Step]

## Proof of Concept
[Working payload / request / code]

## Impact
[What an attacker gains. Be concrete.]

## Evidence
- Screenshot: [filename]
- Video PoC: [link or filename] — strongly preferred by Bugcrowd
- Raw request/response

## Severity Justification
Bugcrowd will override your suggested severity if it doesn't match their
VRT. Justify with CVSS but expect them to recalibrate to their internal
priority levels.

## Remediation
[Fix recommendation]

---
*Bugcrowd researcher handle: grover*
EOF
        ;;

    yeswehack)
        cat > "$DRAFT" <<'EOF'
## Executive Summary
[1 paragraph — non-technical reader friendly. YesWeHack often forwards
to legal / compliance reviewers who aren't engineers.]

## Vulnerability Class
**OWASP Top 10 mapping:** [A01-Broken Access Control / A03-Injection / etc.]
**CWE:** CWE-XXX

## Technical Details
[Root cause analysis]

## Reproduction
1. [Step]
2. [Step]
3. [Step]

## Proof of Concept
```http
[request/response]
```

## Business Impact
[NARRATIVE — explain to a non-technical reader what could go wrong.
Frame in terms of customer trust, regulatory exposure, financial loss.]

## Technical Impact
[CVSS + privilege gained]

## Remediation
[Step-by-step fix]

## Country / Region Notes
[If the program scope restricts to specific countries, confirm your
testing source is compliant.]

---
*YesWeHack handle: grover*
EOF
        ;;

    synack)
        cat > "$DRAFT" <<'EOF'
**Synack Submission — Structured Fields**

```json
{
  "title":         "[VulnClass] in [asset] allows [impact]",
  "severity":      "TBD",
  "cvss_4_vector": "AV:N/...",
  "cvss_4_score":  0.0,
  "category":      "[Synack category code]",
  "asset":         "[URL / endpoint]",
  "cwe":           "CWE-XXX"
}
```

## Reproduction
1. [Step] — screenshot: rep-step-1.png
2. [Step] — screenshot: rep-step-2.png
3. [Step] — screenshot: rep-step-3.png

## Proof of Concept
```http
[request/response]
```

## Impact
[Specific attacker capability]

## Evidence Chain
sequential screenshots (must be numbered to match reproduction steps):
- rep-step-1.png
- rep-step-2.png
- rep-step-3.png
- evidence-traffic.har (full HAR capture)
- evidence-video.mp4 (if multi-step / race / DOM-based)

## Remediation
[Fix recommendation]

---
*Synack Red Team member: grover  |  Invitation verified*
EOF
        ;;

    *)
        echo "Unknown PLATFORM: $PLATFORM"
        echo "Supported: hackerone, intigriti, bugcrowd, yeswehack, synack"
        exit 2
        ;;
esac

# Pre-fill the title heuristically
sed -i "s|\[VulnClass\]|${VULN_CLASS}|g; s|\[asset\]|${TARGET}|g" "$DRAFT" 2>/dev/null || true

echo "draft created: $DRAFT"
echo ""
echo "next:"
echo "  1. fill in placeholders"
echo "  2. ./cvss-calc.sh  — compute CVSS 4.0 score"
echo "  3. ./evidence-pack.sh  — bundle screenshots + req/resp pairs"
echo "  4. ./dup-check.sh \"$VULN_CLASS\" \"$TARGET\"  — confirm no prior similar report"
