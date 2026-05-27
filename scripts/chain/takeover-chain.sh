#!/usr/bin/env bash
# chain/takeover-chain.sh
#
# Subdomain takeover + cookie scope = session hijack.
#
# Premise: target sets cookies with Domain=.target.com. If any subdomain
# of target.com is takeover-vulnerable (dangling GitHub Pages / Heroku /
# S3 / Azure / Fastly CNAME), the attacker can serve content from that
# subdomain that reads / writes those cookies — full session hijack.

PHASE="chain-takeover"
. "$(dirname "$0")/../vuln/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

SUBS="${SUBS:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/01-passive-enum/subs.txt}"
ALIVE="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/05-http-probe/alive.txt"

[ ! -s "$SUBS" ] && { log ERR "no subdomains; run recon first"; exit 5; }

# Step 1: Use nuclei takeover templates against the full subdomain set
log INFO "step 1: nuclei subdomain takeover sweep"
if command -v nuclei >/dev/null 2>&1; then
    nuclei -l "$SUBS" -tags takeover -severity high,critical \
        -rl "$RATE_LIMIT_RPS" -c 5 \
        -jsonl -o "$OUTDIR/takeover-candidates.jsonl" 2>/dev/null || true
    n=$(wc -l < "$OUTDIR/takeover-candidates.jsonl" 2>/dev/null || echo 0)
    log INFO "  $n takeover candidates"
fi

# Step 2: cookie-scope reconnaissance — find cookies set with Domain=.target.com
log INFO "step 2: harvesting cookie scopes from live hosts"
: > "$OUTDIR/cookie-scopes.txt"
if [ -s "$ALIVE" ]; then
    head -30 "$ALIVE" | while read -r host; do
        curl -sI --max-time 8 "$host" 2>/dev/null \
            | grep -i '^set-cookie' \
            | grep -iE "domain=\.?$TARGET" \
            | while read -r line; do
                echo "$host | $line" >> "$OUTDIR/cookie-scopes.txt"
            done
    done
fi
n_cookies=$(wc -l < "$OUTDIR/cookie-scopes.txt")
log INFO "  $n_cookies cookies scoped to .$TARGET — these are hijack-relevant"

# Step 3: pair takeover candidates with cookie scope
if [ -s "$OUTDIR/takeover-candidates.jsonl" ] && [ "$n_cookies" -gt 0 ]; then
    log INFO "step 3: CHAIN PRE-CONDITIONS MET"
    log INFO "  takeover hosts:"
    jq -r '.host' "$OUTDIR/takeover-candidates.jsonl" 2>/dev/null | sed 's/^/    /'
    log INFO "  parent-domain cookies:"
    head -10 "$OUTDIR/cookie-scopes.txt" | sed 's/^/    /'
    log INFO "  next: claim ONE of the dangling resources (e.g. spin up GitHub Pages site)"
    log INFO "        and host content that reads document.cookie via JS"
    {
        echo "# Takeover + session-hijack chain"
        echo ""
        echo "## Takeover candidates"
        jq -r '"- " + .host + " (" + .info.name + ")"' "$OUTDIR/takeover-candidates.jsonl" 2>/dev/null
        echo ""
        echo "## Cookies scoped to .${TARGET}"
        sed 's/^/- /' "$OUTDIR/cookie-scopes.txt"
        echo ""
        echo "## Impact"
        echo "Any of the takeover candidates can be claimed to serve JS that reads the"
        echo "above cookies (HttpOnly cookies are exempt; check Set-Cookie attrs)."
    } > "$OUTDIR/CHAIN-REPORT.md"
    log INFO "  → report draft at $OUTDIR/CHAIN-REPORT.md"
else
    log INFO "chain pre-conditions not met (need both takeover + parent-domain cookie)"
fi
