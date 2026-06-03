#!/usr/bin/env bash
# Phase 1 — passive subdomain enumeration.
#
# Composes the canonical merge: subfinder, amass -passive, assetfinder,
# findomain, github-subdomains, crt.sh, chaos. Each tool's output is
# anew-deduped into a single subs.txt; per-tool counts are logged so the
# operator can see which sources contributed.
#
# Inputs:  $TARGET (root domain)
# Outputs: $OUTDIR/subs.txt    — deduped subdomain master list
#          $OUTDIR/<tool>.txt  — per-tool raw output

PHASE="01-passive-enum"
. "$(dirname "$0")/_lib.sh"

require_target
OUTDIR=$(out_dir "$PHASE")
SUBS="$OUTDIR/subs.txt"
: > "$SUBS"

count_before=0
count_after() {
    local n
    n=$(wc -l < "$SUBS" 2>/dev/null || echo 0)
    local delta=$((n - count_before))
    count_before=$n
    echo "$delta"
}

# ── subfinder ─────────────────────────────────────────────────────
if command -v subfinder >/dev/null 2>&1; then
    log INFO "subfinder starting"
    subfinder -d "$TARGET" -all -recursive -silent -o "$OUTDIR/subfinder.txt" 2>/dev/null || true
    [ -f "$OUTDIR/subfinder.txt" ] && cat "$OUTDIR/subfinder.txt" | anew_or_tee "$SUBS" >/dev/null
    log INFO "subfinder → $(count_after) new"
else
    log WARN "subfinder not installed; skipping"
fi

# ── amass passive ─────────────────────────────────────────────────
if command -v amass >/dev/null 2>&1; then
    log INFO "amass -passive starting (may take 5+ min)"
    amass enum -passive -d "$TARGET" -o "$OUTDIR/amass.txt" 2>/dev/null || true
    [ -f "$OUTDIR/amass.txt" ] && cat "$OUTDIR/amass.txt" | anew_or_tee "$SUBS" >/dev/null
    log INFO "amass → $(count_after) new"
else
    log WARN "amass not installed; skipping"
fi

# ── assetfinder ───────────────────────────────────────────────────
if command -v assetfinder >/dev/null 2>&1; then
    log INFO "assetfinder starting"
    assetfinder --subs-only "$TARGET" 2>/dev/null > "$OUTDIR/assetfinder.txt" || true
    cat "$OUTDIR/assetfinder.txt" | anew_or_tee "$SUBS" >/dev/null
    log INFO "assetfinder → $(count_after) new"
else
    log WARN "assetfinder not installed; skipping"
fi

# ── findomain ─────────────────────────────────────────────────────
if command -v findomain >/dev/null 2>&1; then
    log INFO "findomain starting"
    findomain -t "$TARGET" -q 2>/dev/null > "$OUTDIR/findomain.txt" || true
    cat "$OUTDIR/findomain.txt" | anew_or_tee "$SUBS" >/dev/null
    log INFO "findomain → $(count_after) new"
else
    log WARN "findomain not installed; skipping"
fi

# ── github-subdomains ─────────────────────────────────────────────
if command -v github-subdomains >/dev/null 2>&1 && [ -n "${GITHUB_TOKEN:-}" ]; then
    log INFO "github-subdomains starting"
    github-subdomains -d "$TARGET" -t "$GITHUB_TOKEN" -e -raw -o "$OUTDIR/gh.txt" 2>/dev/null || true
    [ -f "$OUTDIR/gh.txt" ] && cat "$OUTDIR/gh.txt" | anew_or_tee "$SUBS" >/dev/null
    log INFO "github-subdomains → $(count_after) new"
else
    [ -z "${GITHUB_TOKEN:-}" ] && log WARN "GITHUB_TOKEN unset; skipping github-subdomains"
fi

# ── crt.sh (no binary needed) ─────────────────────────────────────
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    log INFO "crt.sh querying"
    curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' | sort -u > "$OUTDIR/crtsh.txt" || true
    cat "$OUTDIR/crtsh.txt" 2>/dev/null | anew_or_tee "$SUBS" >/dev/null
    log INFO "crt.sh → $(count_after) new"
fi

# ── chaos (PD bug-bounty DB) ──────────────────────────────────────
if command -v chaos >/dev/null 2>&1 && [ -n "${CHAOS_KEY:-}" ]; then
    log INFO "chaos starting"
    chaos -d "$TARGET" -silent -o "$OUTDIR/chaos.txt" 2>/dev/null || true
    [ -f "$OUTDIR/chaos.txt" ] && cat "$OUTDIR/chaos.txt" | anew_or_tee "$SUBS" >/dev/null
    log INFO "chaos → $(count_after) new"
fi

total=$(wc -l < "$SUBS" 2>/dev/null || echo 0)
log INFO "Phase 1 done — $total unique subdomains in $SUBS"
