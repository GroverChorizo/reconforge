#!/usr/bin/env bash
# vuln/xss-deep.sh — XSS deep dive (DOM + reflected + stored + CSP gap).
#
# Builds on recon/15-xss-targeted (which gets the easy reflectors) by
# adding DOM-source mining and CSP analysis.

PHASE="xss-deep"
. "$(dirname "$0")/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

URLS_FILE=$(resolve_urls_input)
if [ -z "$URLS_FILE" ]; then
    log ERR "no URL corpus; run recon/06 + recon/09 first"
    exit 5
fi

# 1. CSP audit per alive host — find weak directives that turn a reflected
#    into a working alert(1) or a stored into an admin-takeover
if command -v curl >/dev/null 2>&1; then
    log INFO "CSP audit on alive hosts"
    ALIVE="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/05-http-probe/alive.txt"
    : > "$OUTDIR/csp-audit.txt"
    if [ -s "$ALIVE" ]; then
        while read -r host; do
            csp=$(curl -sI --max-time 8 "$host" 2>/dev/null \
                | tr -d '\r' \
                | awk -F': ' 'tolower($1) == "content-security-policy" {print $2}')
            if [ -n "$csp" ]; then
                weak=""
                echo "$csp" | grep -qiE "unsafe-inline" && weak="${weak}inline"
                echo "$csp" | grep -qiE "unsafe-eval"   && weak="${weak},eval"
                echo "$csp" | grep -qiE "data:"         && weak="${weak},data:"
                echo "$csp" | grep -qiE "\*"            && weak="${weak},wildcard"
                # Check for permissive CDN allowlist (common bypass surface)
                echo "$csp" | grep -qiE "jsdelivr|unpkg|cdnjs" && weak="${weak},cdn-allowlist"
                if [ -n "$weak" ]; then
                    echo "$host | WEAK:${weak#,} | $csp" >> "$OUTDIR/csp-audit.txt"
                fi
            else
                echo "$host | NO-CSP" >> "$OUTDIR/csp-audit.txt"
            fi
        done < "$ALIVE"
    fi
    log INFO "CSP audit → $(wc -l < "$OUTDIR/csp-audit.txt" 2>/dev/null || echo 0) hosts with weak/missing CSP"
fi

# 2. DOM-source mining via jsluice (find document.write / innerHTML sinks)
if command -v jsluice >/dev/null 2>&1; then
    log INFO "DOM-sink mining in JS bodies"
    JS_DIR="$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/07-js-analyze/js-bodies"
    if [ -d "$JS_DIR" ]; then
        : > "$OUTDIR/dom-sinks.txt"
        for f in "$JS_DIR"/*.js; do
            [ -f "$f" ] || continue
            # Custom jsluice query for sink-like nodes
            jsluice query -q '(call_expression
                                 function: (member_expression
                                              property: (property_identifier) @prop
                                              (#match? @prop "innerHTML|outerHTML|insertAdjacentHTML|write|writeln|eval")))' "$f" 2>/dev/null \
                | head -50 >> "$OUTDIR/dom-sinks.txt" || true
        done
    fi
fi

# 3. dalfox deep mode — DOM XSS + parameter mining
if command -v dalfox >/dev/null 2>&1; then
    log INFO "dalfox --mining-dom --deep-domxss on top 20 URLs"
    head -20 "$URLS_FILE" | while read -r u; do
        dalfox url "$u" --mining-dom --deep-domxss --silence 2>/dev/null \
            >> "$OUTDIR/dalfox-dom.txt" || true
    done
fi

# 4. Stored-XSS candidate hunt — endpoints that *take* input and *render*
#    it elsewhere. POST endpoints with `comment`, `message`, `note`,
#    `bio` in the path are the high-value targets.
log INFO "stored-XSS candidate selection"
grep -iE '(comment|message|note|bio|profile|feedback|review|description|chat|post)' "$URLS_FILE" \
    | sort -u > "$OUTDIR/stored-candidates.txt"
log INFO "  $(wc -l < "$OUTDIR/stored-candidates.txt") stored-XSS candidate endpoints"

log INFO "xss-deep done — review $OUTDIR/{csp-audit,dom-sinks,dalfox-dom,stored-candidates}.txt"
