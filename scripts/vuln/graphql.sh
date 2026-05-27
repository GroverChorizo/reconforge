#!/usr/bin/env bash
# vuln/graphql.sh — full GraphQL probe chain.
#
# Pipeline:
#   1. graphw00f — fingerprint the engine (Apollo, Hasura, etc.)
#   2. Try introspection
#   3. If introspection off → clairvoyance field-suggestion schema rebuild
#   4. InQL query/mutation enumeration
#   5. Alias-DoS probe (50 aliased __typename in one request)

PHASE="graphql"
. "$(dirname "$0")/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

# Target should be the full GraphQL endpoint URL
GQL_URL="${GQL_URL:-https://$TARGET/graphql}"

log INFO "target endpoint: $GQL_URL"

# 1. Fingerprint
if command -v graphw00f >/dev/null 2>&1; then
    log INFO "graphw00f fingerprint"
    graphw00f -t "$GQL_URL" -d 2>/dev/null > "$OUTDIR/fingerprint.txt" || true
fi

# 2. Introspection probe
log INFO "introspection probe"
curl -sS -X POST "$GQL_URL" \
    -H 'Content-Type: application/json' \
    --max-time 10 \
    -d '{"query":"{__schema{types{name fields{name}}}}"}' \
    > "$OUTDIR/introspection.json" 2>/dev/null || true

if grep -q '"__schema"' "$OUTDIR/introspection.json" 2>/dev/null; then
    log INFO "INTROSPECTION IS ON — schema dumped to $OUTDIR/introspection.json"
    SCHEMA_LIVE=1
else
    log INFO "introspection disabled — falling back to clairvoyance"
    SCHEMA_LIVE=0
fi

# 3. clairvoyance fallback (only when introspection is off)
if [ "$SCHEMA_LIVE" -eq 0 ] && command -v clairvoyance >/dev/null 2>&1; then
    log INFO "clairvoyance schema reconstruction (slow)"
    clairvoyance "$GQL_URL" -o "$OUTDIR/clairvoyance-schema.json" 2>/dev/null || true
fi

# 4. InQL enumeration
if command -v inql >/dev/null 2>&1; then
    log INFO "inql query/mutation enum"
    inql -t "$GQL_URL" 2>/dev/null > "$OUTDIR/inql.txt" || true
fi

# 5. Alias-DoS test (50 aliased __typename calls in one request)
log INFO "alias-batching probe"
ALIAS_QUERY=$(python3 -c 'print("{" + " ".join(f"a{i}:__typename" for i in range(50)) + "}")')
start=$(date +%s%3N)
curl -sS -X POST "$GQL_URL" \
    -H 'Content-Type: application/json' \
    --max-time 30 \
    -d "{\"query\":\"$ALIAS_QUERY\"}" \
    > "$OUTDIR/alias-response.json" 2>/dev/null || true
end=$(date +%s%3N)
dur=$((end - start))
size=$(wc -c < "$OUTDIR/alias-response.json" 2>/dev/null || echo 0)
log INFO "alias probe: $dur ms / $size bytes — high size suggests batch accepted"

# 6. Common-mutation enumeration (post-schema, if we got one)
if [ "$SCHEMA_LIVE" -eq 1 ] && command -v jq >/dev/null 2>&1; then
    log INFO "extracting mutation names"
    jq -r '.data.__schema.types[]?
            | select(.name=="Mutation")
            | .fields[]?.name' "$OUTDIR/introspection.json" 2>/dev/null \
        > "$OUTDIR/mutations.txt" || true
    log INFO "  $(wc -l < "$OUTDIR/mutations.txt" 2>/dev/null || echo 0) mutation names extracted"
    log INFO "  next: check each for ownership-enforcement (IDOR via mutation is gold)"
fi

log INFO "graphql done — review $OUTDIR/{introspection,clairvoyance-schema,inql,mutations}.*"
