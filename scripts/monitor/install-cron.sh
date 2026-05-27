#!/usr/bin/env bash
# scripts/monitor/install-cron.sh — wire continuous-enum + template-watcher
# into the user's crontab for one or more targets.
#
# Usage:
#   ./install-cron.sh acme.com               # hourly enum, daily templates
#   ./install-cron.sh acme.com bcde.com      # multiple targets
#   ./install-cron.sh --uninstall acme.com   # remove entries for a target
#
# Conservative defaults:
#   continuous-enum.sh   → every hour
#   template-watcher.sh  → every 6 hours
# Tune by editing the CRON_ENUM / CRON_WATCH constants below.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CRON_TAG="reconforge-monitor"

CRON_ENUM="0 * * * *"        # every hour, on the hour
CRON_WATCH="15 */6 * * *"    # every 6 hours, at :15

usage() {
    grep '^# ' "$0" | sed 's/^# //'
    exit 1
}

UNINSTALL=0
if [ "${1:-}" = "--uninstall" ]; then
    UNINSTALL=1
    shift
fi

[ $# -eq 0 ] && usage

current=$(crontab -l 2>/dev/null || true)

# Strip any existing tagged lines for the targets we're touching
filtered="$current"
for t in "$@"; do
    filtered=$(echo "$filtered" | grep -v "$CRON_TAG TARGET=$t " || true)
done

if [ "$UNINSTALL" -eq 1 ]; then
    echo "$filtered" | crontab -
    echo "removed cron entries for: $*"
    exit 0
fi

# Add fresh entries
new=$(echo "$filtered" | grep -v '^$' || true)
for t in "$@"; do
    new=$(printf '%s\n%s TARGET=%s %s/continuous-enum.sh\n%s TARGET=%s %s/template-watcher.sh\n' \
        "$new" \
        "$CRON_ENUM"  "$t" "$HERE" \
        "$CRON_WATCH" "$t" "$HERE")
    # Tag for later cleanup. cron doesn't preserve comments inline so we
    # append the tag as a trailing comment on each line.
    new=$(echo "$new" | sed "s|$HERE/continuous-enum.sh|$HERE/continuous-enum.sh # $CRON_TAG TARGET=$t enum|;
                              s|$HERE/template-watcher.sh|$HERE/template-watcher.sh # $CRON_TAG TARGET=$t watch|")
done

echo "$new" | crontab -

echo "installed cron entries for: $*"
echo
echo "current crontab:"
crontab -l | grep "$CRON_TAG" || true
echo
echo "logs land under: \$MONITOR_STATE/<target>/log"
echo "default \$MONITOR_STATE = ~/.local/share/reconforge/monitor"
