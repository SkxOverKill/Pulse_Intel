#!/usr/bin/env bash
# Download indicators from Pulse Intelligence into common analyst formats
# using a scoped read-only API key.
#
# Usage:
#   bash examples/curl/export_indicators.sh csv  > pulse-indicators.csv
#   bash examples/curl/export_indicators.sh stix > pulse-indicators.stix.json
#   bash examples/curl/export_indicators.sh json | jq '.data | length'
#
# Requires PULSE_BASE_URL and PULSE_API_KEY in the environment. Create the key
# in the app under /settings with only the `indicators:read` scope.

set -euo pipefail

BASE_URL="${PULSE_BASE_URL:?set PULSE_BASE_URL to your Pulse Intelligence host}"
API_KEY="${PULSE_API_KEY:?set PULSE_API_KEY to a scoped indicators:read key}"
FORMAT="${1:-csv}"

case "$FORMAT" in
  csv|stix|misp|snort|json) ;;
  *) echo "unknown format: $FORMAT (use csv, stix, misp, snort or json)" >&2; exit 1 ;;
esac

# Non-JSON formats are full-set exports (capped server-side at 50,000 rows);
# json is paginated and defaults to 100 rows per page.
curl -fsS \
  -H "Authorization: Bearer ${API_KEY}" \
  -G "${BASE_URL%/}/api/v1/indicators" \
  --data-urlencode "format=${FORMAT}" \
  --data-urlencode "severity=HIGH"
