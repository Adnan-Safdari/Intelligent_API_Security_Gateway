#!/usr/bin/env bash
# API flooding: send more requests than requests_per_minute (default 100).
# Expectation: every request is still forwarded (no 429).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_gateway

COUNT="${FLOOD_COUNT:-105}"
echo "Sending $COUNT GET requests to $GATEWAY_URL/ ..."

last_code=""
for i in $(seq 1 "$COUNT"); do
	last_code="$(curl_code "$GATEWAY_URL/")"
	assert_not_throttled "$last_code" "flood request $i"
done

pass "flood: $COUNT requests forwarded (last status $last_code). Check gateway logs for SECURITY ALERT: API FLOOD DETECTED"
