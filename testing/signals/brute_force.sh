#!/usr/bin/env bash
# Brute force: repeated failed logins on /api/login.
# Expectation: backend 401/403 is fine; gateway must not return 429.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_gateway

ATTEMPTS="${BRUTE_ATTEMPTS:-8}"
echo "Sending $ATTEMPTS failed logins to $GATEWAY_URL/api/login ..."

last_code=""
for i in $(seq 1 "$ATTEMPTS"); do
	last_code="$(curl_code -X POST "$GATEWAY_URL/api/login" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"admin\",\"password\":\"wrong$i\"}")"
	assert_not_throttled "$last_code" "brute force attempt $i"
done

pass "brute_force: $ATTEMPTS attempts forwarded (last status $last_code). Check gateway logs for SECURITY ALERT: BRUTE FORCE DETECTED"
