#!/usr/bin/env bash
# SQL injection signatures in body and query string.
# Expectation: request is forwarded (no 429). Alert appears in gateway logs.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_gateway

body_code="$(curl_code -X POST "$GATEWAY_URL/api/search" \
	-H "Content-Type: application/json" \
	-d '{"q":"UNION SELECT"}')"
assert_not_throttled "$body_code" "SQLi body"

query_code="$(curl_code "$GATEWAY_URL/api/items?id=UNION")"
assert_not_throttled "$query_code" "SQLi query"

pass "sqli: body status $body_code, query status $query_code. Check gateway logs for SECURITY ALERT: SQL INJECTION DETECTED"
