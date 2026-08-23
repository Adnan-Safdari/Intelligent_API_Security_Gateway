#!/usr/bin/env bash
# SQL injection on the intentionally vulnerable product search endpoint.
# Expectation: request is forwarded (no detector-originated 403). Evidence
# appears in gateway logs and in Dashboard -> IP -> SQL injection evidence.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_gateway

normal_code="$(curl_code "$GATEWAY_URL/api/products/search?q=keyboard")"
assert_not_throttled "$normal_code" "Normal product search"

query_code="$(curl_code -G "$GATEWAY_URL/api/products/search" \
	--data-urlencode "q=' OR 1=1 --")"
assert_not_throttled "$query_code" "SQLi product search"

pass "sqli: normal status $normal_code, SQLi status $query_code. Check Dashboard -> IP -> SQL injection evidence."
