#!/usr/bin/env bash
# Path traversal and forced-browsing enumeration.
# Expectation: request is forwarded (no 429). Alert appears in gateway logs.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_gateway

trav_code="$(curl_code "$GATEWAY_URL/api/demo-files?file=public%2F..%2Ffake-secret.txt")"
assert_not_throttled "$trav_code" "path traversal"

enum_code="$(curl_code "$GATEWAY_URL/.env-demo")"
assert_not_throttled "$enum_code" "enumeration"

both_code="$(curl_code "$GATEWAY_URL/.env-demo?file=public%2F..%2Ffake-config.txt")"
assert_not_throttled "$both_code" "traversal+enumeration"

pass "traversal/enum: traversal=$trav_code enum=$enum_code both=$both_code. Check gateway logs for PATH TRAVERSAL / ENUMERATION ATTACK"
