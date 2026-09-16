#!/usr/bin/env bash
# Object ID enumeration (BOLA): a logged-in user counting through order ids.
#
# Logs in as jane, reads her own order list the normal way, then requests
# /api/orders/1..N -- most of which belong to other customers. The vulnerable
# route answers 200 with their data; ORDER_ROUTE=orders-secure answers 404 for
# every order that is not hers, which scores higher (refused lookups).
#
# Expectation: every request is forwarded (no 429); the gateway records
# object_enumeration once ORDER_IDS reaches distinct_ids (20 by default).
# Detection is advisory-only: look for it in iasg:events or the console's
# Events page, not in the gateway log.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_gateway

ORDER_IDS="${ORDER_IDS:-30}"
ORDER_ROUTE="${ORDER_ROUTE:-orders}"
xff=()
if [ -n "${ATTACK_IP:-}" ]; then
	xff=(-H "X-Forwarded-For: ${ATTACK_IP}")
fi

# ${xff[@]+...}: macOS bash 3.2 treats an empty array as unbound under set -u.
login="$(curl -sS --connect-timeout 5 ${xff[@]+"${xff[@]}"} -X POST "$GATEWAY_URL/api/login" \
	-H "Content-Type: application/json" \
	-d '{"email":"jane@example.com","password":"user123"}')"
user_id="$(printf '%s' "$login" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"
[ -n "$user_id" ] || fail "login as jane failed: $login"
token="$(printf '%s' "$user_id" | base64)"
echo "Logged in as jane (user $user_id)."

code="$(curl_code -H "Authorization: Bearer $token" "$GATEWAY_URL/api/orders")"
assert_not_throttled "$code" "own order list"
echo "Own order list: $code"

echo "Requesting /api/$ORDER_ROUTE/1..$ORDER_IDS ..."
readable=0
refused=0
for id in $(seq 1 "$ORDER_IDS"); do
	code="$(curl_code -H "Authorization: Bearer $token" "$GATEWAY_URL/api/$ORDER_ROUTE/$id")"
	assert_not_throttled "$code" "order $id"
	case "$code" in
	200) readable=$((readable + 1)) ;;
	*) refused=$((refused + 1)) ;;
	esac
done

pass "object_enumeration: $ORDER_IDS order ids forwarded on /api/$ORDER_ROUTE ($readable readable, $refused refused). Check iasg:events for object_enumeration"
