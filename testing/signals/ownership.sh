#!/usr/bin/env bash
# Ownership check (BOLA): the gateway refusing other customers' orders.
#
# The backend's GET /api/orders/{id} has the BOLA bug on purpose -- any logged-in
# user reads any order. Through the gateway, routes.ownership compares the
# order's owner with the user in jane's signed token, so:
#
#   - jane's own orders          200, unchanged
#   - everyone else's orders     404, and none of their data reaches the client
#   - her order list             only her orders
#   - a forged token (base64 id) 401, never reaching the backend
#
# BACKEND_URL, when set, repeats the walk straight against the backend to show
# the bug is still in the application: there, other customers' orders return 200.
#
# Evidence: ownership_violation in iasg:events and the console, and a
# "[ownership] refused" line in the gateway log for each refused read.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_gateway

ORDER_IDS="${ORDER_IDS:-30}"
xff=()
if [ -n "${ATTACK_IP:-}" ]; then
	xff=(-H "X-Forwarded-For: ${ATTACK_IP}")
fi

# ${xff[@]+...}: macOS bash 3.2 treats an empty array as unbound under set -u.
login="$(curl -sS --connect-timeout 5 ${xff[@]+"${xff[@]}"} -X POST "$GATEWAY_URL/api/login" \
	-H "Content-Type: application/json" \
	-d '{"email":"jane@example.com","password":"user123"}')"
user_id="$(printf '%s' "$login" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')"
token="$(printf '%s' "$login" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[ -n "$user_id" ] && [ -n "$token" ] || fail "login as jane failed (does the backend issue signed tokens?): $login"
echo "Logged in as jane (user $user_id)."

list="$(curl -sS --connect-timeout 5 ${xff[@]+"${xff[@]}"} -H "Authorization: Bearer $token" "$GATEWAY_URL/api/orders")"
foreign="$(printf '%s' "$list" | grep -o '"userId":[0-9]*' | grep -vc "\"userId\":$user_id$" || true)"
[ "$foreign" = "0" ] || fail "order list contains $foreign orders that are not jane's"
echo "Own order list: only jane's orders."

walk() {
	local base="$1" ok=0 refused=0 leaked=0 id code body
	for id in $(seq 1 "$ORDER_IDS"); do
		body="$(curl -sS --connect-timeout 5 ${xff[@]+"${xff[@]}"} -w '\n%{http_code}' \
			-H "Authorization: Bearer $token" "$base/api/orders/$id")"
		code="${body##*$'\n'}"
		assert_not_throttled "$code" "order $id"
		case "$code" in
		200)
			if printf '%s' "$body" | grep -q "\"userId\":$user_id[,}]"; then
				ok=$((ok + 1))
			else
				leaked=$((leaked + 1))
			fi
			;;
		*) refused=$((refused + 1)) ;;
		esac
	done
	echo "$ok $refused $leaked"
}

read -r own refused leaked <<<"$(walk "$GATEWAY_URL")"
echo "Gateway walk of /api/orders/1..$ORDER_IDS: $own own, $refused refused, $leaked other customers' orders returned."
[ "$leaked" = "0" ] || fail "the gateway returned $leaked orders belonging to other customers"
[ "$own" -gt 0 ] || fail "jane could not read any of her own orders"

forged="$(printf '%s' "$user_id" | base64)"
code="$(curl_code -H "Authorization: Bearer $forged" "$GATEWAY_URL/api/orders/1")"
[ "$code" = "401" ] || fail "a forged base64 token got $code, want 401"
echo "Forged token: 401."

if [ -n "${BACKEND_URL:-}" ]; then
	read -r own refused leaked <<<"$(walk "$BACKEND_URL")"
	echo "Direct to the backend (no gateway): $own own, $leaked other customers' orders returned -- the bug is still in the app."
fi

pass "ownership: no other customer's order left the gateway. Check iasg:events for ownership_violation"
