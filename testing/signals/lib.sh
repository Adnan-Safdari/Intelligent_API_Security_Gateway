# Shared helpers for detector test scripts.
# Usage: GATEWAY_URL=http://localhost:8082 bash run_all.sh

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8082}"

pass() {
	echo "PASS: $*"
}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

require_gateway() {
	if ! curl -sS -o /dev/null --connect-timeout 2 "$GATEWAY_URL/" >/dev/null 2>&1; then
		fail "gateway not reachable at $GATEWAY_URL (start Compose: docker compose -f infra/docker-compose.yml up -d)"
	fi
	echo "Gateway: $GATEWAY_URL"
}

# Detectors must not enforce. 429 means the gateway throttled; that is a failure.
# Other codes (200, 401, 404, 500) come from the backend and are allowed.
assert_not_throttled() {
	local code="$1"
	local label="$2"
	if [ "$code" = "429" ]; then
		fail "$label returned 429 — detectors must only detect, not throttle"
	fi
	if [ "$code" = "000" ]; then
		fail "$label: connection failed"
	fi
}

curl_code() {
	curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 "$@"
}
