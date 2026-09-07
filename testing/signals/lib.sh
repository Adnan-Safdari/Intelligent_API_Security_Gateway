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
	local i code
	for i in $(seq 1 30); do
		if curl -sS -o /dev/null --connect-timeout 2 "$GATEWAY_URL/" >/dev/null 2>&1; then
			echo "Gateway: $GATEWAY_URL"
			return 0
		fi
		sleep 1
	done
	fail "gateway not reachable at $GATEWAY_URL after 30s (start Compose: docker compose -f infra/docker-compose.yml up -d, then wait until it prints 'Gateway starting')"
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

# ATTACK_IP, when set, drives the request as that address instead of the peer.
#
# The gateway believes X-Forwarded-For only from a configured trusted proxy, so
# this does nothing from an untrusted network -- which is the safe direction to
# fail. Unset, the behaviour is exactly what it was.
#
# Useful because policy/writer.py refuses to police private and loopback
# addresses: a detector script run from the host produces evidence that can
# never turn into a policy, and looks broken. ATTACK_IP=203.0.113.66 fixes that.
curl_code() {
	if [ -n "${ATTACK_IP:-}" ]; then
		curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 \
			-H "X-Forwarded-For: ${ATTACK_IP}" "$@"
	else
		curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 "$@"
	fi
}
