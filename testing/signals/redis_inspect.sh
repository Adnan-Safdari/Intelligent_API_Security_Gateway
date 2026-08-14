#!/usr/bin/env bash
# Show recent Redis telemetry written by the gateway.
set -euo pipefail

REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"

if ! command -v redis-cli >/dev/null 2>&1; then
	echo "redis-cli not found. Install Redis CLI or run: docker compose -f infra/docker-compose.yml exec redis redis-cli" >&2
	exit 1
fi

echo "=== stats ==="
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HGETALL iasg:stats
echo
echo "=== top attackers ==="
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZREVRANGE iasg:attackers 0 9 WITHSCORES
echo
echo "=== last 5 events ==="
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" XREVRANGE iasg:events + - COUNT 5
