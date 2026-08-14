# Redis Telemetry

The gateway writes one **security event** per request to Redis. This is the hot store for the dashboard and the later isolated agent. Full history still belongs in Postgres (not implemented yet).

## What is stored

Redis is a **capped live window**, not an archive of every request forever.

| Key | Type | Purpose |
| --- | --- | --- |
| `iasg:events` | stream (`MAXLEN` ≈ 2000) | Recent events as JSON |
| `iasg:stats` | hash | Counters: `requests`, `alerts`, `decision:allow`, `signal:*` |
| `iasg:attackers` | sorted set | IP → alert count (top attackers) |
| `iasg:ip:{ip}:latest` | string JSON, TTL 24h | Last event for that IP |

Event payload (field `event` on the stream):

```json
{
  "requestId": "a1b2c3d4e5f60708",
  "ts": "2026-08-14T10:00:00Z",
  "ip": "10.0.0.2",
  "method": "POST",
  "path": "/api/login",
  "query": "",
  "status": 401,
  "userAgent": "...",
  "decision": "allow",
  "riskScore": 70,
  "fired": ["brute_force"],
  "signals": [ { "signal": "brute_force", "score": 70, "thresholdCross": true, "details": {} } ],
  "snippet": "{\"email\":\"admin\",\"password\":\"[redacted]\"}",
  "backendMs": 12
}
```

Passwords and token-like JSON fields are redacted. Bodies are truncated to 512 bytes. `decision` is `allow` unless the optional policy enforcer applied `throttle`, `temp_block`, or `escalate`. `riskScore` is the sum of detector `Metrics()` scores.

The Python control plane consumes this same stream (`IASG_EVIDENCE_STREAM=iasg:events`). Clean requests are ignored; each fired signal becomes one Evidence record. Policy keys are written separately as `policy:<ip>` and do not collide with `iasg:*`.

If Redis is down, the gateway still proxies. It logs `redis telemetry write failed` and continues.

## Config

`configs/config.yaml`:

```yaml
storage:
  redis:
    enabled: true
    host: localhost
    port: 6379
    stream_key: iasg:events
    stream_maxlen: 2000
    ip_latest_ttl: 24h
```

Docker Compose sets `IASG_REDIS_HOST=redis` so the gateway container talks to the Redis service.

## How it is wired

Outermost middleware: `internal/telemetry`. After flood, SQLi, traversal, and brute force (including backend status), it calls `Collector.Snapshot(ip)` and writes the event.

Code:

- `internal/telemetry/` — event shape, redaction, middleware
- `internal/storage/redis/` — stream / stats / per-IP writes

## Inspect locally

With Compose Redis on `localhost:6379`:

```bash
bash testing/signals/redis_inspect.sh
```

Or:

```bash
redis-cli XREVRANGE iasg:events + - COUNT 5
redis-cli HGETALL iasg:stats
redis-cli ZREVRANGE iasg:attackers 0 9 WITHSCORES
```
