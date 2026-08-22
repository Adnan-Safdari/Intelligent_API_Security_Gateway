# Gateway — the data plane

A Go reverse proxy that sits in front of the backend API. Every request passes through it,
so its budget is microseconds: it detects, it enforces a cached decision, and it gets out
of the way.

It never waits on Redis, never waits on the control plane, and never waits on a model.

## What it does, in order

1. Resolve the real client IP — from `X-Forwarded-For`, but only when the immediate peer
   is a configured trusted proxy, so the header cannot be spoofed to frame another address
2. Run the detectors over the request
3. Look up `policy:<ip>` in a background-refreshed snapshot and allow, slow or block
4. Proxy to the backend
5. Publish what happened to `iasg:events` for the control plane to correlate

Steps 3 and 5 are the two halves of the split: the gateway *reads* a decision it did not
make, and *writes* evidence it does not interpret.

## Layout

| Path | What it is |
|---|---|
| `cmd/server/` | Entry point |
| `internal/config/` | YAML + env configuration |
| `internal/proxy/` | Reverse proxy, middleware chain, server |
| `internal/signals/` | The detectors, and the evidence they emit |
| `internal/policy/` | Reads `policy:<ip>`, caches it, enforces the action |
| `internal/netutil/` | Client IP resolution |
| `internal/storage/redis/` | Stream and key access |
| `internal/telemetry/` | Per-request records for the dashboard |

## Detectors

| File | Catches |
|---|---|
| `brute_force.go` | Repeated failed logins against one account |
| `api_flooding.go` | Request volume from one address |
| `sqli_injection.go` | Injection patterns in query, body and headers |
| `enumeration_path_traversal.go` | Directory walking and resource enumeration |

Each one emits `Evidence` onto `iasg:events`. They score and report; they do not decide
what to do about it. That is the control plane's job, and keeping it there is what lets
the detectors stay fast.

## Running it

```bash
cp configs/config.yaml.example configs/config.yaml
go mod download
go run ./cmd/server
```

Listens on `:8082` and proxies to `proxy.backend_url` (`http://localhost:5002` by default,
which is the deliberately vulnerable app).

Environment overrides, used by Compose:

| Variable | Overrides |
|---|---|
| `IASG_CONFIG` | Path to the config file |
| `IASG_BACKEND_URL` | `proxy.backend_url` |
| `IASG_REDIS_HOST` | `storage.redis.host` |

## Enforcement

The control plane writes `policy:<ip>` keys with a TTL. This side reads them from a
snapshot refreshed in the background, so:

- The request path does no Redis I/O
- A dead Redis means "no policy", never added latency
- An action the gateway does not recognise fails open

Actions are `monitor`, `throttle`, `temp_block` and `escalate`. See
[`internal/policy/store.go`](internal/policy/store.go) for the JSON contract, which is
written by `PolicyDecision.to_json` on the Python side.

## Testing

```bash
go test ./...
```

For traffic that exercises the detectors end to end, the shell scripts in
[`../testing/`](../testing/) hit a running gateway over HTTP.

## No separate trust engine

There is no central trust-scoring component, and no `trust_engine` block in
`configs/config.yaml` any more. It was parsed into structs that nothing read, so it has
been removed rather than left advertising a component that does not exist.

Every decision is made by the parts that already hold the evidence: each detector scores
what it sees, [`internal/enforcement`](internal/enforcement/) acts on a threshold cross
immediately, and the control plane re-decides off-path with the wider view.

## Documentation

- [Client IP resolution](docs/client-ip.md)
- [Reverse proxy logic](docs/reverse-proxy-logic.md)
- [Request lifecycle](docs/request-lifecycle.md)
- [System architecture](docs/system-architecture.md)
- [Project structure](docs/project-structure.md)
- [Running locally](docs/running-locally.md)
