# Intelligent API Security Gateway

An API gateway that detects attacks in the request path and decides what to do about them
out of it — a fast Go proxy that enforces, and a Python agent that watches, correlates and
adapts.

## How it works

Two lanes, deliberately separate.

```
                    ┌──────────────────────────────────────────┐
   request ────────▶│  Go gateway (data plane)                 │────▶ backend API
                    │  detect · check policy · allow/slow/block │
                    └───────────────┬──────────────────────────┘
                                    │ evidence            ▲ policy:<ip>
                                    ▼                     │
                    ┌──────────────────────────────────────────┐
                    │  Redis                                   │
                    └───────────────┬──────────────────────────┘
                                    │                     ▲
                                    ▼                     │
                    ┌──────────────────────────────────────────┐
                    │  Python control plane (every 30s)        │
                    │  correlate · remember · decide · explain  │
                    └──────────────────────────────────────────┘
```

The **gateway** handles every request and must be fast, so it only ever reads a cached
answer — never waits on Redis, never waits on the agent, never waits on a model.

The **control plane** never touches a live request. It reads what the detectors saw, groups
it into attack campaigns, decides enforcement, and writes it back as `policy:<ip>` keys
with a TTL.

Stop the control plane and the gateway keeps serving traffic exactly as before. That
independence is the point of the split.

## Layout

| Path | What it is |
|---|---|
| `gateway/` | Go reverse proxy, detectors, policy enforcement |
| `control-plane/` | Python agent — correlation, policy, narration |
| `vulnerable-app/` | Deliberately insecure API to attack |
| `gateway-dashboard/` | Web UI (`api/` + `web/`) |
| `infra/` | Docker Compose for everything |
| `testing/` | Load and attack scripts |

## Prerequisites

- Docker and Docker Compose
- Go 1.22.2+ and Python 3.11+ for local development
- Redis (via Compose, or `brew install redis`)

## Quick start

### Everything at once

```bash
docker compose -f infra/docker-compose.yml up -d
docker ps
```

Ports:

| Service | URL |
|---|---|
| Gateway | http://localhost:8082 |
| Vulnerable API | http://localhost:5002 |
| Vulnerable web | http://localhost:5175 |
| Dashboard API | http://localhost:4004 |
| Dashboard web | http://localhost:5177 |
| Docs | http://localhost:8000 |
| Redis | localhost:6379 |

### Gateway only

```bash
cd gateway
cp configs/config.yaml.example configs/config.yaml
go mod download
go run ./cmd/server
```

### Control plane only

Needs Redis running; nothing else.

```bash
cd control-plane
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

.venv/bin/python -m iasg --once     # one cycle
.venv/bin/python -m iasg            # every 30s
.venv/bin/python -m iasg --dry-run  # decide everything, write nothing
```

Every setting has a working default, so that runs with no configuration at all.
`control-plane/.env.example` documents the `IASG_*` variables and what they do — they are
read from the environment, so export the ones you want to change rather than copying the
file:

```bash
IASG_LLM_PROVIDER=ollama .venv/bin/python -m iasg --once
```

## See it work without an attacker

The seeder writes realistic attack evidence straight into Redis, so the whole pipeline is
demonstrable in a second:

```bash
cd control-plane
.venv/bin/python -m tools.seed_evidence --scenario credential-stuffing
.venv/bin/python -m iasg --once

redis-cli KEYS 'policy:*'
redis-cli GET policy:203.0.113.5
```

Scenarios: `credential-stuffing`, `brute-force`, `flood`, `enumeration`, `path-traversal`,
`recon`, `sqli`, `mixed`, and `noise` — which must *not* form a campaign.

## What each side does

**Gateway (Go)**

- Reverse proxy to the backend
- Detectors: brute force, API flooding, SQL injection, enumeration and path traversal
- Resolves the real client IP from `X-Forwarded-For`, but only from proxies configured as
  trusted, so the header cannot be spoofed to frame another address
- Reads `policy:<ip>` from a background-refreshed snapshot, so the request path does no
  Redis I/O. A dead Redis means "no policy", never added latency. Unknown actions fail open

**Control plane (Python)**

- Groups IPs into campaigns by shared behaviour — subnet, user agent, endpoint, detector,
  timing
- Remembers campaigns between cycles, and keeps tracking one after the attacker moves to
  addresses never seen before
- Notices whether acting worked, and answers an action that failed with a stronger one
- Reads several attack phases from one actor as one intrusion rather than separate attacks
- Writes `monitor` / `throttle` / `temp_block` / `escalate`, always by rule

An LLM writes the human-readable incident note and nothing else. It runs *after* the
decision is made and written, so a hallucinated or prompt-injected note can mislead a
reader but cannot change enforcement. It is optional — the default provider is an offline
template.

## Testing

```bash
cd gateway && go test ./...
cd control-plane && .venv/bin/pytest
```

## Not built yet

Honest about the gaps, since the config file implies more than exists:

- **Trust engine** — `trust_engine` in `gateway/configs/config.yaml` is parsed but not
  used. Nothing scores requests by trust today; the detectors and the control plane decide.
- **Postgres** — configured and running in Compose, but the control plane persists
  campaigns in Redis. Not yet wired up.

## Documentation

- [Client IP resolution](gateway/docs/client-ip.md)
- [Reverse proxy logic](gateway/docs/reverse-proxy-logic.md)
- [Request lifecycle](gateway/docs/request-lifecycle.md)
- [System architecture](gateway/docs/system-architecture.md)
- [Project structure](gateway/docs/project-structure.md)
- [Control plane README](control-plane/README.md) and [guide](control-plane/GUIDE.md)
- [Demo walkthrough](DEMO.md)

## Stopping

```bash
docker compose -f infra/docker-compose.yml down
```
