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
| `gateway-dashboard/` | Next.js operations console |
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
| Dashboard | http://localhost:5177 |
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
- Checks the response is safe before writing it — allowlisted and shared ranges are
  protected, and a standing policy is never traded for a weaker one
- Takes instructions from a human, and learns from being overruled

An LLM writes the human-readable incident note and nothing else. It runs *after* the
decision is made and written, so a hallucinated or prompt-injected note can mislead a
reader but cannot change enforcement. It is optional — the default provider is an offline
template.

## Durable memory

Without Postgres, campaigns live in Redis under a 24-hour TTL, so restarting the machine
loses every investigation in progress. With it, they survive:

```bash
cd control-plane
.venv/bin/python -m pip install -e ".[postgres]"

export IASG_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg
.venv/bin/python -m iasg --once      # prints: [postgres] campaigns and feedback are durable
```

Compose already passes this, so `docker compose up` needs no extra step.

What moves and what does not:

| | Where | Why |
|---|---|---|
| Campaigns, feedback tallies | Postgres, mirrored to Redis | Postgres is the record. Redis keeps a copy because the dashboard reads it, exactly as the gateway does |
| `policy:<ip>` | Redis | The gateway reads it on the hot path, and it is *meant* to expire |
| Evidence, alerts, overrides | Redis streams | Transport. Once correlated, it is done |

The mirror is a projection, not a second source of truth: it may expire, and the agent
rebuilds it from Postgres on startup, so a wiped Redis costs a cycle rather than an
investigation.

Campaigns are never deleted, but only the last 24 hours are offered to the correlator, so
switching stores does not change which campaigns a cycle can merge into. The rest is
history you can query:

```sql
SELECT type, count(*), round(avg(confidence)::numeric, 2) AS avg_confidence
  FROM campaigns GROUP BY type ORDER BY count DESC;
```

Everything degrades: no driver, no database, or a database that is down means the agent
says so once and carries on with Redis.

## Signing in

The console can change enforcement, so it requires an account. On first run every page
redirects to `/setup` to create the administrator; that page closes permanently once one
exists.

| Role | May |
|---|---|
| `viewer` | Read every page. No action buttons, and the server refuses the write anyway |
| `operator` | Instruct the agent — monitor, throttle, temp block, escalate |
| `admin` | Everything, plus adding, disabling and removing accounts |

Roles are checked server-side on every write. Hiding a button is presentation; the check
in the route handler is the authorisation.

Accounts live in Postgres alongside campaigns, so **the console needs `IASG_POSTGRES_URL`**
— without a durable store there is nowhere to keep them, and it refuses to start rather
than run unauthenticated.

Details worth knowing:

- Passwords are hashed with scrypt (`N=16384, r=8, p=1`) and a per-password salt, using
  Node's standard library rather than a dependency. The parameters are stored with the
  hash so they can be raised later without invalidating anyone's password.
- Sessions are random 256-bit tokens in an `httpOnly`, `SameSite=Lax` cookie. Only the
  SHA-256 of the token is stored, so a database leak cannot be replayed as a live session.
- Ten failed attempts locks a username for fifteen minutes. A console that detects brute
  force should not be trivially brute forced.
- Wrong password and unknown user return the same message after the same amount of work.
- Disabling an account, changing its password, or signing out revokes the sessions
  immediately rather than waiting for them to expire.
- The last enabled admin cannot be deleted, demoted or disabled.
- Overrides record the actor from the session, never from the request body.

## Testing

```bash
cd gateway && go test ./...
cd control-plane && .venv/bin/python -m pytest
```

The Postgres tests are skipped unless you point them at a database they may write to —
they truncate tables, so never aim this at anything that matters:

```bash
createdb iasg_test    # once -- the tests truncate, so never the live database

IASG_TEST_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg_test \
    .venv/bin/python -m pytest tests/test_postgres.py
```

## Not built yet

Honest about the gaps, since the config file implies more than exists:

- **Trust engine** — `trust_engine` in `gateway/configs/config.yaml` is parsed but not
  used. Nothing scores requests by trust today; the detectors and the control plane decide.
Postgres was on this list until campaigns and feedback were moved into it. See
**Durable memory** above.

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
