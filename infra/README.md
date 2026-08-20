# Infra — everything at once

One Compose file brings up the whole system: the gateway, the agent, the target it
protects, the console, and the two stores they share.

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml logs -f control_plane
```

## Services

| Service | Port | What it is |
|---|---|---|
| `gateway` | 8082 | Go reverse proxy — the data plane |
| `control_plane` | — | Python agent, no HTTP port. Correlates and decides |
| `vulnerable_api` | 5002 | The deliberately insecure API being protected |
| `vulnerable_web` | 5175 | Its front end |
| `gateway_dashboard` | 5177 | Next.js operations console |
| `postgres` | 5434 | Durable campaign memory and console accounts |
| `vulnerable_postgres` | 5435 | The vulnerable app's own database, kept separate |
| `redis` | 6379 | Evidence stream, policy keys, telemetry |
| `docs` | 8000 | MkDocs site |
| `ports_info` | — | Prints the port map and exits |

`ports_info` runs once and stops. Compose reporting it as exited is expected.

## The two databases

They are deliberately separate. `postgres` holds what the security system knows;
`vulnerable_postgres` holds the target application's data. An SQL injection demo that
reached the security system's own campaign history would be a very different demo from the
one intended.

## Persistence

Both databases and Redis use named volumes, and Redis runs with `--appendonly yes`, so a
`docker compose down` and back up keeps campaigns, accounts and evidence.

`docker compose down -v` removes the volumes and everything in them, including the console
accounts — you will be sent back to `/setup` on the next start.

## Configuration

Every service has a working default. Override by putting an `.env` beside the Compose file:

```bash
POSTGRES_USER=iasg_user
POSTGRES_PASSWORD=change-me-before-anyone-else-uses-this
POSTGRES_DB=iasg

VULN_POSTGRES_USER=vuln_user
VULN_POSTGRES_PASSWORD=vuln_changeme
VULN_POSTGRES_DB=vuln_app
```

The compose file is the only place these are read; `control_plane` and
`gateway_dashboard` are handed `IASG_POSTGRES_URL` built from them.

The control plane's own settings are documented in
[`../control-plane/.env.example`](../control-plane/.env.example) and read from the
environment, so add them to the `control_plane` service rather than copying that file.

## Ordering

`gateway` and `control_plane` wait for Redis and Postgres to pass their health checks
before starting, so a cold `up` does not race the stores. The gateway does not wait for
the control plane, and never should — that independence is the point of the split, and
Compose is where it would be easiest to accidentally undo.

## Stopping

```bash
docker compose -f infra/docker-compose.yml down      # keeps the data
docker compose -f infra/docker-compose.yml down -v   # deletes it
```
