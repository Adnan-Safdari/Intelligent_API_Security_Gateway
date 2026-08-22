# Command Center Dashboard

## Overview

The operations console is a **Next.js 15** app in `gateway-dashboard/`, served
on <http://localhost:5177>. It is a single App Router application — not a
separate Express API plus React SPA.

It reads live state from Redis and the durable record from Postgres, and it is
the one place an operator can overrule the agent.

## Pages

The pages live in the `(console)` route group, which supplies the shared shell.
The console runs open -- there is no login -- so whoever can reach the port can
use every control on it:

| Route | File | Shows |
| --- | --- | --- |
| `/` | `app/(console)/page.jsx` | Overview: live traffic, stats, attack map |
| `/campaigns` | `app/(console)/campaigns/page.jsx` | Campaigns the control plane has formed |
| `/events` | `app/(console)/events/page.jsx` | The raw `iasg:events` stream |
| `/policy` | `app/(console)/policy/page.jsx` | Active `policy:<ip>` keys, and overrides |
| `/history` | `app/(console)/history/page.jsx` | Durable campaign history from Postgres |
| `/settings` | `app/(console)/settings/page.jsx` | Live enforcement settings |

## API routes

| Route | Purpose |
| --- | --- |
| `app/api/overview/route.js` | Live stats and events for the overview |
| `app/api/campaigns/route.js` | Active campaigns |
| `app/api/history/route.js` | Campaign history from Postgres |
| `app/api/overrides/route.js` | Operator instructions to the agent |
| `app/api/settings/route.js` | Read, change and revert the live enforcement settings |
| `app/api/admin/reset/route.js` | Clear the history and live telemetry |
| `app/api/health/route.js` | Liveness |

## Shared modules

| Path | Role |
| --- | --- |
| `app/ui/chrome.jsx` | Console shell and page headers |
| `app/ui/parts.jsx` | Shared presentational pieces |
| `app/ui/store.jsx` | Client-side polling provider |
| `app/ui/format.js` | Formatting helpers |
| `app/traffic-map.jsx` | Geographic plot of source addresses |
| `lib/redis.js` | Redis client |
| `lib/postgres.js` | Postgres pool |
| `lib/telemetry.js` | Reads the event stream and stats |
| `lib/geo.js` | Address to coordinates |
| `lib/auth.js` | Password hashing, sessions, RBAC |

## Settings

`/settings` changes what the running gateway detects and blocks, without a
restart. Two Redis keys carry it:

| Key | Written by | Holds |
| --- | --- | --- |
| `iasg:settings` | The console | The override that was asked for |
| `iasg:settings:effective` | The gateway | What it is actually enforcing |

The page reads the **effective** key, never the requested one. The gateway
validates independently and can refuse a change -- a duration that will not
parse, a CIDR that will not -- and when it does, the two keys disagree.
Building the form from the request would tell an operator their change was live
when it was not.

`Revert to file` deletes the override, and the gateway returns to exactly the
settings it booted with. The YAML file stays the source of truth: the override
is a layer on top of it, not a replacement for it.

Only the `enforcement` block travels this way. Listen address, backend URL,
timeouts and the Redis connection are structural -- changing them means
rebuilding the server -- so they stay in the file, where a restart applies them.

Both actions are typed confirmations rather than plain buttons, for the same
reason the reset is: the console is open, and these change what a security
gateway is doing to live traffic.

## Overrides

An operator's instruction is written to the `iasg_overrides` stream and read by
the control plane **before** it decides anything, so a human does not have to
wait for the agent to notice a campaign first.

Overrides still pass through the same simulation and safety checks as the
agent's own decisions, so an allowlisted range is protected from a mistyped
instruction exactly as it is from the agent. Policy written this way is
recorded with `source: human`.

## Environment

| Variable | Purpose |
| --- | --- |
| `REDIS_HOST`, `REDIS_PORT` | Live panels |
| `IASG_POSTGRES_URL` | Campaign history |

## Running it

Under Compose it starts automatically. Standalone:

```bash
cd gateway-dashboard
npm ci
npm run dev      # next dev -H 0.0.0.0 -p 5177
npm start        # production build on the same port
```

The map plots public source addresses; private and container traffic is drawn
at the gateway site instead. On Docker Desktop, host-originated traffic all
arrives as one address — see the warning in
[Running with Docker](../running-with-docker.md).
