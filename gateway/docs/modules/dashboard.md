# Command Center Dashboard

## Overview

The operations console is a **Next.js 15** app in `gateway-dashboard/`, served
on <http://localhost:5177>. It is a single App Router application — not a
separate Express API plus React SPA.

It reads live state from Redis and the durable record from Postgres, and it is
the one place an operator can overrule the agent.

## Pages

The authenticated pages live in the `(console)` route group, which supplies the
shared shell:

| Route | File | Shows |
| --- | --- | --- |
| `/` | `app/(console)/page.jsx` | Overview: live traffic, stats, attack map |
| `/campaigns` | `app/(console)/campaigns/page.jsx` | Campaigns the control plane has formed |
| `/events` | `app/(console)/events/page.jsx` | The raw `iasg:events` stream |
| `/policy` | `app/(console)/policy/page.jsx` | Active `policy:<ip>` keys, and overrides |
| `/history` | `app/(console)/history/page.jsx` | Durable campaign history from Postgres |
| `/users` | `app/(console)/users/page.jsx` | Account administration |
| `/login`, `/setup` | `app/login/`, `app/setup/` | Outside the console shell |

## API routes

| Route | Purpose |
| --- | --- |
| `app/api/overview/route.js` | Live stats and events for the overview |
| `app/api/campaigns/route.js` | Active campaigns |
| `app/api/history/route.js` | Campaign history from Postgres |
| `app/api/overrides/route.js` | Operator instructions to the agent |
| `app/api/users/route.js`, `app/api/users/[id]/route.js` | Account management |
| `app/api/auth/login`, `logout`, `setup` | Session lifecycle |
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

## Accounts and roles

There is no seeded default account. On a database with no users, every route
redirects to `/setup` to create the first one.

Roles are ordered `viewer < operator < admin`, and anything that changes state
names the lowest role permitted to do it:

| Role | Can |
| --- | --- |
| `viewer` | Read every page |
| `operator` | Also issue overrides |
| `admin` | Also manage accounts |

Passwords are hashed with **scrypt** from the Node standard library
(`N=16384, r=8, p=1, keylen=64`) rather than a dependency. Sessions are stored
server-side in Postgres and carry an expiry.

To clear every account and return to the setup flow:

```bash
cd gateway-dashboard && npm run reset-accounts
```

That touches accounts only — campaigns, feedback, and policy all survive.

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
| `IASG_POSTGRES_URL` | Campaign history, accounts, sessions |

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
