# Dashboard — the operations console

A Next.js app that reads what the gateway saw, shows what the agent concluded, and lets a
person argue with it. UI and API routes in one process.

Runs on **http://localhost:5177**.

## Pages

| Page | Answers |
|---|---|
| `/` | What does the traffic look like right now |
| `/campaigns` | What did the agent correlate, and what did it decide |
| `/policy` | What is being enforced, and how do I change it |
| `/events` | What actually happened, request by request |
| `/history` | What keeps happening to us, across restarts |
| `/users` | Who can reach this console (admins only) |

They are linked rather than merely separate: an address anywhere opens its own events, a
signal opens the events that fired it, and a metric tile opens the page behind it.

## Where the data comes from

| Source | Written by | Shows as |
|---|---|---|
| `iasg:stats`, `iasg:events`, `iasg:attackers` | Go gateway | Metrics, map, signals, event stream |
| `campaign:*`, `policy:*`, `feedback:*`, `iasg_alerts` | Control plane | Campaigns, policy, escalations, learning |
| `iasg:heartbeat` | Control plane | Whether the agent is alive |
| `campaigns` table (Postgres) | Control plane | History that survives a restart |
| `iasg_overrides` | **This console** | Instructions to the agent |

The gateway's counters only exist while the gateway is running. When they are absent —
seeded evidence, a replay — the metrics fall back to the visible event window and say so,
rather than reporting zero above a screen full of attacks.

## Accounts

The console can change enforcement, so it requires a login. First run redirects to
`/setup` to create an administrator; that page closes for good once one exists.

| Role | May |
|---|---|
| `viewer` | Read everything |
| `operator` | Instruct the agent |
| `admin` | Everything, plus managing accounts |

Roles are checked in the route handlers on every write. The hidden button is presentation;
the check on the server is the authorisation. See the root
[README](../README.md#signing-in) for the hashing, session and lockout details.

## Writing is instructing, not enforcing

Nothing here writes a policy key. Every action appends to `iasg_overrides`, and the
control plane applies it on its next cycle **after** the same allowlist and collateral
checks its own decisions face. Two consequences worth knowing:

- The toast says *"applies next cycle"* because that is true, and the UI should not imply
  an address is already blocked.
- `monitor` stops future enforcement rather than clearing a block that is already
  standing; that expires on its own TTL. There is no release button, because the control
  plane has no release operation.

The actor recorded against an override comes from the session, never from the request
body — an actor the caller can choose is not an audit trail.

## Running it

```bash
cd gateway-dashboard
npm install

export IASG_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg
REDIS_HOST=127.0.0.1 npm run dev
```

| Variable | Default | For |
|---|---|---|
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6379` | Everything live |
| `IASG_POSTGRES_URL` | — | Accounts, and campaign history |

**Postgres is required.** Accounts have to live somewhere durable, and the console refuses
to start rather than run unauthenticated. Without it you get an explanatory page, not a
broken one.

Under Compose both are set for you:

```bash
docker compose -f infra/docker-compose.yml up -d gateway_dashboard
```

For traffic to look at: `bash testing/signals/run_all.sh`, or seed the control plane
directly with `python -m tools.seed_evidence --scenario mixed`.

## Layout

```text
app/
  (console)/        signed-in pages; its layout is the gate
    layout.js       redirects to /setup or /login before rendering anything
  login/ setup/     outside the shell -- no session to poll with
  api/              overview, campaigns, history, overrides, auth, users
  ui/
    store.jsx       one poller for the whole console, above the router
    chrome.jsx      header, nav, status line, toasts
    parts.jsx       cards, tables and action rows shared between pages
    format.js       pure helpers: labels, tones, filters
lib/
  redis.js  postgres.js  auth.js  telemetry.js  geo.js
```

Polling lives in `LiveProvider`, above the router, so moving between pages neither
restarts the clock nor blanks the screen, and Pause stops every page at once.

## One thing that leaves the machine

`lib/geo.js` calls `ip-api.com` over plain HTTP to place public addresses on the map. It
is cached, has a short timeout, and degrades to no marker — but it does send attacker IP
addresses to a third party, and looks up this host's own public IP for the "gateway site"
marker. With no internet the rest of the console is unaffected.
