# Vulnerable app — the target

A deliberately insecure API and a small front end for it. It exists to be attacked, so
that the gateway in front of it has something real to detect.

> **Do not deploy this anywhere.** It stores passwords in plain text and will happily
> concatenate your input into SQL. That is the point. Run it on a machine you control,
> behind the gateway, and nowhere else.

## Layout

```text
vulnerable-app/
  backend/          Express API on :5002
    routes/auth.js  login, and the switch between auth modes
    data/           in-memory users, plain text on purpose
    middleware/     request logging
  src/              Vite + React front end on :5175
```

## Endpoints

| Method | Path | What it does |
|---|---|---|
| `POST` | `/login` | Authenticates, in whichever mode is active |
| `POST` | `/set-mode` | Switches auth mode at runtime, without a restart |

## The three auth modes

`AUTH_MODE` decides how a login is checked, and each mode fails differently. Being able to
switch between them live is what makes this useful for a demo: the *same* attack produces
a different outcome, and the gateway's detection should not care which mode is running.

| Mode | Behaviour |
|---|---|
| `memory` | Checks the in-memory user list. Plain text comparison, no database |
| `db_vulnerable` | Builds SQL by string concatenation — injectable, on purpose |
| `db_secure` | Parameterised queries. Injection fails; brute force still works |

Set it at start:

```bash
AUTH_MODE=db_vulnerable npm start
```

or flip it while running:

```bash
curl -X POST http://localhost:5002/set-mode \
  -H 'Content-Type: application/json' -d '{"mode":"db_secure"}'
```

`db_secure` is the Compose default, so the stack starts in the mode where SQL injection
is *not* the easy win and the brute force detector has to earn its keep.

## Running it

Through Compose, with the gateway in front of it:

```bash
docker compose -f infra/docker-compose.yml up -d
```

| | URL |
|---|---|
| Direct (unprotected) | http://localhost:5002 |
| Through the gateway | http://localhost:8082 |
| Front end | http://localhost:5175 |

Standalone, for working on the app itself:

```bash
cd vulnerable-app/backend && npm install && npm start
cd vulnerable-app && npm install && npm run dev
```

**Attack it through :8082, not :5002.** Hitting the backend directly bypasses the gateway
entirely, so nothing is detected and the console stays empty — which looks like a broken
detector rather than a bypassed one. If a demo produces no events, this is the first thing
to check.

## Attacking it

The scripts in [`../testing/`](../testing/) drive every detector:

```bash
bash testing/signals/run_all.sh
```

`../testing/jmeter/brute_force_demo.jmx` provides sustained volume with a password list,
which is closer to what a real credential attack looks like than a shell loop.

## Further reading

[`walkthrough.md`](walkthrough.md) goes through the backend's deliberate weaknesses one at
a time, with the code that causes each.
