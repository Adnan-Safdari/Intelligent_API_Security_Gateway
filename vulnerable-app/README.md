# Vulnerable app — the target

A deliberately insecure API and a small front end for it. It exists only so the gateway has a safe, local target to detect.

> **Do not deploy this anywhere.** The intentionally unsafe routes are isolated to demo tables with fictional data and must only run on a machine you control.

## Endpoints

| Method | Path | What it does |
|---|---|---|
| `POST` | `/api/login` | Parameterized login; it remains the brute-force demo target. |
| `GET` | `/api/products` | Successful product-list endpoint for the flood demo. |
| `GET` | `/api/products/search?q=<query>` | Intentionally vulnerable product search for the SQLi demo only. |
| `GET` | `/api/products/search-secure?q=<query>` | Parameterized comparison route. |
| `GET` | `/backup-demo`, `/config-demo`, `/.env-demo` | Harmless planted resources for forced-browsing enumeration. |
| `GET` | `/api/demo-files?file=<relative-path>` | Deliberately permissive, but filesystem-bounded traversal demonstration. |
| `GET` | `/api/orders` | The caller's own orders. |
| `GET` | `/api/orders/:id` | Intentionally vulnerable to BOLA / IDOR: returns any customer's order. |
| `GET` | `/api/orders-secure/:id` | Ownership-checked comparison route: someone else's order is `404`. |

## SQL injection demo

There are no runtime authentication modes and no `/api/set-mode` endpoint. Login always uses a parameterized query, which keeps its failed-login behavior predictable for the brute-force demo. The only intentional SQL injection surface is `/api/products/search`.

Normal input returns the matching demo products:

```bash
curl 'http://localhost:5002/api/products/search?q=keyboard'
```

The direct SQLi demonstration makes the database-only consequence visible:

```bash
curl -G 'http://localhost:5002/api/products/search' \
  --data-urlencode "q=' OR 1=1 --"
```

The unsafe `WHERE name ILIKE '%<input>%'` query is changed by the payload and returns the demo catalogue. No secrets, host files, or command execution are exposed. The optional `search-secure` route retains the same input as a parameter and does not change its query semantics.

Repeat the same payload through IASG to create telemetry evidence:

```bash
curl -G 'http://localhost:8082/api/products/search' \
  --data-urlencode "q=' OR 1=1 --"
```

The detector records SQL Injection evidence and forwards the request. Open **Dashboard → IP address → SQL injection evidence** to see the timestamp, endpoint, matched patterns, risk, request ID, HTTP result, and separate gateway decision. Detection is not a claim that the request was blocked; later control-plane policy may throttle or block it.

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

For the SQLi story, use :5002 first to demonstrate the isolated vulnerable endpoint, then repeat the exact request through :8082. Direct traffic intentionally bypasses the gateway; only traffic through :8082 appears in telemetry and the dashboard.

## Tests

```bash
cd vulnerable-app/backend && npm test
cd gateway && go test ./...
```

The shared scripts can also drive a running gateway:

```bash
bash testing/signals/sqli.sh
```

## Other direct-backend demonstrations

`GET /api/products` is a normal successful endpoint, so a direct burst to
`:5002` reaches the application unrestricted. `POST /api/login` intentionally
has no native IP lockout: repeated invalid attempts and attempts against the
seeded demo usernames are normal `401` responses for brute-force and
password-spraying demonstrations.

The planted forced-browsing resources return explicit harmless markers, not
configuration or secrets:

```bash
curl 'http://localhost:5002/.env-demo'
```

The bounded traversal route deliberately resolves relative paths inside
`backend/demo-files` only. This demonstrates a relative-path mistake without
ever exposing container or host files:

```bash
curl -G 'http://localhost:5002/api/demo-files' \
  --data-urlencode 'file=public/../fake-secret.txt'
```

It can return the static `fake-secret.txt` fixture, but a path that resolves
outside `demo-files` is rejected. Use the same requests through `:8082` to
produce traversal/enumeration evidence in IASG.

The signal scripts exercise every direct-demo counterpart through IASG:

```bash
bash testing/signals/sqli.sh
bash testing/signals/flood.sh
bash testing/signals/traversal.sh
bash testing/signals/brute_force.sh
```

## BOLA (object-level authorization) demo

`/api/orders/:id` checks that the caller is logged in and never that the order
is theirs. The SQL is parameterized: this is an authorization bug, not an
injection one. The 40 seeded orders are fictional, and owners are interleaved,
so counting through ids reaches other customers.

The caller is identified by `Authorization: Bearer <base64 user id>`, the same
demo token the storefront makes after login. Jane is usually user 2:

```bash
curl -s http://localhost:5002/api/login -H 'Content-Type: application/json' \
  -d '{"email":"jane@example.com","password":"user123"}'   # note "id"
TOKEN=$(printf 2 | base64)

curl -s http://localhost:5002/api/orders -H "Authorization: Bearer $TOKEN"        # her orders
curl -s http://localhost:5002/api/orders/2 -H "Authorization: Bearer $TOKEN"      # someone else's: 200
curl -s http://localhost:5002/api/orders-secure/2 -H "Authorization: Bearer $TOKEN"  # 404
```

Through IASG, counting through ids records `object_enumeration` evidence once
one client reaches 20 distinct ids in five minutes:

```bash
ATTACK_IP=203.0.113.81 bash testing/signals/object_enumeration.sh
ATTACK_IP=203.0.113.82 ORDER_ROUTE=orders-secure bash testing/signals/object_enumeration.sh
```

The gateway cannot see who owns an order, so it detects the harvesting pattern,
not the authorization failure. The fix is the ownership check `orders-secure`
already has.
