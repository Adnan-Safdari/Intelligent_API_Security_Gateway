# Signal Test Scripts

Detector checks live **outside** the gateway Go module, next to JMeter:

```text
testing/
  jmeter/
  signals/
    lib.sh
    run_all.sh
    flood.sh
    sqli.sh
    traversal.sh
    brute_force.sh
    README.md
```

`gateway/internal/signals/` contains detector source only. No `*_test.go` files there.

## Why they are not in the gateway

The gateway package is production code: reverse proxy, middleware, detectors. Mixing Go `_test.go` files into `internal/signals` made it look like those scripts were part of the gateway.

These scripts:

- are not compiled into the gateway binary
- talk to a **running** gateway over HTTP (`localhost:8082`)
- fail if a detector starts enforcing (`429`)
- treat backend statuses (`200`, `401`, `404`) as normal

Proof of **detection** is the `SECURITY ALERT` line in the gateway logs, not a blocked HTTP response.

## How to run

Start the stack, then from the repository root:

```bash
docker compose -f infra/docker-compose.yml up -d

bash testing/signals/run_all.sh
```

One detector:

```bash
bash testing/signals/flood.sh
bash testing/signals/sqli.sh
bash testing/signals/traversal.sh
bash testing/signals/brute_force.sh
```

Override the target if needed:

```bash
GATEWAY_URL=http://localhost:8082 bash testing/signals/run_all.sh
```

## What each script does

| Script | Traffic | Pass condition | What to look for in gateway logs |
| --- | --- | --- | --- |
| `flood.sh` | 105 `GET /api/products` (above default 100/min) | no `429` | `SECURITY ALERT: API FLOOD DETECTED` |
| `sqli.sh` | Product search with normal input, then `' OR 1=1 --` in `q` | no detector-originated block | `SECURITY ALERT: SQL INJECTION DETECTED`; Dashboard → IP → SQL injection evidence |
| `traversal.sh` | bounded `demo-files` traversal, `/.env-demo`, both together | no `429` | `PATH TRAVERSAL` / `ENUMERATION ATTACK` |
| `brute_force.sh` | 8 `POST /api/login` with wrong passwords | no `429` (backend `401` is OK) | `SECURITY ALERT: BRUTE FORCE DETECTED` |

`lib.sh` holds `GATEWAY_URL`, `require_gateway`, and `assert_not_throttled`.

## What these scripts cannot check

`Metrics(ip)` is an in-process Go method, read by the collector and the reflex. HTTP scripts cannot read `Evidence` structs. They only prove the live middleware still **forwards** attack traffic.

JMeter plans stay in `testing/jmeter/` for heavier demo runs.
