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
    object_enumeration.sh
    ownership.sh
    redis_inspect.sh
    README.md
```

`gateway/internal/signals/` also has Go unit tests beside every detector
(`api_flooding_test.go`, `brute_force_test.go`, `sqli_injection_test.go`,
`enumeration_path_traversal_test.go`, `unknown_route_scanning_test.go`,
`object_enumeration_test.go`,
`ip_reputation_test.go`, `collector_test.go`, and more) — these scripts exist
for a different reason than "Go tests aren't allowed in that package."

There is currently no script here for `unknown_route_scanning`, the newest
detector — a real gap, not a design choice.

## Why they exist as a separate layer

The Go tests above verify the detector logic in isolation. These scripts
verify something a unit test cannot: that a **running** gateway, wired
through its real middleware chain and real config, actually produces the
evidence and logs a real HTTP client should see. That's an end-to-end check,
not a substitute for the Go tests.

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
| `brute_force.sh` | 8 `POST /api/login` with wrong passwords | no `429` (backend `401` is OK) | Nothing is logged — `brute_force.go` is evidence-only and advisory; check `Metrics(ip)` via the dashboard or `iasg:events` instead |

`lib.sh` holds `GATEWAY_URL`, `require_gateway`, and `assert_not_throttled`.

## What these scripts cannot check

`Metrics(ip)` is an in-process Go method, read by the collector and the reflex. HTTP scripts cannot read `Evidence` structs. They only prove the live middleware still **forwards** attack traffic.

JMeter plans stay in `testing/jmeter/` for heavier demo runs.
