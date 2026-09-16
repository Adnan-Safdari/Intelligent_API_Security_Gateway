# Signal detector test scripts

These scripts live **outside** the gateway Go module. They hit a running gateway over HTTP. They are not compiled into the gateway binary.

```text
testing/
  jmeter/                 # JMeter demo plans
  signals/                # detector test scripts (this folder)
    lib.sh
    run_all.sh
    flood.sh
    sqli.sh
    traversal.sh
    brute_force.sh
    object_enumeration.sh
    redis_inspect.sh
```

There is currently no script here for `unknown_route_scanning`, the newest
detector — a real gap, not a design choice.

## Prerequisites

Gateway must already be running (Compose or `go run ./cmd/server`):

```bash
cd infra
docker compose up -d
```

Default target: `http://localhost:8082`

```bash
export GATEWAY_URL=http://localhost:8082   # optional
```

## Run

From the repository root:

```bash
bash testing/signals/run_all.sh
```

Or one detector:

```bash
bash testing/signals/flood.sh
bash testing/signals/sqli.sh
bash testing/signals/traversal.sh
bash testing/signals/brute_force.sh
bash testing/signals/object_enumeration.sh
ORDER_ROUTE=orders-secure bash testing/signals/object_enumeration.sh
```

Watch the **gateway process logs** for `SECURITY ALERT` — this applies to
`flood.sh`, `sqli.sh`, and `traversal.sh`. `brute_force.sh` is the exception:
`brute_force.go` is advisory-only and evidence-only, and logs nothing at all
(so is `object_enumeration.sh`'s detector),
so its proof of detection is `Metrics(ip)` surfaced through the dashboard or
`iasg:events`, not a log line. Every script's real pass condition is still
that the request was **forwarded** (no `429`).

## What “pass” means

Detectors are detect-only. Scripts fail if the gateway returns `429 Too Many Requests`. Backend codes such as `200`, `401`, or `404` are success for these scripts. The flood script hits the successful `/api/products` endpoint; traversal uses the isolated `demo-files` fixtures and enumeration uses `/.env-demo`, all of which are safe demo data.

`Metrics()` is an in-process Go API. These HTTP scripts cannot read it; they only exercise the live middleware path.
