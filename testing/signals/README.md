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
```

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
```

Watch the **gateway process logs** for `SECURITY ALERT`. A passing script only proves the request was **forwarded** (no `429`). The alert text is the proof of detection.

## What “pass” means

Detectors are detect-only. Scripts fail if the gateway returns `429 Too Many Requests`. Backend codes such as `200`, `401`, or `404` are success for these scripts. The flood script hits the successful `/api/products` endpoint; traversal uses the isolated `demo-files` fixtures and enumeration uses `/.env-demo`, all of which are safe demo data.

`Metrics()` is an in-process Go API. These HTTP scripts cannot read it; they only exercise the live middleware path.
