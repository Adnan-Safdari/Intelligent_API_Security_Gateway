# Project Structure

## Overview

The repository holds four runnable components plus shared infrastructure. The
Go gateway is one of them, not the whole system.

## Top level

| Path | Role |
| --- | --- |
| `gateway/` | The Go data plane and this documentation |
| `control-plane/` | The Python agent. See [Control Plane](control-plane.md) |
| `gateway-dashboard/` | Next.js operations console |
| `vulnerable-app/` | Deliberately weak API and front end, used as the protected backend |
| `datasets/` | Captured traffic, frozen and versioned, used to train and evaluate the anomaly model — not a runnable component |
| `models/` | Trained model artifacts read by the control plane's `ModelScorer` — not a runnable component |
| `testing/signals/` | Shell scripts that drive a running gateway |
| `testing/traffic/` | Python harness that generates the labelled traffic behind `datasets/` |
| `testing/jmeter/` | JMeter plans for load and enforcement demos |
| `infra/` | Compose stack. See [Running with Docker](running-with-docker.md) |
| `mkdocs.yml` | Documentation config; `docs_dir` points at `gateway/docs` |

## Inside the gateway

| Path | Role |
| --- | --- |
| `cmd/server/` | Entrypoint; loads config, applies env overrides, starts the server |
| `internal/config/` | YAML schema, defaults, and validation |
| `internal/proxy/` | Server, middleware chain, reverse proxy |
| `internal/netutil/` | Client IP resolution and the trusted-proxy rules |
| `internal/signals/` | The six detectors, evidence, collector, evidence store |
| `internal/telemetry/` | Event shape, redaction, and the recording middleware |
| `internal/policy/` | Policy snapshot store, the enforcing middleware, the rate limiter |
| `internal/enforcement/` | The gateway's own reflex: block on a threshold cross |
| `internal/reputation/` | The known-bad list: load, refresh, look up |
| `internal/settings/` | Live reconfiguration over Redis, from the console |
| `internal/storage/redis/` | Redis telemetry writer |
| `configs/` | `config.yaml` and `config.yaml.example` |
| `docs/` | This documentation |

Enforcement is split on purpose. `internal/policy` acts on decisions the
control plane wrote and holds the per-address rate limiter;
`internal/enforcement` is the gateway's own reflex, for a threshold cross too
fast to wait a full agent cycle for.

There is no trust-scoring package. `internal/trust/` and the `trust_engine`
config block were both removed: the block was parsed into structs nothing read,
so it advertised a component that did not exist.

## Tests

Every package that makes a decision has tests beside it — every `internal/`
subpackage carries at least one `*_test.go` file, and the list changes often
enough that it isn't itemized here:

```bash
find gateway -name '*_test.go'
```

```bash
cd gateway && go test ./...
cd control-plane && .venv/bin/python -m pytest
```

## Repository map

```text
.
├── gateway/
│   ├── cmd/server/main.go
│   ├── configs/
│   │   ├── config.yaml
│   │   └── config.yaml.example
│   ├── docs/                     # this site
│   │   ├── assets/
│   │   ├── stylesheets/extra.css
│   │   ├── modules/
│   │   └── requirements.txt
│   ├── internal/
│   │   ├── config/
│   │   ├── enforcement/
│   │   ├── netutil/
│   │   ├── policy/
│   │   ├── proxy/
│   │   ├── reputation/
│   │   ├── settings/
│   │   ├── signals/
│   │   ├── storage/redis/
│   │   └── telemetry/
│   └── go.mod
├── control-plane/
│   ├── iasg/
│   │   ├── adaptive/    anomaly/    assessment/  campaigns/  correlation/
│   │   ├── dataset/     evidence/   explanation/ feedback/   ml/
│   │   ├── policy/      reasoning/  store/
│   │   ├── config.py  models.py  runner.py  alerts.py
│   │   └── __main__.py
│   ├── tools/seed_evidence.py
│   └── tests/
├── gateway-dashboard/
│   ├── app/
│   │   ├── (console)/            # overview, campaigns, events, history, ip, policy, settings, adaptive, signals
│   │   ├── api/
│   │   ├── ui/
│   │   └── globals.css
│   └── lib/                      # redis, postgres, geo, telemetry, plane, adaptive (login removed; auth.js is a stub)
├── vulnerable-app/
│   └── backend/
├── datasets/
│   └── v1/  v2/  v3/  v4/  part5-fresh/    # each frozen and versioned; see datasets/README.md
├── models/
│   └── v2-iforest/  v3-iforest/  v4-iforest/  ...   # trained artifacts, one directory per model
├── testing/
│   ├── signals/
│   │   ├── lib.sh  run_all.sh
│   │   ├── brute_force.sh  sqli.sh  flood.sh  traversal.sh
│   │   └── redis_inspect.sh
│   ├── traffic/                  # generates the labelled traffic behind datasets/
│   └── jmeter/                   # load and enforcement demo plans
├── infra/
│   ├── docker-compose.yml
│   └── README.md
└── mkdocs.yml
```

## How the pieces connect

```mermaid
flowchart TD
    VW[vulnerable-app front end] --> GW[gateway]
    GW --> VA[vulnerable-app backend]
    GW -->|events| R[(Redis)]
    R --> CP[control-plane]
    CP -->|policy| R
    R --> GW
    CP --> PG[(Postgres)]
    PG --> D[gateway-dashboard]
    R --> D
    TS[testing/signals] --> GW
```
