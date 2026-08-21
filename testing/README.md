# Testing — attacking your own gateway

Everything here is a *client*. It sends real traffic to a running gateway over HTTP and
watches what the system does about it. None of it is compiled into the gateway or imported
by the control plane, and none of it is a substitute for the unit tests
(`cd gateway && go test ./...`, `cd control-plane && .venv/bin/python -m pytest`).

```text
testing/
  signals/     shell scripts, one per detector
  jmeter/      load-shaped attacks
```

## Prerequisites

A gateway on `:8082` with somewhere to send traffic:

```bash
docker compose -f infra/docker-compose.yml up -d
```

## Shell scripts

```bash
bash testing/signals/run_all.sh        # every detector in sequence
bash testing/signals/brute_force.sh    # or one at a time
bash testing/signals/flood.sh
bash testing/signals/sqli.sh
bash testing/signals/traversal.sh

bash testing/signals/redis_inspect.sh  # what landed in Redis
```

See [`signals/README.md`](signals/README.md) for what each one sends and what it should
trigger.

## JMeter

`jmeter/brute_force_demo.jmx` drives a credential attack with `passwords.csv` as its word
list — useful when you want sustained volume rather than a script's burst. Open it in the
JMeter GUI, or run it headless:

```bash
jmeter -n -t testing/jmeter/brute_force_demo.jmx
```

## Seeding instead of attacking

If you only need the *control plane* to have something to reason about, the seeder writes
realistic evidence straight into Redis and skips the traffic entirely:

```bash
cd control-plane
.venv/bin/python -m tools.seed_evidence --scenario credential-stuffing
.venv/bin/python -m iasg --once
```

That is the faster path for demonstrating correlation, policy and the console. These
scripts are the slower, more honest one: they prove the *detectors* fire, which seeding
assumes.

Scenarios: `credential-stuffing`, `brute-force`, `flood`, `enumeration`, `path-traversal`,
`recon`, `sqli`, `mixed`, and `noise` — which must **not** form a campaign, and is the
most useful one to run when you want to know the correlator is not simply agreeing with
everything.

## What to watch while they run

| Where | Shows |
|---|---|
| Gateway logs | Detectors firing, in real time |
| `http://localhost:5177` | The console — events, then campaigns, then policy |
| `redis-cli KEYS 'policy:*'` | What the agent decided to enforce |
| Control plane logs | The correlation and the reasoning behind each action |

The interesting gap is the one between a detector firing and a campaign forming: the
gateway reacts within a request, and the agent takes up to a cycle. Watching both at once
is the clearest way to see why the system is split in two.
