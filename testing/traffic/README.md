# Traffic harness

Generates the traffic an anomaly dataset is built from: benign personas and
attack scenarios, driven from documentation addresses, with labels written
before a single request is sent.

Stdlib only, apart from `redis` for the pre-flight check.

## Running one collection run

```bash
IASG_CONFIG=configs/config.collect.yaml \
  docker compose -f infra/docker-compose.yml up -d gateway

RUN_ID=run1 docker compose -f infra/docker-compose.yml --profile collect up -d capture
RUN_ID=run1 docker compose -f infra/docker-compose.yml --profile collect run --rm traffic

cd control-plane
PYTHONPATH=. .venv/bin/python -m iasg.dataset.build --runs ../datasets/raw/run1 --out ../datasets/v1
# Supply an artifact trained before this run. If no deployed artifact exists,
# reproduce one from a separate frozen historical dataset -- never this run.
PYTHONPATH=. .venv/bin/python -m iasg.ml.train \
  --dataset ../datasets/v4 --out ../models/fresh-validation-v4 \
  --version fresh-validation-v4
PYTHONPATH=. .venv/bin/python -m iasg.ml.validate \
  --dataset ../datasets/v1 --artifact ../models/fresh-validation-v4 \
  --out ../datasets/v1/fresh-validation.json
```

`iasg.ml.validate` compares deterministic detector evidence, the advisory
Isolation Forest at the artifact's already-fixed validation threshold, and
their combined visibility. It also reports only attack-minutes that the gateway
neither detected nor already refused, so a policy/reflex refusal is never
misreported as a detector miss. It does not train or tune a model.

It runs **inside** the compose network deliberately. Docker Desktop rewrites a
host request's source address, so from the host every persona collapses into one
private address.

## The pre-flight is not optional

The gateway believes `X-Forwarded-For` only from a configured trusted proxy.
`config.yaml` trusts `172.16.0.0/12`, which Compose usually lands in — but
Docker Desktop sometimes allocates `192.168.65.0/24` instead, and then every
persona becomes one client. No error is raised anywhere, the run completes, the
files look right, and the dataset is silently wrong in a way nothing downstream
can detect.

So the generator sends one request per address first, reads back
`iasg:ip:<ip>:latest`, and **refuses to start** if the gateway recorded
something else — naming the address it recorded instead. `--skip-preflight`
exists and should not be used for a dataset anyone will train on.

## Personas, and why each one is here

Each exists to put ordinary traffic somewhere a naive rule would call
suspicious. Without them the model learns "any non-zero X is an attack".

| Persona | Teaches |
|---|---|
| `browser`, `shopper` | the baseline; logins with zero failures |
| `forgetful_user` | **`login_failure_ratio > 0` is benign** |
| `dead_link_visitor` | **`backend_404_ratio > 0` is benign** |
| `search_heavy` | query strings stay out of `unique_path_ratio` |
| `mobile_poller` | **low `interarrival_cv` is benign** — what a naive rule calls a bot |
| `impatient` | `peak_1s_requests` without an attack |
| `one_shot`, `idle` | `insufficient_history` rows; absent windows |

`forgetful_user` is the one that matters most. Without benign login failures the
feature separates perfectly in training, and the first real person who mistypes
their password gets throttled.

The generator warns by name when a persona is missing from a run, and says which
feature loses its benign mass.

## Reserved scenarios

`slow_brute_force` (one attempt every 8s) and `low_and_slow_enumeration` (a
probe every 12s) stay deliberately under the Go detectors' thresholds. They are
the only honest measure of whether this layer catches what the detectors miss,
so the splitter forces them into **test** and raises if asked to put them
anywhere else. They also draw from their own address pool, so they can never
share a group key with a tunable scenario.

## Addresses

`203.0.113.0/24` throughout — RFC 5737, which is what `policy/writer.py`
accepts. An attack from a private or loopback address correctly produces no
policy at all and looks broken.

| Pool | Range |
|---|---|
| benign | `.10`–`.99` |
| reserved scenarios | `.180`–`.199` |
| tunable attacks | `.200`–`.250` |

One address per session per run, so `session_id ≡ (run_id, ip)` and grouping
rows by address is automatically session-safe. The pool raises rather than
reusing an address: reuse would merge two sessions with nothing able to
separate them afterwards.

## Labels

`attacks.jsonl` is written from the **plan**, before traffic starts. Written
afterwards it would be a second opinion about the traffic rather than a record
of what was launched — and that is the door detector output gets in by.

## Attack drivers are Python, not JMeter

`.gitignore`'s `testing/jmeter/*` would silently ignore a new `.jmx`, so it
would exist on one machine and nowhere else.

`testing/signals/lib.sh` also accepts an optional `ATTACK_IP`, which makes the
shell detector scripts drive from a documentation address instead of the peer.
Unset, its behaviour is unchanged.
