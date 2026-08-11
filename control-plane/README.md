# IASG Control Plane

The Python half of the Intelligent API Security Gateway — Lane 2 of the proposal.

The Go gateway is the **data plane**: it sees every request and decides allow/block in
microseconds. This is the **control plane**: it never touches a live request, wakes up
every 30 seconds, works out which attackers are acting together, and writes policy the
gateway can read later.

Kill this process and the gateway keeps protecting traffic. It just stops getting smarter.

```
Go gateway  ->  attack_events (Redis stream)  ->  control plane
                        ^                              |
                        |                    correlate -> decide -> explain
                    ingest.py                          |
                                                 policy:<ip> (Redis)
```

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Needs Redis on `localhost:6379`. Nothing else — no Docker, no Postgres, no LLM.

## Run it

```bash
# 1. make some fake attacks
.venv/bin/python -m tools.seed_evidence --scenario credential-stuffing

# 2. one cycle
.venv/bin/python -m iasg --once

# 3. see what it decided
redis-cli --scan --pattern 'policy:*'
redis-cli GET policy:203.0.113.5
redis-cli TTL policy:203.0.113.5      # expires by itself
```

Expected output:

```
[cycle] read 36 events
[correlation] Campaign #1 -- Credential Stuffing
              6 IPs, confidence 1.00, high
              6 IPs sharing same attack type (bruteforce), same endpoint
              (/api/login), same subnet (203.0.113.0/24), overlapping timing,
              same User-Agent (curl/8.4.0)
[explain]     Between 16:48 and 16:49, the system detected a coordinated
              credential stuffing campaign involving 6 IP addresses targeting
              /api/login...
[policy]      wrote 6 policy keys
```

Other options:

```bash
.venv/bin/python -m iasg                  # loop forever, every 30s
.venv/bin/python -m iasg --once --dry-run # decide everything, write nothing
.venv/bin/pytest                          # 50 tests, no Redis needed
```

Scenarios: `credential-stuffing`, `flood`, `recon`, `sqli`, `noise`, `mixed`.
Add `--clear` to wipe the stream first.

## Against the real gateway

The gateway is not modified, so its detections only reach stdout. Pipe them in:

```bash
cd ../gateway && go run ./cmd/server 2>&1 | ../control-plane/.venv/bin/python -m iasg.evidence.ingest
```

Then attack `localhost:8082/api/login` and run `python -m iasg --once` in another terminal.

## Layout

| path | what it does |
|---|---|
| `iasg/config.py` | settings from `IASG_*` env vars, all with defaults |
| `iasg/models.py` | `Evidence` → `Campaign` → `PolicyDecision` |
| `iasg/store/` | Redis access, plus an in-memory fake for tests |
| `iasg/evidence/consumer.py` | reads the stream via a consumer group |
| `iasg/evidence/ingest.py` | parses the gateway's `SECURITY ALERT` blocks |
| `iasg/correlation/` | **groups IPs into campaigns** — union-find over shared traits |
| `iasg/campaigns/` | memory: campaigns persist and merge across cycles |
| `iasg/policy/` | the block/throttle ladder, and the rails around it |
| `iasg/explanation/` | the admin-facing paragraph |
| `iasg/assessment/` | the LLM's review of what the rules concluded |
| `iasg/runner.py` | the loop |

## Where the AI is, and is not

Grouping, confidence scoring and the block/throttle decision are **plain deterministic
Python**. No LLM is anywhere near them. Rules can't be talked out of blocking someone,
give the same answer twice, and need no network.

The LLM writes two pieces of **text only**: the admin paragraph (`campaign.explanation`)
and a review of the grouping (`campaign.assessment`). Both run *after* policy is already
written, and nothing reads them back to make a decision. A hallucinated or
prompt-injected assessment can mislead a human reader; it cannot unblock an attacker.

Default provider is `null`, which renders templates offline. To use a real model:

```bash
brew install ollama && ollama serve
ollama pull llama3.2
IASG_LLM_PROVIDER=ollama .venv/bin/python -m iasg --once
```

## Safety rails on policy writes

`policy/writer.py` is the only code that can influence the gateway, so the guards live
there together:

- never writes policy for loopback, private, link-local or reserved addresses
  (the RFC 5737 documentation ranges used by the seeder are explicitly allowed)
- `monitor` writes nothing at all
- `IASG_MAX_IPS_PER_CYCLE` caps how many IPs one cycle may action
- `--dry-run` logs every intended write and performs none

## Notes

**Enforcement is out of scope.** This branch delivers evidence → campaign → policy.
Making the gateway *read* `policy:<ip>` and act on it is the next piece of work.

**Run commands as modules** (`python -m tools.seed_evidence`, not
`python tools/seed_evidence.py`). Setuptools' editable install doesn't wire up
`sys.path` correctly on Python 3.14, so `-m` — which puts the current directory on the
path — is the dependable form.
