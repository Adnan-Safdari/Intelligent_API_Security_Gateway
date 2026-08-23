# IASG Control Plane

The Python half of the Intelligent API Security Gateway — Lane 2 of the proposal.

The Go gateway is the **data plane**: it sees every request and decides allow/block in
microseconds. This is the **control plane**: it never touches a live request, wakes up
every 30 seconds, works out which attackers are acting together, and writes policy the
gateway enforces.

Kill this process and the gateway keeps protecting traffic, using the last policy it was
given until those keys expire. It just stops getting smarter.

```
                 evidence
   Go gateway  ──────────▶  iasg:events (Redis stream)
       ▲                              │
       │                              ▼
       │                    correlate → remember → decide → explain
       │                              │
       └──────────────────────────────┘
              policy:<ip> (Redis, TTL)
```

The gateway writes one JSON event per request to `iasg:events`. The control plane
reads that stream, skips clean traffic, and turns fired signals into Evidence.
`iasg.evidence.ingest` remains as a fallback for piping old SECURITY ALERT logs.

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
              6 IPs sharing same endpoint (/api/login), same User-Agent
              (curl/8.4.0), same attack type (bruteforce), same subnet
              (203.0.113.0/24), overlapping timing
[explain]     Between 16:48 and 16:49, the system detected a coordinated
              credential stuffing campaign involving 6 IP addresses targeting
              /api/login...
[policy]      wrote 6 policy keys
[escalate]    Campaign #1 raised for human review -- 6 IPs, confidence 1.00
```

Other options:

```bash
.venv/bin/python -m iasg                  # loop forever, every 30s
.venv/bin/python -m iasg --once --dry-run # decide everything, write nothing
.venv/bin/pytest                          # 236 tests, no Redis needed
```

Scenarios: `credential-stuffing`, `brute-force`, `flood`, `enumeration`, `path-traversal`,
`recon`, `sqli`, `noise`, `mixed`. Add `--clear` to wipe the stream first.

`noise` is the one that must produce *nothing*. Unrelated traffic being reported as a
campaign is worse than missing a real one, so there is a scenario whose whole job is to be
rejected.

## Against the real gateway

The gateway prints its detections to stdout. Pipe them in:

```bash
cd ../gateway && go run ./cmd/server 2>&1 | ../control-plane/.venv/bin/python -m iasg.evidence.ingest
```

Then attack `localhost:8082/api/login` and run `python -m iasg --once` in another terminal.

One thing that bites here: if the gateway sits behind a proxy it must be configured with
`trusted_proxies`, or every request is attributed to `127.0.0.1` — which the writer refuses
as a non-public address, so no policy is ever written. See
[client-ip.md](../gateway/docs/client-ip.md).

## What it actually works out

Beyond grouping addresses, the parts worth knowing about:

**A lone attacker can be actioned.** Confidence is built from traits shared *between*
addresses, and one machine shares traits with nobody — so a single IP could never exceed
0.15 and never be blocked, however many times a detector fired. Solo campaigns are now
scored on their own volume and severity instead, capped below the level that wakes a human.

**Campaigns survive the attacker moving.** Matching on addresses alone meant every
rotation opened a new campaign and the investigation restarted. When no addresses are
shared, the behavioural signature — endpoint, user agent, detector — identifies the
campaign instead. Deliberately strict: merging two unrelated attackers hides one behind
the other.

**It notices whether acting worked.** A campaign that goes quiet is marked contained; one
that returns after enforcement has that counted against the action, and the next response
moves a rung up the ladder rather than repeating what just failed.

What "contained" honestly means is written into the code: for a block it is close to
circular, since a blocked address never reaches the detectors. It confirms enforcement is
holding, not that the attacker gave up. For monitor and throttle it is a real signal.

**Several attack phases from one actor read as one intrusion.** Someone who hunts for
`.env`, attacks the login they find, then probes the database is a *Multi-Stage Intrusion*
— not three separate incidents named after whichever detector was loudest. Phases are
ordered by when each was actually observed, and each phase beyond the first raises the
response.

**Escalation means something.** It writes to the `iasg_alerts` stream with the campaign and
its readable explanation, and its block outlasts an ordinary one — a human has been asked
to look, and it should still be in place when they do. Once per campaign, not once per
cycle.

## Before a policy is written

Deciding whether traffic is malicious and deciding whether the response is safe are
different questions, and `policy/simulation.py` asks the second one. It runs last, so
nothing reaches the gateway without passing it.

Its limit is stated in the module rather than hidden: the gateway reports attacks and
never ordinary traffic, so nothing here can measure how many real users sit behind an
address. It does not invent a percentage. It works with what is observable:

```bash
# never policed, whatever the evidence says and whoever asks
IASG_ALLOWLIST=10.0.0.0/8,203.0.113.9
# an office NAT or campus gateway: slowed if it attacks, never cut off
IASG_SHARED_RANGES=198.51.100.0/24
```

It also refuses to trade a standing policy for a weaker one — campaigns are re-decided
every cycle, so otherwise the quiet caused by a block could downgrade the block that
caused it.

One check is inference rather than configuration: an address speaking with many distinct
user agents looks shared. That one only softens campaigns the evidence was unsure about.
Softening a confident campaign would be an evasion route — rotate the header enough and a
block becomes a throttle — so above 0.9 confidence the action stands and the doubt is
reported instead.

## When a human disagrees

An admin instructs the agent by writing to a stream, from a dashboard, a script, or
`redis-cli`:

```bash
redis-cli XADD iasg_overrides '*' \
    ip 203.0.113.5 action temp_block actor pranav reason "confirmed attack"
```

An instruction about an address no campaign mentioned still writes policy — blocking
something the agent has not noticed is the plainest use of this. An unparseable action is
refused rather than written.

Precedence is decided rather than left to ordering, and the two kinds of check answer to
different people. **Declared configuration binds everyone**, including a human at a
console: an operator who allowlisted a range has already answered, and an instruction
typed in a hurry should not quietly undo it. **The inferred checks bind only the agent**,
since someone who says block anyway has seen something a heuristic cannot.

Disagreement is tallied per campaign type, and after enough consistent corrections in one
direction the agent starts making that correction itself. Bounded hard: one rung ever,
several samples before it moves at all, opposing corrections cancel, and it shifts only
the starting recommendation — the checks above run afterwards and are not learnable, since
a system that could learn its way past its own rails eventually would. There is no model
and nothing is trained; it is a tally.

Both features are off until configured. With nothing set, the ladder behaves exactly as it
did before they existed, and a test pins that.

## Where the AI is, and is not

Grouping, confidence scoring and the block/throttle decision are **plain deterministic
Python**. No LLM is anywhere near them. Rules can't be talked out of blocking someone,
give the same answer twice, and need no network.

The LLM writes two pieces of **text only**: the admin paragraph (`campaign.explanation`)
and a review of the grouping (`campaign.assessment`). Both run *after* policy is already
written, and nothing reads them back to make a decision. A hallucinated or
prompt-injected assessment can mislead a human reader; it cannot unblock an attacker.

Compose enables this: it sets `IASG_LLM_PROVIDER=ollama` and points the container at
Ollama on the *host*, so there is no second copy of the model. A bare `python -m iasg`
still defaults to `null` and renders templates offline. To use a real model there:

```bash
brew install ollama
brew services start ollama   # runs in the background, restarts at login
ollama pull llama3.2         # ~2GB, stored in ~/.ollama (not in this repo)
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

## Layout

| path | what it does |
|---|---|
| `iasg/config.py` | settings from `IASG_*` env vars, all with defaults |
| `iasg/models.py` | `Evidence` → `Campaign` → `PolicyDecision`, and the action ladder |
| `iasg/store/` | Redis access, plus an in-memory fake for tests |
| `iasg/evidence/consumer.py` | reads the stream via a consumer group |
| `iasg/evidence/ingest.py` | parses the gateway's `SECURITY ALERT` blocks |
| `iasg/correlation/` | **groups IPs into campaigns** — union-find over shared traits |
| `iasg/campaigns/` | memory: campaigns persist, merge, and are reviewed for outcome |
| `iasg/policy/agent.py` | the block/throttle ladder |
| `iasg/policy/simulation.py` | is the response safe? collateral checks, run last |
| `iasg/policy/writer.py` | the only code that writes policy, and its rails |
| `iasg/feedback/` | human overrides, and what the agent learns from them |
| `iasg/alerts.py` | escalation to a human, on its own stream |
| `iasg/reasoning/` | LLM providers, and the per-cycle narration budget |
| `iasg/explanation/` | the admin-facing paragraph |
| `iasg/assessment/` | the LLM's review of what the rules concluded |
| `iasg/runner.py` | the loop |

## Notes

**Run commands as modules** (`python -m tools.seed_evidence`, not
`python tools/seed_evidence.py`). Setuptools' editable install doesn't wire up
`sys.path` correctly on Python 3.14, so `-m` — which puts the current directory on the
path — is the dependable form. `pytest` and `python -m iasg` work either way.

**Postgres is not used.** Campaigns are stored in Redis with a TTL. The Compose stack runs
a Postgres for the gateway, and `IASG_POSTGRES_URL` exists in config, but nothing here
reads it yet.
