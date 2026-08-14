# Control Plane — file by file

Everything built on the `pranav/agentic-evidence-pipeline` branch, in the order it makes
sense to read it.

---

## What this branch does

The Go gateway detects attacks and prints them. That's it — six IPs attacking `/api/login`
produce six unrelated warnings that scroll past and vanish.

This branch adds a Python program that reads those detections, works out that the six IPs
are **one coordinated attacker**, decides what to do, and writes that decision into Redis
for the gateway to read later.

```
Go gateway                     Python control plane (this branch)
  detects, prints    ──────▶     reads every 30s
                     Redis        │
                                  ├─ groups IPs into one campaign
                                  ├─ remembers it across cycles
                                  ├─ decides monitor/throttle/block
                                  ├─ writes policy:<ip>
                                  └─ explains it in English
```

**The gateway was not modified.** Not one Go file changed. The two halves only ever meet
through Redis, which is what keeps them independent — kill this program and the gateway
carries on protecting traffic.

---

## What changed on the branch

**Deleted** — `gateway/internal/store/` (`store.go`, `memory.go`, `memory_test.go`). That
was an earlier attempt to build this in Go. The whole control plane moved to Python, so
the Go version was removed. `go build ./...` still passes.

**Added** — everything below.

---

## 1. Foundations

### `pyproject.toml`
Python's equivalent of `go.mod`. Names the project, lists dependencies (`redis` at runtime,
`pytest` for tests — that's all), and makes `iasg` importable.

### `.env.example`
Every setting with its default, committed so teammates can see what knobs exist.

### `iasg/config.py`
One `Settings` object holding every setting, read from `IASG_*` environment variables.

Every setting has a working default, so the agent runs on a machine with nothing
configured. `frozen=True` makes it read-only after creation — which matters most for
`dry_run`, the flag that stops the agent writing real blocking policy while you test.

The `_env_int` / `_env_bool` helpers exist because environment variables are always text:
`IASG_INTERVAL_SECONDS=30` arrives as the string `"30"`. If someone types nonsense, you get
the default rather than a crash on startup.

### `iasg/models.py`
The three shapes everything else passes around:

```
Evidence          →   Campaign            →   PolicyDecision
"IP .5 failed         "these 6 IPs are        "throttle IP .5
 12 logins"            one attack"              for 15 minutes"
```

The important part is `Evidence.from_stream_fields` / `to_stream_fields`. **Redis stores
only text** — `failedLogins` comes back as `"12"`, not `12`. All that conversion lives here
once, instead of being repeated (and got slightly wrong) inside every agent.

`Campaign` also carries `explanation` and `assessment` — both written by the LLM, both
advisory text only.

---

## 2. `iasg/store/` — talking to Redis

This is the Python port of the Go `store` package that was deleted.

| File | Purpose |
|---|---|
| `base.py` | The `Store` **interface**. Eight methods, no code — like a Go interface. |
| `memory.py` | A **fake** store made of dictionaries. No Redis needed. |
| `redis_store.py` | The **real** one. Same eight methods, actual Redis commands. |
| `__init__.py` | `open_store()` — connects to Redis, falls back to memory if it's unreachable. |

**Why an interface?** So tests get the fake and production gets the real one, and no code
in between can tell the difference. Your teammate can clone the repo with no Redis
installed and `pytest` still passes.

**Worth noticing:** the deleted Go interface had only `Append` and `Get`, because the
*gateway* writes evidence and reads policy. This one is the mirror image — it reads
evidence and writes policy.

**The trick in `memory.py`:** keys expire when you *read* them, not on a background timer.
An expired key is indistinguishable from a missing one, so nobody can tell — and there's no
thread to start, leak, or shut down. Straight from the Go version.

---

## 3. `iasg/evidence/` — getting data in

### `consumer.py`
Reads the `iasg:events` stream using a Redis **consumer group**, which is Redis
remembering how far we've read. Without it, every restart would re-process every attack
since the beginning of time.

Events are acked **last**, only after a cycle succeeds. Acking on read would silently lose
evidence whenever the agent crashed mid-cycle. On startup it also reclaims anything a
previous crash left unacked.

### `ingest.py`
Optional fallback. The gateway now writes `iasg:events` itself. This parser still
accepts printed `SECURITY ALERT` blocks if you want to pipe an older gateway:

```bash
cd ../gateway && go run ./cmd/server 2>&1 | ../control-plane/.venv/bin/python -m iasg.evidence.ingest
```

This is how real attacks reach the agent **with zero Go changes**. All four detectors print
the same `Key : Value` block format, so one parser covers every one of them.

---

## 4. `iasg/correlation/` — the heart of it

Answers *"what is actually happening?"* — never *"should this be blocked?"*.
Entirely deterministic. No LLM is anywhere near this.

### `features.py`
Folds many events into one profile per IP: which endpoints it hit, which user-agents, which
detectors fired, its `/24` subnet, its time range.

`common_traits()` finds what the **whole group** shares — not what some pair happened to
share. That distinction matters: reporting the union would claim "same User-Agent" when only
two of six members had one.

### `cluster.py`
**Union-find.** If A links to B and B links to C, all three end up in one campaign, even
though A and C were never compared directly.

The linking rule is two gates beyond a simple count:

- **Timing is required.** Two IPs with an identical fingerprint a day apart are two
  incidents, not one coordinated campaign.
- **At least two identity traits** (user-agent / endpoint / subnet). "Same attack type at
  the same time" describes every busy minute on a public API.

Slow campaigns aren't lost by the timing gate — each cycle's cluster merges into the stored
campaign by IP overlap (see `campaigns/`).

### `agent.py`
Puts it together: cluster the IPs → score confidence → name the campaign → write the reason.

Naming works off the dominant detector plus the *shape*: brute-force across many IPs with
many distinct usernames is **Credential Stuffing**; one IP on one account is **Brute
Force**; many IPs flooding is a **Distributed Flood**.

A lone IP with fewer than 3 events is filed as noise rather than a campaign — otherwise
memory fills with every stray detection.

---

## 5. `iasg/campaigns/repository.py` — memory

Stores campaigns in Redis, and **merges** a new cluster into an existing campaign when their
IPs overlap enough, instead of creating a duplicate. Confidence, event count and `last_seen`
accumulate.

That merge is the whole difference between an **agent continuing an investigation** and a
script starting from zero every 30 seconds. Run the same attack twice and you'll see
Campaign #1 grow to 72 events, not a second Campaign #2 appear.

---

## 6. `iasg/policy/` — the only part that can touch the gateway

### `agent.py`
The ladder. Sees only campaign, severity, confidence and history — never raw requests.

| confidence | severity | action |
|---|---|---|
| < 0.5 | any | `monitor` |
| 0.5 – 0.75 | any | `throttle` |
| ≥ 0.75 | high | `temp_block` |
| ≥ 0.9 | high + 5 or more IPs | `escalate` |

### `writer.py`
Writes `policy:<ip>` to Redis with a TTL, **and holds every safety rail** so they can be
audited in one place:

- never writes policy for loopback, private, link-local or reserved addresses
- `monitor` writes nothing at all
- `IASG_MAX_IPS_PER_CYCLE` caps how many IPs one cycle can action
- `--dry-run` logs every intended write and performs none

The TTL is what makes "throttle for 15 minutes" work with no cleanup code — Redis deletes
the key itself when it expires.

> One subtlety: Python classifies the RFC 5737 documentation ranges (`203.0.113.x`,
> `198.51.100.x`, `192.0.2.x`) as *private*. Those are exactly what the seeder uses, so
> they're explicitly allowed — otherwise every demo would write zero policies.

---

## 7. The LLM layer

| File | Purpose |
|---|---|
| `reasoning/provider.py` | The `LLMProvider` interface: `generate(system, prompt) -> str` |
| `reasoning/null.py` | No LLM. Returns `""` so callers fall back to templates. **Default.** |
| `reasoning/ollama.py` | Talks to a local Ollama model. Opt-in, uses stdlib `urllib` so it adds no dependency. |
| `explanation/agent.py` | The admin-facing paragraph → `campaign.explanation` |
| `assessment/agent.py` | The LLM's review of the grouping → `campaign.assessment` |

**Where the AI is, and is not.** Grouping, scoring and the block/throttle decision are plain
deterministic Python. The LLM writes **text only**, runs *after* policy is already written,
and nothing reads its output back to make a decision. A hallucinated or prompt-injected
assessment can mislead a human reader; it cannot unblock an attacker.

Right now it's inert — `IASG_LLM_PROVIDER=null` means those paragraphs are templates. To
switch on real generation:

```bash
brew install ollama
brew services start ollama   # runs in the background, restarts at login
ollama pull llama3.2         # ~2GB, stored in ~/.ollama (not in this repo)
IASG_LLM_PROVIDER=ollama .venv/bin/python -m iasg --once
```

No code changes needed.

---

## 8. `iasg/runner.py` and `iasg/__main__.py`

`runner.py` is the loop:

```
observe → correlate → remember → decide → explain
```

Note the order: policy is decided and written **before** the LLM is asked for anything. And
evidence is acked at the very end, once everything above succeeded.

`__main__.py` is the CLI — `--once`, `--dry-run`, `--interval`.

---

## 9. `tools/seed_evidence.py`

Writes fake attacks into the stream, so the whole pipeline is testable in a second without
an attacker, a gateway, or Docker.

```bash
python -m tools.seed_evidence --scenario credential-stuffing
```

Scenarios: `credential-stuffing`, `flood`, `recon`, `sqli`, `noise`, `mixed`. The `noise`
one exists so you can check the correlator correctly **refuses** to group unrelated traffic.

---

## 10. `tests/` — 53 tests, none needing Redis

| File | Covers |
|---|---|
| `test_store_memory.py` | Expiry, cursors, ack, copy-on-append |
| `test_correlation.py` | Grouping — and **refusing** to group unrelated traffic |
| `test_campaigns.py` | Merging, accumulating, not duplicating |
| `test_policy.py` | The ladder and every safety rail |
| `test_ingest.py` | Parsing the gateway's printed alerts |

The tests asserting things **don't** group are the more interesting half — that's where the
design decisions live.

---

## Running it

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

.venv/bin/python -m tools.seed_evidence --scenario credential-stuffing
.venv/bin/python -m iasg --once

redis-cli GET policy:203.0.113.5
redis-cli TTL policy:203.0.113.5
```

Expected:

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
```

**Run scripts as modules** — `python -m tools.seed_evidence`, not
`python tools/seed_evidence.py`. Setuptools' editable install doesn't wire up `sys.path`
correctly on Python 3.14, so `-m` (which puts the current directory on the path) is the
dependable form.

---

## What's still missing

**Enforcement.** The gateway does not yet *read* `policy:<ip>` and act on it. This branch
delivers evidence → campaign → policy; making the gateway obey that policy is the next
branch. It's one middleware doing a single `GET` per request, with a short-lived local
cache so it stays microsecond-fast.
