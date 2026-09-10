# Control Plane - Five Core Mechanisms

The system is intentionally explainable through five mechanisms. The Go gateway
observes bounded facts on a request; the Python control plane reasons from those
facts off the request path, every 30 seconds. The gateway never waits on that
reasoning.

| Core mechanism | Purpose | It does not do |
| --- | --- | --- |
| 1. Deterministic attack detectors | Recognise known attack shapes and emit evidence | Choose a policy or refuse the request they inspect |
| 2. Adaptive endpoint baseline | Learn a safe normal rate for each method and route | Learn from attack or enforcement-distorted traffic |
| 3. Campaign correlation | Connect related evidence into a continuing attack | Treat every IP or every 30-second batch as a new incident |
| 4. Risk/confidence policy engine | Select a bounded monitor, throttle, or temporary-block response | Let a list, a model, or narration originate enforcement |
| 5. Optional Isolation Forest advisory model | Add a bounded anomaly observation when a valid model is installed | Supply policy confidence or act by itself |

Token buckets, Redis streams, telemetry queues, cooldowns, body limits, policy
TTLs, and durable storage support enforcement or reliability. They are important
constraints, but they are not extra detection algorithms.

## 1. Deterministic attack detectors

The gateway detects flooding, SQL injection, brute force, traversal/enumeration,
and known-bad IP reputation. A detector fills `Evidence` and allows the request;
it never chooses the request's response. The gateway's reflex and the cached
control-plane policy are enforcement mechanisms which act on a decision already
available before the next request.

The deterministic evidence is the policy engine's required floor. A baseline
deviation or a statistical anomaly without it results in `monitor`, never a
throttle or block. Detector thresholds, body limits, cooldowns, and evidence
publication are documented in [the gateway detection-signal guide](../gateway/docs/detection-signals.md).

### Reputation is supporting evidence

IP reputation is deliberately not a sixth core mechanism. It is a standing prior
about an address, not behaviour observed from this API. The live adaptive risk
engine excludes it from both the deterministic-evidence floor and score, so it
cannot turn otherwise ordinary traffic into an actionable campaign. The default
gateway configuration also does not arm it for reflex enforcement.

## 2. Adaptive endpoint baseline

The control plane completes privacy-safe 60-second telemetry windows and learns
a separate normal rate for each normalized HTTP method and route template. For
example, `GET /api/products/{id}` has one baseline, independent from
`POST /api/login`; raw IDs and query strings cannot create an unbounded number
of baselines.

For a trusted endpoint, the threshold is a bounded
`median + MAD multiplier * max(MAD, minimum MAD)`. A sample enters the rolling
baseline only when the window is complete, detector-clean, allowed, and has no
telemetry or heartbeat defect. Warm-up, fixed lower/upper bounds, hysteresis,
and cooldown prevent one unusual minute from moving the normal value.

Once ready, deviation from the baseline is an explainable input to risk. It is
not an autonomous detector: deterministic evidence is still required before an
active policy is eligible. The full learning and guardrail contract is in
[Adaptive policy and analyst control](../gateway/docs/adaptive-policy.md#baselines).

## 3. Campaign correlation

Correlation turns evidence from individual addresses into a statement about an
attack campaign. It begins with a profile per address, then groups profiles when
their activity overlaps in time and at least two identity traits agree.

### Union-Find: grouping connected attackers

Suppose A matches B and B matches C, while A and C have no direct match. They
still form one campaign: B is evidence that they are part of one coordinated
operation. Union-Find represents exactly that friend-of-a-friend relationship
efficiently.

The five correlation traits are endpoint, User-Agent, /24 subnet, attack type,
and timing. Timing is mandatory, and at least two of endpoint, User-Agent, and
subnet must agree. This avoids merging every busy minute that happens to contain
the same detector type.

### Confidence and continuity

The correlator assigns confidence from shared traits, then carries campaign
history across cycles. Jaccard overlap keeps a campaign continuous when some
addresses remain. If every IP rotates, a stricter behavioural signature can
re-identify it from the endpoint, User-Agent, subnet, detector type, and a
short time window.

A solo attacker cannot share traits, so it is scored in bounded volume bands.
That lets repeated single-address attacks be actioned while keeping volume alone
below the threshold for an analyst escalation.

Correlation is deliberately conservative, not a claim of ground truth. Its
current limits are transitive Union-Find links, binary/modal trait comparison,
and O(n^2) comparison within a cycle. See `iasg/correlation/` and
`iasg/campaigns/repository.py` for the executable definitions.

## 4. Risk/confidence policy engine

The adaptive policy engine combines four explainable facts: deterministic
evidence, endpoint-baseline deviation, campaign facts, and (when available) an
advisory anomaly score. It records every component, its configured weight, the
0-100 risk total, the independent 0-1 confidence value, and the guardrail result.
Risk and confidence are intentionally separate: a surprising observation cannot
manufacture confidence.

The engine produces `monitor`, `throttle`, or `temp_block` recommendations. In
automatic mode, only non-monitor recommendations that pass every guardrail may
be written. In manual mode they await analyst approval; monitor mode writes no
active policy. Analyst escalation is an alert for a human, not an unbounded
fourth automatic enforcement action.

### Non-negotiable rails

The policy engine cannot write an active policy without deterministic evidence.
It also cannot write one for allowlisted, private, loopback, link-local,
multicast, or reserved addresses; it cannot omit a TTL; and it cannot exceed
the per-cycle write budget or configured duration ceiling. Shared-address
softening and the monotonic no-downgrade rule run before the sole policy writer,
`policy/writer.py`, reaches Redis.

Those rails, policy TTLs, and gateway token buckets are supporting enforcement
mechanisms. They bound the harm a bad recommendation could cause; they are not
independent ways to detect an attack. The precise score, confidence, modes, and
rails are documented in [Risk and confidence](../gateway/docs/adaptive-policy.md#risk-and-confidence).

The older `iasg/policy/agent.py` action ladder remains a compatibility surface
for tests and embedders. Production cycles use `iasg/adaptive/`; its historical
thresholds are not live policy.

## 5. Optional Isolation Forest advisory model

An Isolation Forest can score completed telemetry windows when a valid, compatible
artifact is installed. The model is optional and currently dormant when its
files are absent or invalid. There is no live retraining path.

The model is advisory by construction:

1. No deterministic evidence means `monitor`, even with a maximal anomaly.
2. The anomaly score is excluded from policy confidence.
3. If ML is needed to cross the block boundary, the anomaly itself must clear
   the configured strong-anomaly threshold.

It may therefore add useful context to a decision earned by evidence, but it
cannot originate enforcement. Model availability failures also degrade to the
same safe, model-free path. See [Advisory ML signals](../gateway/docs/adaptive-policy.md#advisory-ml-signals).

## Narration is outside every decision

Attacker-controlled strings such as endpoints and User-Agents must never be
able to persuade the system that they are benign. The LLM therefore runs only
after a policy has been selected and written. It produces an incident explanation
and a grouping assessment for a human reader; neither output is read back by
risk, confidence, policy selection, or enforcement.

The safe default provider is `null`, which renders offline templates. Compose
may opt into Ollama for narration, but provider timeout, failure, or prompt
injection cannot fail a cycle or alter a policy. The template fallback remains
the default experience outside that explicit opt-in.

## Supporting enforcement and reliability mechanisms

| Mechanism | Why it exists |
| --- | --- |
| Capped request bodies and detector cooldowns | Bound request work and evidence volume |
| Redis streams, consumer groups, and replay | Deliver evidence without delaying a request |
| Policy snapshots and token buckets | Enforce a cached policy quickly and consistently across gateway replicas |
| TTLs, duration caps, and write budgets | Make enforcement self-expiring and limit a bad cycle's blast radius |
| Postgres projections and lifecycle records | Preserve campaign and recommendation history across restarts |

Keeping these separate from the five mechanisms makes the design easier to
audit: the first five answer how the system reaches a conclusion; these answer
how it does so safely and reliably.

## Read the code in this order

1. `gateway/internal/signals/` for deterministic evidence.
2. `iasg/adaptive/windows.py` and `iasg/adaptive/baseline.py` for endpoint
   baselines.
3. `iasg/correlation/` and `iasg/campaigns/repository.py` for campaigns.
4. `iasg/adaptive/risk.py`, `iasg/adaptive/controller.py`,
   `iasg/policy/simulation.py`, and `iasg/policy/writer.py` for policy.
5. `iasg/ml/scorer.py` for the optional advisory model.

`iasg/runner.py` composes those mechanisms into an operational cycle. Its Redis
reads, acknowledgements, durable projections, and post-policy narration are
the plumbing that preserves their boundary rather than more algorithms.
