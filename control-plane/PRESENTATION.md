# Control Plane - presentation notes

Speaker notes for a 10-12 minute presentation plus questions.

**The thread to hold onto:** the gateway sees requests; the control plane sees
attacks. The gateway never waits on thinking.

## 1. What it is (30 sec)

> "This is an API security gateway in two lanes. The Go gateway is on every
> request, so it observes known attack shapes and enforces cached decisions. The
> Python control plane runs off-path every 30 seconds, where it can use history
> and context to decide what an attack means."

The split is the security and performance boundary. A gateway request never
waits for Redis, a model, or the control plane.

## 2. The five mechanisms (1 min)

Use this as the project map. Do not present queues, buckets, or TTLs as
independent detection algorithms.

| Mechanism | One sentence |
| --- | --- |
| Deterministic attack detectors | Recognise known attack shapes and emit evidence. |
| Adaptive endpoint baseline | Learn a safe normal rate for each endpoint from clean completed windows. |
| Campaign correlation | Turn related evidence from several addresses and cycles into one attack. |
| Risk/confidence policy engine | Choose a bounded, explainable response from evidence, behaviour, and campaign facts. |
| Optional Isolation Forest advisory model | Add anomaly context when a validated model exists, without acting alone. |

> "Everything else is a supporting safety or reliability mechanism. Body limits
> bound work. Redis transports evidence. Token buckets enforce a throttle.
> Cooldowns prevent noisy repeat evidence. Policy TTLs make every action expire."

That distinction is deliberate: the five mechanisms explain how the system
reaches a conclusion; the supporting mechanisms explain how it stays fast and
safe while doing so.

## 3. Deterministic attack detectors (1 min)

> "The gateway recognises flooding, SQL injection, brute force,
> traversal/enumeration, unknown-route scanning, and known-bad IP reputation. A detector records
> evidence and allows the request. It never decides the response to that
> request."

The reflex and control-plane policy are enforcement mechanisms acting on a
decision already available before a later request. This preserves the invariant
that a detector does not become an inline policy engine.

**Reputation is supporting evidence, not a sixth mechanism.**

> "Reputation says an address appears on a list. It is a useful prior, but it is
> not behaviour from this API. The live adaptive engine excludes it from the
> evidence floor and risk score, and the default gateway configuration does not
> arm it for reflex enforcement. It cannot create enforcement for ordinary traffic."

## 4. Adaptive endpoint baseline (1.5 min)

> "The system learns normal traffic separately for each method and route. A
> busy product endpoint should not define normal for login, and product IDs share
> one route baseline rather than create thousands of keys."

Each baseline uses trusted completed 60-second windows and a robust median plus
MAD threshold. A window with detector evidence, active enforcement, missing
telemetry, a heartbeat gap, or dropped events is visible but cannot teach the
baseline. Warm-up, hard bounds, hysteresis, and cooldown stop one unusual minute
from redefining normal.

> "A baseline deviation is an explainable input to risk, not an automatic block.
> Deterministic evidence is still required before the system may throttle or
> block."

## 5. Campaign correlation (2 min)

> "Six IPs failing login are not necessarily six incidents. The correlator
> builds one profile per address, then groups profiles whose timing overlaps and
> whose identity traits agree. The result is a campaign: these addresses are
> coordinating one credential-stuffing attack."

The traits are endpoint, User-Agent, /24 subnet, attack type, and timing. A
link requires overlapping timing plus at least two identity traits: endpoint,
User-Agent, or subnet.

> "Those two gates prevent a common false positive: same detector type during a
> busy minute is not enough to call unrelated customers one botnet."

Union-Find supplies the friend-of-a-friend grouping: if A matches B and B
matches C, all three become one campaign even if A and C do not directly match.
Campaign continuity uses IP overlap first, then a stricter behavioural signature
when an attacker rotates every address.

A lone address is scored by bounded volume bands. This means a persistent solo
attack can be actioned, while volume alone cannot justify analyst escalation.

## 6. Risk/confidence policy engine (2 min)

> "The policy engine makes one recorded, explainable recommendation. It combines
> deterministic evidence, endpoint-baseline deviation, campaign facts, and an
> advisory anomaly score when one is available."

Risk is a 0-100 score; confidence is a distinct 0-1 value. They are not merged:
a statistical surprise cannot invent confidence. Every recommendation records
its components, weights, total, confidence, and guardrail result.

| Mode | Result |
| --- | --- |
| Monitor | Store a recommendation; never write active policy. |
| Manual | Store a pending recommendation for an analyst to approve or reject. |
| Automatic | Write only a non-monitor recommendation that passes every guardrail. |

> "The active outcomes are monitor, throttle, and temporary block. Escalation
> wakes a person; it is not an unlimited automatic block."

No deterministic evidence means monitor. Reputation cannot supply that evidence.
Allowlisted and non-public addresses are never actioned; shared addresses are
softened; every policy has a bounded TTL; and policy/writer.py is the only code
that can affect the gateway.

## 7. Optional Isolation Forest (1 min)

> "The Isolation Forest is an optional advisory model over completed telemetry
> windows. If its artifact is missing or invalid, the system continues on the
> deterministic path. There is no live retraining."

It cannot originate enforcement:

1. No deterministic evidence always yields monitor.
2. Its score never contributes to policy confidence.
3. If it is needed for a block, its own anomaly must also clear the
   strong-anomaly threshold.

> "So the model can add context to a decision that evidence already earned; it
> cannot decide that somebody should be blocked."

## 8. LLM narration is not the model in the policy (1 min)

> "The language model is separate from the Isolation Forest and separate from
> enforcement. It writes an incident explanation and a review for the operator
> only after policy selection and writing. Nothing reads either text back into
> risk, confidence, or enforcement."

The default provider is the offline null template provider. A deployment can opt
into Ollama for narration, but a timeout, failure, hallucination, or
prompt-injected result cannot change a policy or fail a control-plane cycle.

## 9. Supporting enforcement and reliability (1 min)

| Support | Reason |
| --- | --- |
| Body caps and cooldowns | Bound request work and evidence volume. |
| Redis streams and consumer groups | Deliver/replay evidence without delaying traffic. |
| Snapshot policies and token buckets | Enforce a cached decision quickly across gateway replicas. |
| TTLs, duration caps, and write budgets | Make enforcement self-expiring and bound a bad cycle. |
| Postgres history | Preserve campaigns and recommendations across restarts. |

> "These features make enforcement reliable. They do not independently decide
> that traffic is malicious."

## 10. Demo (2-3 min)

    docker compose -f infra/docker-compose.yml up -d
    docker compose -f infra/docker-compose.yml logs -f control_plane

Drive demo traffic from a 203.0.113.x documentation address. The writer
correctly refuses to police private or loopback ranges, and Docker Desktop would
otherwise collapse host traffic to a private peer.

For a gateway-independent backup, seed evidence and run one cycle:

    cd control-plane
    PYTHONPATH=. .venv/bin/python -m tools.seed_evidence --scenario credential-stuffing
    PYTHONPATH=. .venv/bin/python -m iasg --once

Point out the campaign, its risk/confidence explanation, the recommendation,
and the policy expiry. Do not claim that a narrated paragraph made the decision.

## Questions you may get

**"Why not decide in the gateway?"**

> "History, correlation, and models are too slow and failure-prone for every
> request. The gateway only observes and enforces cached decisions. It never
> waits on thinking."

**"Is reputation enough to block someone?"**

> "No. It is optional supporting evidence. It can firm up a recommendation that
> deterministic observed evidence already earned, but it cannot originate
> enforcement."

**"Can the anomaly model block somebody?"**

> "Not by itself. No deterministic evidence means monitor, its score is excluded
> from policy confidence, and a model-assisted block has an additional
> strong-anomaly check."

**"Where is the LLM in the decision?"**

> "Nowhere. It runs after policy selection and writing, to narrate the outcome
> for a person. The offline template provider is the safe default."

**"What happens if the control plane dies?"**

> "The gateway continues serving and enforcing its cached policies until their
> TTLs expire. No request fails because the thinking lane is unavailable."
