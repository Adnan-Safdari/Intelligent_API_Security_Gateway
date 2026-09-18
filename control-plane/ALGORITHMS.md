# Control plane algorithms

The control plane reasons asynchronously from bounded gateway evidence. The
gateway never waits for it.

| Mechanism | Purpose | It does not do |
| --- | --- | --- |
| Deterministic gateway evidence | Recognise known attack shapes and publish evidence | Refuse the request being inspected |
| Adaptive endpoint baseline | Learn a safe normal rate for each route | Learn from attack or enforcement-distorted traffic |
| Campaign correlation | Group related evidence into continuing campaigns | Treat each IP or each cycle as a separate incident |
| Risk/confidence policy engine | Select a bounded monitor, throttle, or temporary-block response | Let reputation or narration originate enforcement |

## Baselines

Trusted completed windows update a per-method/per-route rolling baseline using
`median + MAD multiplier * max(MAD, minimum MAD)`. Warm-up, lower and upper
bounds, hysteresis, and cooldown prevent one unusual window from redefining
normal. Baseline deviation is an input to risk, never autonomous authority.

## Campaign correlation

The correlator creates a profile for each address and links profiles only when
their activity overlaps in time and enough identity traits agree. Union-Find
turns these links into campaigns. Jaccard overlap preserves continuity when
members overlap; a stricter behavioural signature handles address rotation.

## Risk, confidence, and policy

Risk combines deterministic evidence, baseline deviation, and campaign facts.
Confidence is calculated independently. No deterministic evidence always
results in monitor. The lifecycle stages a recommendation according to monitor,
manual, or automatic mode; the simulator and policy writer then apply address,
TTL, duration, and collateral-safety rails before Redis is changed.

## Narration is outside the decision

The optional language provider writes an explanation only after policy
selection. Its output is never read by risk, confidence, or enforcement.
