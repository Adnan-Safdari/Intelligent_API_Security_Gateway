# Anomaly Feature Specification

| | |
| --- | --- |
| **Spec version** | `v1` |
| **Written against** | `aaddadb`, 2026-09-06 |
| **Implemented by** | `control-plane/iasg/anomaly/` |

**This document is the contract, not the code.** If the extractor and this page
disagree, the extractor is wrong. A feature whose meaning changes gets a new
spec version and a new dataset; it does not get edited in place, because a model
trained on `v1` has no way to notice that column 9 started meaning something
else.

## Scope

One row is **one resolved client address's activity during one non-overlapping
60-second window**.

| Decision | Specification |
| --- | --- |
| One row represents | One resolved client identity's activity in one 60-second window |
| Window type | Non-overlapping, aligned to `:00` UTC — `12:00:00–12:01:00`, `12:01:00–12:02:00` |
| Window membership | Arrival time falls within `[window_start, window_end)` |
| Client identity | The gateway's resolved client identity (`internal/netutil`), trusted-proxy aware |
| Model inputs | Twelve numerical behaviour summaries, nothing else |
| Model output | An anomaly score on the risk convention (higher = worse) |
| Execution | Python control plane, off the synchronous Go request path |

**The address groups requests; it is never a feature.** It is not in the feature
array in any form — not as an integer, not hashed, not bucketed. Two reasons: a
model that learns addresses learns this lab's address pool rather than
behaviour, and one address can be a whole office behind a shared network.

Scoring necessarily waits for the window to close, so an assessment can be up to
sixty seconds behind the traffic it describes, plus the control plane's own
cycle delay. That is acceptable because nothing waits on it — the Go detectors
and the enforcer handle the request path throughout, exactly as they do now. See
[Detection Signals](detection-signals.md) and
[Policy Enforcement](policy-enforcement.md).

## The time contract

Two instants matter per request, and confusing them is the main way this
specification can be implemented wrongly.

| Instant | Meaning | Field |
| --- | --- | --- |
| **Arrival** | The gateway first saw the request, before any middleware ran | `arrivalTs` |
| **Completion** | The whole chain returned and the record was built | `ts` |

**Windowing uses `arrivalTs` exclusively.** A request is in the window it
arrived in, whatever happened afterwards.

A wrinkle worth stating plainly: the telemetry event's `ts` field has always
been a *completion* time despite its generic name. It keeps that name and that
meaning, because the console reads it. `arrivalTs` was added for this
specification.

## Definitions

These are referenced by the feature table and are stated once here.

**Arrival gap.** Sort a window's requests by `arrivalTs`, then take the
milliseconds between consecutive arrivals. N requests give N−1 gaps.

**Population standard deviation.** `ddof = 0`. Named explicitly so nobody has to
guess which convention a library defaulted to.

**Path.** `r.URL.Path` as Go produced it: percent-decoded once by `net/url`,
query string removed, **not lexically cleaned**, not case-folded, trailing slash
significant.

`/api/../../etc/passwd` therefore keeps its `..` segments. This is deliberate
and load-bearing: collapsing them before measuring path diversity would erase
exactly the behaviour a traversal probe exhibits, and would leave the anomaly
layer blind to the thing the traversal detector exists to catch. The proxy chain
does not route through `ServeMux`, which is the only thing in `net/http` that
would clean the path, so recording it unchanged is a property to hold rather
than code to write.

*Known limitation:* a double-encoded `%252e` decodes once to the literal text
`%2e` and stays that way. It is a distinct path from `..` and is counted as one.

**Route template.** The configured template a path matched — `/api/products/12`
and `/api/products/34` both match `/api/products/{id}` — or the reserved literal
`<unmatched>`. Templates keep ordinary variation in resource identifiers from
looking like a client visiting hundreds of different endpoints. The table is
configured under `routes:` in `configs/config.yaml` and is **structural**:
changing it changes what past telemetry means, which is why it is read at boot
and is not live-reconfigurable through the settings watcher.

Matching is by **specificity, not configuration order** — the candidate with the
most literal segments wins, so `/api/products/search` beats
`/api/products/{id}` regardless of how the YAML is ordered. A tie is a
configuration error and fails at boot.

**Upstream duration.** From the instant the gateway begins the backend request
until that response's body has finished being read. **The same definition is
used at collection time and at deployment time**, because it is produced by one
transport wrapper (`internal/proxy/upstream.go`) that does not know which is
happening.

**Login attempt and failed login.** Derived from the endpoint's verified
behaviour, configured under `routes.auth_outcomes`, never inferred from a status
code in general. For `POST /api/login`, `vulnerable-app/backend/routes/auth.js`
returns 200 on success, 401 with `Invalid email or password`, and 500 on a
database error. So:

| Backend status | Outcome |
| --- | --- |
| 200 | `success` |
| 401 | `invalid_credentials` |
| anything else, or no backend response | `unknown` |

This mapping is configuration and must be re-verified if the backend changes. A
401 elsewhere is not a failed password attempt.

## The twelve features

`N` is the number of requests from that client whose arrival fell in the window.
Every ratio is in `[0, 1]`.

### 1. `request_count`

`N`. A window with no requests is not a row — an inactive client produces
*absence*, not a zero. Creating zero rows for every idle address would bury the
dataset in samples of nothing happening.

### 2. `peak_1s_requests`

Divide the window into 60 one-second buckets, `floor((arrival_ts − window_start))`
in seconds, buckets 0–59. Take the largest bucket count. Empty seconds count
as 0.

This is what separates 60 requests spread evenly from 60 requests in one second,
which `request_count` alone cannot see.

### 3. `interarrival_cv`

Population standard deviation of the arrival gaps ÷ mean gap.

**Null** when there are fewer than 3 requests (fewer than 2 gaps) or the mean
gap is zero. A coefficient of variation is undefined without a positive mean,
and inventing one would place a value where there is no measurement.

### 4. `unique_path_ratio`

Distinct paths (query string excluded) ÷ `N`.

An **empty path is a telemetry defect**, not a value. It fails the dataset build
in strict mode and is counted in the quality metadata otherwise. A path is
always present in a well-formed record.

### 5. `dominant_route_ratio`

Requests to the most-used `(method, route_template)` pair ÷ `N`.

All unmatched requests of the same method share the `<unmatched>` bucket, which
is a **documented real category and not a null**. A scanner walking paths that
match no template produces a large `<unmatched>` bucket, which is itself
informative — treating it as missing data would discard that.

### 6. `post_ratio`

POST requests ÷ `N`. **0** when there are none.

### 7. `login_ratio`

`POST /api/login` requests ÷ `N`. **0** when there are none.

### 8. `login_failure_ratio`

Confirmed `invalid_credentials` outcomes ÷ login attempts **with a known
outcome**.

- **0** when no login was attempted.
- **Null** when logins occurred but none has a known outcome.

The denominator is deliberately not "all login attempts". A login the gateway
refused never reached the backend, so its outcome is unknown, and counting it as
a non-failure would let blocking an attacker make their failure ratio look
better.

### 9. `backend_404_ratio`

Backend responses with status 404 ÷ backend responses with a known status.

**Null** when no backend statuses are available.

### 10. `backend_5xx_ratio`

Backend responses with status 500–599 ÷ backend responses with a known status.

**Null** when no backend statuses are available.

For both: **gateway-generated statuses are excluded from the numerator and the
denominator.** A 403 the enforcer wrote, a 429 from the rate limiter, a 413 from
the body cap and a 502 from an unreachable backend are the gateway talking about
itself, and mixing them into backend response statistics would mean enforcement
changed the features of the address it enforced against. See
[Zero versus unknown](#zero-versus-unknown).

### 11. `mean_request_body_bytes`

Sum of completely measured request-body sizes ÷ number of completely measured
bodies.

- A **confirmed empty body is 0** and counts toward the denominator.
- A refused or unreadable body is **unknown** and counts toward neither.

### 12. `p95_upstream_duration_ms`

Sort the completed upstream durations ascending and take position
`ceil(0.95 × count)`, **one-based**.

| count | index | note |
| --- | --- | --- |
| 1 | 1 | the only value |
| 20 | 19 | |
| 21 | 20 | |

**Null** when no completed durations are available. A request that timed out has
no duration, and one is never invented for it.

### A note on what is deliberately absent

There is no "average requests per second" feature. With a fixed 60-second
window it is `request_count / 60` — the same number twice, which teaches a model
nothing and costs a column.

## Zero versus unknown

These are different observations and the extractor must never conflate them.

| Situation | Feature value | Quality field affected |
| --- | --- | --- |
| No login requests occurred | `login_ratio` and `login_failure_ratio` are **0** | — |
| Logins occurred, outcomes unavailable | `login_failure_ratio` is **null** | `login_attempts_known_outcome` |
| A request definitely had no body | body size **0**, counted | `complete_body_measurements` |
| Body measurement truncated or refused | body size **unknown**, not counted | `complete_body_measurements` |
| Gateway-generated 403 / 429 / 413 / 502 | **not** a backend response; in no backend ratio | `known_status_count` |
| Backend request timed out | a recorded timeout; **no** status, **no** duration | `timeouts` |
| Request still in flight at scoring time | counts toward arrival features only | `pending_at_scoring` |

**Unknowns stay `null` in extracted records.** Imputation happens later and
elsewhere: at vectorisation time, using medians learned **only from the training
partition** and reused byte-identically at runtime from `medians.json`. A median
computed over the whole dataset would leak the test partition into the model
through the back door.

If a feature has no usable training measurements at all, fix its collection or
remove it from the schema before freezing. **Median replacement cannot repair a
broken telemetry pipeline** — it will happily produce a full column of the same
number and hide the fact that nothing was ever measured.

### How the gateway makes this distinguishable

`responseOrigin` is **derived, not inferred**: `backend` if and only if the
gateway actually attempted the upstream request and received a status;
`gateway` otherwise.

This matters because inference from `decision` and `status` is not sufficient. A
policy 403 is inferable, and so is a 429. But a 413 from the body cap and a 400
from an unreadable body both record `decision: "allow"` and no policy match, and
are otherwise **indistinguishable from backend statuses of the same number**.
A body-limit refusal never reaches the transport, so `upstreamAttempted` is
false and the answer is unambiguous regardless of what `decision` says.

## Quality metadata

Carried alongside every row, never in the feature array.

| Field | Meaning |
| --- | --- |
| `known_status_count` | Backend responses with a status, settled at scoring time |
| `login_attempts` | Total login attempts in the window |
| `login_attempts_known_outcome` | Denominator of feature 8 |
| `complete_body_measurements` | Denominator of feature 11 |
| `complete_duration_measurements` | Denominator of feature 12 |
| `pending_at_scoring` | Arrived in-window, not yet settled |
| `timeouts` | Upstream timeouts |
| `telemetry_dropped_in_window` | Telemetry the gateway dropped rather than delaying traffic |
| `interval_fully_observed` | The whole 60 seconds was observed, with no gap, drop or stream trim |
| `insufficient_history` | `1 ≤ request_count ≤ 2` |
| `telemetry_defects` | Malformed records, e.g. an empty path |

These exist to separate *an incomplete measurement* from *unusual behaviour*.
Without them a collection outage looks exactly like an address that went quiet.

Two behavioural rules:

- **A window with `N = 0` is not created at all.**
- **Windows with 1–2 requests are retained**, marked `insufficient_history`, and
  **abstain from ML scoring**. This is a coverage rule, not an attack threshold:
  a two-request window has no meaningful inter-arrival statistics. Report how
  much traffic it excludes. The Go detectors still inspect those requests, so
  abstaining costs no coverage on the request path.

`telemetry_dropped_in_window` deserves a caveat. The gateway's drop counter is
**process-wide**, so the flag is window-wide and **cannot be attributed to a
particular address**. It says "something was lost during this minute", which is
enough to distrust every row in that minute and not enough to say whose.

## Leakage and availability

A request arrives at `12:00:59` and its response completes at `12:01:02`. The
window is scored at `12:01:00`.

At that instant:

- Its arrival contributes to `request_count`, `peak_1s_requests`,
  `interarrival_cv`, `unique_path_ratio`, `dominant_route_ratio`, `post_ratio`
  and `login_ratio`.
- Its status, body measurement and duration are **not available**, and it
  contributes to none of features 8–12.
- `pending_at_scoring` counts it.

**The offline extractor must reproduce that state exactly.** Filling that
training row in with the response that arrived two seconds later produces a
model that expects information the runtime will never have, and the failure is
silent: offline metrics look good and production quietly underperforms.

The mechanism is structural rather than disciplinary. Arrival and completion are
recorded as **separate observations joined by `requestId`**, each preserving
when it became available, and there is exactly one function:

```python
def extract(records, window_start, as_of) -> WindowRow
```

Runtime passes `as_of = now`. The dataset build passes `as_of = window_end`.
Inside, one predicate governs everything:

```python
def _settled(r, as_of):
    return r.completed_ts is not None and r.completed_ts <= as_of
```

Arrival-derived features use every in-window record; completion-derived features
use only settled ones. **The offline extractor cannot cheat because it has no
code path that would let it** — there is no second implementation to drift.

## Label independence

Labels come from the run manifest — run id, scenario, attacker addresses, and
attack-active intervals — all recorded **before traffic starts**.

**Labels are never derived from detector output**, `fired`, `riskScore`,
`decision`, or HTTP status. A dataset labelled by the detectors can only teach a
model to reproduce the detectors, including their mistakes, and it would score
well while being worthless: the whole point of this layer is to catch what the
detectors miss.

`run_id`, `scenario`, attack interval, label, address, timestamps, detector
scores, campaign confidence and enforcement decisions are **dataset metadata and
never model inputs**. That guarantee is physical: they live in a different file
from the feature matrix, and the build fails if `features.csv` has any column
that is not one of the twelve.

A high `login_failure_ratio` does not make a row an attack. A genuine user who
mistypes a password three times produces one, and the training set contains that
case on purpose.

## Score authority

The anomaly score is worth **at most one rung**, and only on a campaign that
already earned an action on evidence alone. It **never originates enforcement**.

This mirrors `reputation_bias` in `control-plane/iasg/policy/agent.py`, for the
same reason and with the same clamp: an unsupervised model fit on a small
laboratory dataset is the last input that should be trusted to block somebody by
itself. It returns 0 when the evidence alone would only monitor, and the
promotion clamp means it cannot compound with the reputation or learned bias.

Two further constraints:

- It is an **anomaly score on the existing risk convention** (higher = worse),
  not a trust score and not a competing scale. See `project-context.md` §14.
- It runs entirely in Python, off the request path. No `internal/trust` or
  `internal/decision` package is introduced; that layer was considered and
  deliberately not built.

`control-plane/iasg/policy/writer.py` remains the only code that can influence
the gateway, and all of its rails — no private or reserved addresses, no policy
without a TTL, the per-cycle cap, dry-run — apply unchanged to any policy a
campaign carrying an anomaly bias produces.

## Divergences and known gaps

Stated so they are not discovered later and mistaken for bugs.

**The brute-force detector and this spec count login failures differently.**
`internal/signals/brute_force.go` treats 401 **or** 403 as a failure; this
specification counts only 401. Today the difference is inert — the policy
enforcer sits outside the detectors, so a policy 403 never reaches brute force,
and the backend's `/api/login` never returns 403. The detector is deliberately
**not** being changed to match: it feeds campaign formation, and altering what
it counts would change which campaigns form.

**`backendMs` conflates zero with unknown.** It now carries the true upstream
duration and reads 0 when there was none, which is fine for a console column and
wrong for a feature. `p95_upstream_duration_ms` reads the nullable
`upstreamDurationMs` and never `backendMs`. Whole-chain latency, which
`backendMs` used to hold under a name that claimed otherwise, is now `gatewayMs`.

**These features describe behaviour and cannot identify every malicious
payload.** A single SQL injection request may have entirely ordinary timing,
size, path diversity and response status — there is nothing anomalous about
one request. The deterministic detectors are not replaced by this layer and
must keep running alongside it.
