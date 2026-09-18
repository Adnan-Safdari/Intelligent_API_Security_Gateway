# Changes since September 1, 2026

This changelog covers every commit reachable from `HEAD` whose commit timestamp
is on or after 2026-09-01, through `77365c6`. Dates use the commit timestamp in
Asia/Kolkata, rather than the author timestamp, so rebases and merges remain in
the order in which they entered this history. Several telemetry commits authored
late on September 6 were committed together on September 7. There were no
commits in scope on September 1-5 or September 8.

Merge commits are described with the changes they actually introduced relative
to their first parent. Their contents are not repeated as separate features when
the underlying commits are also in this period.

## 2026-09-06

### Features added

- Merged the LLM narration, IP reputation, request-path hardening, and shared
  quota work in PR #15 (`2a6e8e9`). The control plane gained bounded Ollama
  narration for explanations and assessments, with per-call timeouts, a
  per-cycle time budget, template fallback, and reporting when calls are
  skipped (`control-plane/iasg/reasoning/budget.py`). Narration remains after
  policy selection and cannot feed back into enforcement.
- Added a gateway IP-reputation subsystem that accepts addresses and CIDRs from
  a checked-in file plus an optional remote feed
  (`gateway/internal/reputation/`). Remote data is unioned with the bundled
  list, refreshed in the background, and the last valid remote list survives a
  fetch failure. The detector scores a listed address on every request but
  emits fresh evidence only once per cooldown
  (`gateway/internal/signals/ip_reputation.go`). Reputation cannot create a
  block by itself; in the control plane it may firm up an evidence-backed
  action by at most one rung.
- Added replica-wide adaptive quotas backed by an atomic Redis token-bucket Lua
  script (`gateway/internal/policy/redis_limiter.go` and `token_bucket.lua`).
  Buckets are scoped by client, normalized route, method, and policy generation;
  quota checks have a strict Redis timeout, no retries, a recovery probe/backoff,
  and fail open when Redis is unavailable.
- Added bounded asynchronous telemetry delivery
  (`gateway/internal/telemetry/async.go`) so Redis writes use a fixed queue and
  timeout and overload drops telemetry instead of delaying API traffic or
  creating unbounded goroutines.
- Added a configurable request-body cap, defaulting to 1 MiB, ahead of every
  body-buffering stage (`gateway/internal/proxy/bodylimit.go`). It preserves the
  important ordering in which policy enforcement can reject an address before
  its body is read.

### Features modified

- Reworked policy throttling to consume the shared Redis quota instead of
  sleeping on the synchronous path. Existing policy snapshots remain local and
  background-refreshed; Redis accounts for a decision already made rather than
  making the decision.
- Policy quota expiry now follows the actual remaining policy TTL. The Lua
  script verifies the cached policy value and TTL before charging a request, so
  a deleted, replaced, or expired policy cannot continue throttling through a
  stale snapshot.
- The dashboard settings surface and live settings wire format were extended to
  carry reputation and request-path hardening settings.

### Bug fixes

- Prevented an accepted request with an unbounded body from exhausting gateway
  memory before detectors or telemetry finished reading it.
- Prevented a transient reputation-feed failure from clearing the last known
  good list, and made an unavailable remote feed fall back to the bundled list.
- Prevented slow Redis telemetry writes from adding request latency; queue
  overflow is counted and rate-limited in logs.
- Removed tracked repository cruft (`aaddadb`): the 86 MB `JMeter.zip`, a
  credential-bearing `gateway/.env`, and the obsolete
  `gateway/docs/chatgpt-handoff-prompt.md`. Environment-file ignore rules were
  enabled and the documentation navigation/context was cleaned up accordingly.

### Security/enforcement changes

- Preserved the architectural boundary that detectors only emit evidence.
  Reputation is not an independent enforcement authority, and its control-plane
  bias cannot turn a monitor-only campaign into enforcement.
- Exhausted quotas are refused before body inspection. Redis failures still
  fail open within a bounded time, avoiding a new external dependency on the
  synchronous path.
- Request bodies are capped below the enforcer, so blocked clients are rejected
  without body reads while all accepted body readers remain protected.

### Configuration changes

- Added `enforcement.adaptive_rate_limit` settings for fallback RPM, burst,
  Redis timeout, refresh timeout, failure backoff, cache age, and bucket prefix.
- Added `enforcement.ip_reputation` settings for enablement, local feed path,
  optional URL, refresh/fetch timing, score, and evidence cooldown, together
  with `gateway/configs/reputation.txt`.
- Added Redis telemetry queue size/write timeout and configurable maximum body
  size settings to the gateway configuration and examples.
- Added control-plane LLM provider, Ollama URL/model, timeout, and narration
  budget settings. Compose defaults narration to host Ollama but permits the
  null provider.

### Infrastructure/Docker changes

- Updated `infra/docker-compose.yml` so the control plane can reach host Ollama
  through `host.docker.internal`, including Linux's `host-gateway` mapping.
- Carried the new gateway reputation, quota, body-limit, and telemetry settings
  through the Compose runtime configuration.

### Testing changes

- Added property and integration coverage for Redis quota sharing, per-route and
  per-method limits, policy expiry, Redis failure/backoff, and token-bucket
  behavior.
- Added tests for body-limit ordering, oversized and malformed bodies, policy
  rejection before reads, enforcement configuration propagation, snapshot
  expiry, and asynchronous telemetry overload.
- Added tests for reputation parsing, CIDR matching, bundled/remote union,
  refresh failure retention, detector cooldown, live configuration, and the
  rule that reputation cannot invent enforcement.
- Expanded control-plane narration tests for timeouts, budget exhaustion,
  provider failure, and template fallback, plus reputation-policy bias tests.

### Documentation changes

- Added repository-wide agent working notes and invariants in `AGENTS.md`, plus
  `control-plane/PRESENTATION.md`.
- Updated the gateway README and the control-plane, request lifecycle, reverse
  proxy, policy enforcement, signal, Docker, architecture, and project-context
  documentation to match the merged runtime behavior.
- Removed references and MkDocs exclusions for the deleted handoff prompt.

Commits covered: `180fbd0`, `2a6e8e9`, `aaddadb`.

## 2026-09-07

### Features added

- Added boot-time route-template compilation and specificity-based matching
  (`gateway/internal/telemetry/route.go`). Telemetry now records normalized
  routes such as `/api/products/{id}` and explicitly categorizes unmatched paths
  as `<unmatched>`, while preserving the raw path for security analysis.
- Added true upstream measurements using a transport wrapper
  (`gateway/internal/proxy/upstream.go`): backend duration ends when the response
  body reaches EOF, total gateway duration is separate, failed upstream calls
  remain unknown, and every response is attributed to either the backend or the
  gateway. Request-body bytes and configured login outcomes are also recorded.
- Added pre-handler arrival telemetry in the independent `iasg:arrivals` stream
  and a once-per-second `iasg:telemetry:health` heartbeat
  (`gateway/internal/telemetry/arrival.go` and `health.go`). This makes windows
  depend on when a request arrived, includes in-flight/refused requests, and
  exposes queue drops, sequence gaps, and in-flight counts without adding Redis
  I/O to the request path.

### Features modified

- Generalized the asynchronous writer and gateway startup wiring for separate
  arrival and completion queues while keeping the existing console, counters,
  and evidence consumer on `iasg:events`.
- Extended the store interfaces and memory/Redis implementations with the
  consumer-group, stream-head, group-cursor, trim, and acknowledgement
  operations needed by capture.
- Added optional `ATTACK_IP` handling to the detector-driving shell helpers so
  tests can use RFC 5737 documentation addresses that are eligible for policy
  writing.

### Bug fixes

- Fixed the evidence consumer so every Redis entry read is acknowledged after a
  successful cycle, including clean entries that produced no `Evidence`
  (`90b749a`). Read IDs are retained if acknowledgement fails, and crash replay
  semantics remain intact.
- Extracted telemetry sink construction from gateway startup and added a
  reflection-based wiring guard (`gateway/internal/proxy/telemetry_sinks.go`).
  This prevents a configured stream from silently receiving no writes and
  verifies the health reporter observes the actual queue instances.

### Security/enforcement changes

- Separated backend outcomes from gateway-generated 400/403/413/429 responses,
  preventing enforcement from changing the backend-error features of the same
  address it enforces against.
- A gateway-refused login is now an attempted login with unknown credential
  outcome, not a success. Only configured backend statuses count as success or
  invalid credentials, preventing a block from artificially improving an
  attacker's failure ratio.
- Arrival writes use only a non-blocking queue send; a dead or overloaded Redis
  loses observable telemetry and records the loss rather than delaying traffic.

### Configuration changes

- Added top-level normalized route definitions and per-route authentication
  success/failure status mappings to `gateway/configs/config.yaml` and its
  example.

### Infrastructure/Docker changes


### Testing changes

- Added route matching tests for specificity, ambiguity, segment bounds,
  unmatched routes, and preservation of traversal paths.
- Added upstream timing/origin, body-size, login-outcome, arrival, heartbeat,
  queue, sink-wiring, and policy-before-body regression tests, including race
  coverage for live detector state.

### Documentation changes

- Rewrote `control-plane/ALGORITHMS.md` around trust boundaries and failure
  prevention, documented known analytical limits, and corrected source anchors
  and test counts.
- Corrected `AGENTS.md` to state the real body-limit ordering, the tracked
  status of `gateway/configs/config.yaml`, and the three-stream telemetry model.

Commits covered: `ade0da8`, `90b749a`, `8148536`, `e8a7069`, `1840af9`,
`52df62a`, `f4ba6a2`, `b3cf617`, `a010ae6`, `5e9c544`, `b10aa08`,
`a5f8768`, `140c465`, `ad3c4e0`, `8596764`, `ee6eb8a`, `3675222`.

## 2026-09-09

### Features added

- Added adaptive policy generation and analyst-controlled enforcement
  (`cd0666d`). The control plane now consumes completed 60-second windows,
  maintains endpoint/method rolling median-and-MAD baselines, uses warm-up,
  hysteresis, and threshold-change cooldowns, and learns only from windows
  considered safe.
- Added a validated 0-100 adaptive risk calculation combining deterministic
  evidence, endpoint deviation, and campaign facts. Policy confidence is
  calculated separately from deterministic evidence and campaign correlation
  (`control-plane/iasg/adaptive/risk.py`).
- Added monitor, manual, and automatic operating modes plus a durable policy
  recommendation lifecycle. PostgreSQL now stores versioned settings,
  endpoint baselines, pending/approved/active/expired/revoked recommendations,
  and an audit trail (`control-plane/migrations/0002_adaptive_policy.up.sql`).
- Added the adaptive dashboard at `gateway-dashboard/app/(console)/adaptive/`.
  Operators can inspect baselines and explanations, edit validated settings,
  approve/edit/reject pending recommendations, inspect active policies and
  audit history, and queue emergency allow/block overrides.
- Added endpoint-scoped policy support. The control plane hashes method/route
  scope into bounded Redis keys; the Go snapshot indexes the explicit target
  and normalized endpoint; manual and approved decisions outrank adaptive ones,
  and the more specific endpoint policy wins within the same origin
  (`gateway/internal/policy/store.go`). Policy telemetry now includes policy and
  campaign IDs, risk, confidence, mode, issuer, and normalized scope.

### Features modified

- Policy decisions gained stable policy IDs, target/scope, risk and confidence,
  issuer/mode, baseline/config versions, supersession, expiry, and a
  structured explanation. The Go gateway accepts both legacy `temp_block` and
  the adaptive Redis wire spelling `temporary_block` during migration.
- Policy deletion from the dashboard now validates addresses with Node's IP
  parser, deletes both address-wide and bounded endpoint-scoped siblings, and
  records durable revocation status/audit entries when PostgreSQL is available.
- The admin reset now clears adaptive audit/recommendation/baseline tables and
  trims the arrival, health, evidence, override, and alert streams without
  deleting consumer groups. Live `policy:*` keys remain deliberately separate.

### Bug fixes

- Fixed unedited approval of an adaptive temporary-block recommendation
  (`d0cc08c`). PostgreSQL payloads now retain canonical `temp_block`, while only
  the Redis policy serializer rewrites it to `temporary_block` for the Go wire
  contract.

### Security/enforcement changes

- Centralized adaptive safety checks again at `control-plane/iasg/policy/writer.py`,
  the only boundary allowed to affect the gateway. It rechecks mode, automatic
  action ceiling, TTL/duration, confidence, deterministic evidence counts,
  throttle bounds, private/reserved-address rules, emergency allowlists, dry-run,
  and the per-cycle write cap immediately before writing Redis.
- Automatic policy actions are limited to monitor, throttle, or temporary
  block. Monitor never writes an enforcing key; manual mode requires analyst
  approval; automatic mode writes only guardrail-compliant non-monitor actions;
  and emergency manual overrides have explicit precedence.
- Policies remain self-expiring and are never renewed. Same-scope active or
  pending recommendations are suppressed until expiry or the configured change
  cooldown; approval delay consumes the original bounded enforcement window
  rather than granting a fresh TTL.
- Baseline-derived throttles are bounded by configured RPM limits and still
  require deterministic evidence and confidence for enforcement.
- Analyst escalation remains an alert layered over a bounded throttle/block;
  it does not create a stronger fourth automatic gateway action.

### Configuration changes

- Added complete adaptive JSON configuration in
  `control-plane/configs/adaptive.json.example`: baseline windows and MAD
  parameters, risk weights and detector points, score thresholds, confidence
  weights, action/duration/RPM ceilings, evidence thresholds, change
  cooldowns, analyst escalation thresholds, and emergency CIDR lists.
- Added environment settings for arrival/health streams, window consumer group
  and grace period, and adaptive JSON/path input in `control-plane/.env.example`.
- Adaptive settings are persisted and versioned in PostgreSQL. Dashboard saves
  validate the complete schema and use optimistic version checks so a stale
  page cannot overwrite a newer configuration.

### Infrastructure/Docker changes

- Compose installs the `postgres` extra and supplies telemetry-health settings.
- Extended the collection profile with seed and sessions-per-persona controls
  and a capture deadline longer than traffic, preventing the final in-flight
  completions from being misread as a quiet partial window.

### Testing changes

- Added `control-plane/tests/test_adaptive_enforcement.py`, covering baseline
  warm-up/learning safety, median/MAD thresholds, hysteresis, risk/confidence
  separation, all three modes, action ceilings, evidence guardrails,
  emergency lists, scope/cooldown/expiry, no-renewal behavior, analyst approval,
  writer revalidation, and dry-run/per-cycle caps.
- Added Go adaptive-policy tests for legacy and expanded wire formats,
  `temporary_block`, endpoint matching, policy precedence, normalized routes,
  telemetry metadata, and body-before-enforcement ordering.
- Expanded PostgreSQL tests for adaptive configuration, baselines,
  recommendations, lifecycle/audit durability, approval, and canonical-versus-
  wire action serialization.

### Documentation changes

- Added `gateway/docs/network-level-blocking.md`, explaining why L7 enforcement
  remains the default behind trusted proxies and why pre-HTTP drops would lose
  client identity and telemetry.
- Added `gateway/docs/adaptive-policy.md` and updated the policy and
  system-architecture documentation for adaptive baselines, guardrails,
  lifecycle, and endpoint-scoped policies.
- Added `attack-detection-options.pdf`, which evaluates deterministic follow-up
  rules on v4. The recommended unmatched-route and consecutive failed-login
  rules catch 65 of 76 gateway-missed attack minutes with no observed false
  positives; the remaining missed traffic is documented for future detector work.
  The document recommends implementing those behaviors in the deterministic Go
  detectors instead of adding another classifier or LLM decision path.
- Updated MkDocs navigation for adaptive-policy and network-blocking material.

Commits covered: `d26e0ba`, `c9c37a2`, `5de1eb0`, `9efe91f`, `c2d22df`,
`56a6585`, `cd0666d`, `d0cc08c`, `a1362ee`, `4a9a055`, `f4b13c5`,
`ffdf273`, `680b397`, `ee9ec0b`, `e50ed84`, `e237e7b`, `77365c6`.

## Uncommitted (2026-09-09)

### Features added

- None.

### Features modified

- None.

### Bug fixes

- None.

### Security/enforcement changes

- None.

### Configuration changes

- None.

### Infrastructure/Docker changes

- None.

### Testing changes

- None.

### Documentation changes

- Added this `CHANGES.md`. The worktree was otherwise clean before the file was
  created.
