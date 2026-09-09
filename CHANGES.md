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
- Added the versioned anomaly feature implementation under
  `control-plane/iasg/anomaly/`. A single extractor serves offline builds and
  runtime scoring and initially produces 12 ordered features: request count,
  one-second peak, inter-arrival variation, path/route diversity, POST and login
  ratios, known login failure ratio, backend 404/5xx ratios, mean measured body
  size, and p95 upstream duration. Unknown measurements remain null until
  training-partition median imputation.
- Added quality metadata for measurement coverage, pending requests, timeouts,
  telemetry loss/gaps, insufficient history, and malformed records. These
  fields are kept out of the model input.
- Added durable three-stream capture under `control-plane/iasg/dataset/` using
  its own Redis consumer groups. Capture writes, flushes, and fsyncs before
  acknowledging, redelivers unacknowledged entries after failure, detects stream
  trimming numerically, and records loss in the run manifest.
- Added the frozen dataset builder. It derives labels only from the traffic
  plan, groups address histories wholly into deterministic train/validation/test
  splits, keeps attacks out of training, forces reserved low-and-slow scenarios
  into test, derives medians only from training, separates features from
  identifying/label metadata, writes an evaluation plan before fitting, hashes
  artifacts, and refuses to rebuild a `FROZEN` directory without an explicit
  override.
- Added a Compose-based traffic laboratory under `testing/traffic/` with nine
  benign personas and seven attack scenarios. Personas deliberately cover
  behavior that simplistic rules misclassify—failed human logins, legitimate
  dead links, and regular mobile polling. Address identity is preflight-tested,
  attack labels are written before traffic, and held-out attacks use separate
  pools.
- Froze `datasets/v1`, the first real gateway-derived dataset: 85 rows from one
  180-second run, 25 distinct sessions, and 5,042 requests, with no reported
  telemetry drops or trim loss.

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
- Fixed four live-collection failures (`8596764`): Compose commands that YAML
  had split across lines, an unquoted `redis>=5.0` shell requirement, missing
  `RUN_ID`/duration environment forwarding, and a `depends_on` path that could
  recreate the gateway with the small default stream limits. Capture now loads
  environment settings instead of silently targeting localhost.
- Made the real dataset build execute its leakage checks before writing
  `FROZEN`, rather than relying on tests that used synthetic rows.

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
- Added `gateway/configs/config.collect.yaml`, selected with `IASG_CONFIG`, with
  200,000-entry arrival/completion streams and a 16,384-record telemetry queue.
  Detection and enforcement thresholds remain the normal gateway settings.
- Added `datasets/raw/` to `.gitignore` while keeping frozen versioned datasets
  trackable.

### Infrastructure/Docker changes

- Added the Compose `collect` profile with traffic-generator and capture
  services running inside the Compose network, where trusted forwarded client
  addresses survive Docker Desktop source-NAT behavior.
- Added run ID, traffic duration, capture duration, Redis connection, and
  collection configuration wiring for repeatable capture runs.

### Testing changes

- Added route matching tests for specificity, ambiguity, segment bounds,
  unmatched routes, and preservation of traversal paths.
- Added upstream timing/origin, body-size, login-outcome, arrival, heartbeat,
  queue, sink-wiring, and policy-before-body regression tests, including race
  coverage for live detector state.
- Added broad anomaly tests that recompute all 12 features and quality counters,
  enforce runtime/offline availability equivalence, preserve null semantics,
  pin vector order/spec versions, and reject identity or detector leakage.
- Added dataset capture/build tests for fsync-before-ack durability, crash
  redelivery, trim loss, malformed records, deterministic group splitting,
  reserved scenarios, training-only medians, manifests, and frozen-directory
  protection.
- Added traffic-persona tests that execute plans through the real extractor and
  verify each persona or held-out scenario continues to exercise its intended
  behavioral property.

### Documentation changes

- Added the anomaly feature contract at `gateway/docs/anomaly-features.md`,
  including zero-versus-unknown semantics, arrival/completion availability,
  label independence, and the rule that a model is only advisory.
- Rewrote `control-plane/ALGORITHMS.md` around trust boundaries and failure
  prevention, documented known analytical limits, and corrected source anchors
  and test counts.
- Added `testing/traffic/README.md` and expanded Redis telemetry documentation
  for the three streams, their consumers, health data, and safe `XTRIM` reset.
- Corrected `AGENTS.md` to state the real body-limit ordering, the tracked
  status of `gateway/configs/config.yaml`, and the three-stream telemetry model.

Commits covered: `ade0da8`, `90b749a`, `8148536`, `e8a7069`, `1840af9`,
`52df62a`, `f4ba6a2`, `b3cf617`, `a010ae6`, `5e9c544`, `b10aa08`,
`a5f8768`, `140c465`, `ad3c4e0`, `8596764`, `ee6eb8a`, `3675222`.

## 2026-09-09

### Features added

- Added a resumable multi-run collection driver at `testing/traffic/collect.sh`.
  It starts capture before traffic, assigns a distinct seed to every run, waits
  for in-flight completions, clears prior policy/campaign state, restarts the
  gateway without losing the collection config, and stops the control plane so
  the model is not trained on traffic already shaped by itself.
- Froze `datasets/v2`: 17,160 rows from 24 runs (9,236 train, 3,837 validation,
  4,087 test), with roughly 264 rows per attack scenario and no recorded
  telemetry loss. This provided enough benign-only training data to fit the
  first model.
- Added adaptive policy generation and analyst-controlled enforcement
  (`cd0666d`). The control plane now consumes completed 60-second windows,
  maintains endpoint/method rolling median-and-MAD baselines, uses warm-up,
  hysteresis, and threshold-change cooldowns, and learns only from windows
  considered safe.
- Added a validated 0-100 adaptive risk calculation combining deterministic
  evidence, endpoint deviation, campaign facts, and a small advisory ML weight.
  Policy confidence is calculated separately from deterministic evidence and
  campaign correlation; an ML-only anomaly can produce monitor advice but not
  enforcement (`control-plane/iasg/adaptive/risk.py`).
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
- Added safe optional model loading (`control-plane/iasg/ml/scorer.py`) and a
  reproducible Isolation Forest training/evaluation pipeline. Artifacts record
  dataset and runtime schema versions, exact feature order, training runs,
  library version, medians, score scale, admission rule, and whether the model
  is loadable by the runtime. Missing or incompatible models leave adaptive
  scoring operational with `model_available=false`.
- Added protocol-aware evaluation (`control-plane/iasg/ml/evaluate.py`): the
  threshold is selected on validation against a 1% false-positive budget for
  every sufficiently supported benign persona, test is read once, small
  personas receive confidence intervals, and coverage, conditional recall, and
  operational recall are reported separately per attack scenario.
- Added model experiment artifacts under `models/` while keeping reproducible
  `.joblib` binaries ignored. The v2 baseline exposed 2.1% pooled operational
  recall and an inability to extrapolate beyond benign training ranges. The
  optional repeated `login_regularity` feature raised slow-brute-force recall
  to 93.9% and pooled recall to 22.0%, but is explicitly not runtime-loadable.
- Froze `datasets/v3`, rebuilt from 23 clean runs against feature spec v2 with
  16,438 rows and the runtime's 13-feature schema. It adds derived
  `endpoint_method_deviation` and evaluation-only `detector_fired` and
  `gateway_blocked` metadata. One contaminated duplicate-generator run was
  deliberately excluded.
- Added `unmatched_route_ratio` as an arrival-time feature and bumped the
  positional feature contract to v3 (`control-plane/iasg/anomaly/spec.py`).
  The value is zero for all captured benign personas and about 54-99.9% for the
  scanning scenarios. `datasets/v4` freezes the same 23 runs under this
  14-feature schema and contains 16,438 rows.
- Added v3/v4 model artifacts. The plain v4 Isolation Forest matches the current
  feature schema and is marked runtime-loadable; the experiments also show why
  pooled recall is misleading when a model mostly re-detects requests the
  gateway already caught.

### Features modified

- Dataset rows now carry an opaque `client_id` rather than raw addresses,
  preserve benign persona names in metadata, retain per-endpoint counts for
  baseline derivation, and mark whether a window is safe to learn from. These
  values remain outside `features.csv`.
- The builder now records detector firings separately from gateway blocks, so
  evaluation can measure attack windows missed by both without treating a
  blocked request—which never reached a detector—as a detector miss.
- The feature contract advanced from v1/12 features (`datasets/v2`) to v2/13
  features (`datasets/v3`) and then v3/14 features (`datasets/v4`). Model
  training reads and stamps the frozen dataset's own schema instead of assuming
  the current runtime schema.
- Policy decisions gained stable policy IDs, target/scope, risk and confidence,
  issuer/mode, baseline/config/model versions, supersession, expiry, and a
  structured explanation. The Go gateway accepts both legacy `temp_block` and
  the adaptive Redis wire spelling `temporary_block` during migration.
- Policy deletion from the dashboard now validates addresses with Node's IP
  parser, deletes both address-wide and bounded endpoint-scoped siblings, and
  records durable revocation status/audit entries when PostgreSQL is available.
- The admin reset now clears adaptive audit/recommendation/baseline tables and
  trims the arrival, health, evidence, override, and alert streams without
  deleting consumer groups. Live `policy:*` keys remain deliberately separate.

### Bug fixes

- Dataset builds now read `sessions.jsonl`, discard and report windows from
  unplanned addresses instead of labeling them benign, and reject a run when
  more than 5% of its rows are unplanned. This addresses the stray public and
  Docker host addresses found in v1. Persona identity is retained so the stated
  per-persona false-positive evaluation is actually possible (`d26e0ba`).
- Collection now forwards distinct traffic seeds and sessions-per-persona and
  stops the control plane unconditionally before and during a sequence, closing
  a restart-policy race that had inserted live policies into collection runs.
- The production builder now executes split-disjointness and label-independence
  checks on the rows being frozen; malformed paths are reported and become
  fatal under `--strict`. Health sequence/counter parsing was extracted and
  hardened during the adaptive/dataset merge (`a1362ee`).
- Fixed unedited approval of an adaptive temporary-block recommendation
  (`d0cc08c`). PostgreSQL payloads now retain canonical `temp_block`, while only
  the Redis policy serializer rewrites it to `temporary_block` for the Go wire
  contract.
- Fixed schema-mismatch handling in training: an old frozen dataset is rejected
  by default, may be trained only with an explicit advisory override, and can no
  longer be mislabeled as compatible with the runtime.

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
- Baseline-derived throttles are bounded by configured RPM limits. ML can adjust
  risk only as advisory input and cannot supply policy confidence or satisfy the
  deterministic-evidence requirement for enforcement.
- Analyst escalation remains an alert layered over a bounded throttle/block;
  it does not create a stronger fourth automatic gateway action.

### Configuration changes

- Added complete adaptive JSON configuration in
  `control-plane/configs/adaptive.json.example`: baseline windows and MAD
  parameters, risk weights and detector points, score thresholds, confidence
  weights, action/duration/RPM ceilings, evidence and ML thresholds, change
  cooldowns, analyst escalation thresholds, and emergency CIDR lists.
- Added environment settings for arrival/health streams, window consumer group
  and grace period, adaptive JSON/path input, and deployed model/metadata paths
  in `control-plane/.env.example`.
- Adaptive settings are persisted and versioned in PostgreSQL. Dashboard saves
  validate the complete schema and use optimistic version checks so a stale
  page cannot overwrite a newer configuration.
- Added `models/**/*.joblib` to `.gitignore`; model metadata and evaluation
  results remain tracked and reproducible from frozen datasets.

### Infrastructure/Docker changes

- Changed the control-plane image from Alpine to `python:3.12-slim` so official
  NumPy/SciPy/scikit-learn wheels are usable without compiling on startup.
- Compose now installs the `postgres` and `ml` extras, mounts frozen datasets
  read-only, persists deployed models in `control_plane_models`, and supplies
  telemetry-health and model artifact paths.
- Extended the collection profile with seed and sessions-per-persona controls
  and a capture deadline longer than traffic, preventing the final in-flight
  completions from being misread as a quiet partial window.

### Testing changes

- Added `control-plane/tests/test_adaptive_enforcement.py`, covering baseline
  warm-up/learning safety, median/MAD thresholds, hysteresis, risk/confidence
  separation, all three modes, action ceilings, evidence/ML guardrails,
  emergency lists, scope/cooldown/expiry, no-renewal behavior, analyst approval,
  writer revalidation, and dry-run/per-cycle caps.
- Added Go adaptive-policy tests for legacy and expanded wire formats,
  `temporary_block`, endpoint matching, policy precedence, normalized routes,
  telemetry metadata, and body-before-enforcement ordering.
- Expanded PostgreSQL tests for adaptive configuration, baselines,
  recommendations, lifecycle/audit durability, approval, and canonical-versus-
  wire action serialization.
- Added ML tests for artifact metadata, safe no-model behavior, compatible and
  incompatible schema loading, scoring, and trained model output.
- Expanded dataset tests for unplanned traffic, persona preservation,
  anonymization, endpoint deviation, build-time integrity checks, strict
  malformed-record handling, detector/gateway metadata isolation, and frozen
  artifact verification.
- Model experiments and reports explicitly measured per-persona false positives,
  held-out-scenario coverage/recall, random-seed stability, gateway-missed
  minutes, and alternatives that did not improve the model.

### Documentation changes

- Added `gateway/docs/network-level-blocking.md`, explaining why L7 enforcement
  remains the default behind trusted proxies and why pre-HTTP drops would lose
  client identity and telemetry.
- Added `datasets/README.md`, documenting every frozen artifact, null semantics,
  split rules, leakage boundaries, manifests, and verification/rebuild workflow.
- Added and refined `gateway/docs/anomaly-evaluation.md` with the fixed 1%
  per-persona false-positive budget, 100-row gate, confidence intervals,
  coverage/conditional/operational recall, full-window admission, run-level
  benign holdout, and separate model/policy delay definitions.
- Added `gateway/docs/adaptive-policy.md` and updated the feature, policy, and
  system-architecture documentation for adaptive baselines, guardrails,
  lifecycle, endpoint-scoped policies, and the model trust boundary.
- Added `gateway/docs/anomaly-model-results.md`, recording baseline and
  login-regularity results, schema/deployment limitations, failed alternatives,
  and the Isolation Forest extrapolation problem.
- Added `attack-detection-options.pdf`, which evaluates deterministic follow-up
  rules on v4. The recommended unmatched-route and consecutive failed-login
  rules catch 65 of 76 gateway-missed attack minutes with no observed false
  positives; combined with the retained anomaly model, 75 of 76 are covered.
  The document recommends implementing those behaviors in the deterministic Go
  detectors instead of adding another classifier or LLM decision path.
- Updated MkDocs navigation for the evaluation, adaptive-policy, model-results,
  dataset, and network-blocking material.

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
