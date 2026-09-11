# Anomaly Evaluation Protocol

| | |
| --- | --- |
| **Status** | Decided before any model is fit |
| **Applies to** | Feature spec `v2` onward, dataset `v3` onward |
| **Companion to** | [Feature Specification](anomaly-features.md) |

**Why this page exists rather than an edit to the dataset.** Each frozen
dataset carries its own `evaluation.md`, and that file is hashed in
`manifest.json` — editing it makes `verify()` fail, which is the point. A
frozen dataset's `evaluation.md` is a record of what was decided *when it was
built*. This page is where the protocol is decided and revised. When they
disagree about a past result, the dataset's copy describes that result.

Everything here is fixed **before** test is read. Deciding what counts as
success after seeing the scores is how a result gets talked into existing.

---

## 1. The false-positive budget

The previous wording — "a fixed false-positive budget" — was unfalsifiable. It
is replaced by a number.

> **The threshold is selected on validation so that no gated benign persona has
> a false-positive rate above 1.0%, and the pooled benign false-positive rate is
> at or below 1.0%. Test is then read once.**

**Gated** means the persona has at least **100 benign rows of test support**.
Personas below that are **reported but not gated** — as a raw `FP / N` count with
a 95% confidence interval, never as a bare percentage — because the measurement
cannot support the claim:

| Persona | v2 val rows | one FP = | v2 test rows | one FP = | Gated |
| --- | --- | --- | --- | --- | --- |
| `search_heavy` | 505 | 0.20% | 351 | 0.28% | yes |
| `browser` | 470 | 0.21% | 327 | 0.31% | yes |
| `impatient` | 462 | 0.22% | 474 | 0.21% | yes |
| `dead_link_visitor` | 460 | 0.22% | 469 | 0.21% | yes |
| `shopper` | 425 | 0.24% | 404 | 0.25% | yes |
| `forgetful_user` | 416 | 0.24% | 339 | 0.29% | yes |
| `mobile_poller` | 373 | 0.27% | 358 | 0.28% | yes |
| `idle` | 82 | 1.22% | 88 | 1.14% | **no** |
| `one_shot` | 28 | **3.57%** | 50 | **2.00%** | **no** |

A 1.0% budget is not measurable on `one_shot`: a single false positive is
already 3.6% of its validation rows. Gating on it would mean the threshold was
chosen by one window.

**The gate is not a licence to loosen the budget.** The tempting move is to set
the budget wherever one false positive happens to fit the smallest denominator —
2%, because `one_shot` has 50 test rows. That picks a number to fit an artefact
of sample size rather than to express what a false positive costs. The budget
stays at 1.0%; the personas too small to measure it are excluded from gating
instead.

**A clean small persona proves very little and must not be reported as if it
did.** Zero false positives in 50 rows is consistent with a true rate near 6%.
By the rule of three the 95% upper bound is `3/n`:

| Persona | Test rows | 0 FPs still allows a true rate up to |
| --- | --- | --- |
| `one_shot` | 50 | ~6.0% |
| `idle` | 88 | ~3.4% |
| smallest gated persona (`browser`) | 327 | ~0.9% |

`idle` and `one_shot` are therefore reported as counts with intervals, and the
honest remedy is more independent capture of those two behaviours — not a softer
threshold.

**Why 1.0% and not tighter.** The anomaly score is worth at most one severity
rung, and only on a campaign that already earned an action on evidence alone —
it never originates enforcement. A false positive here costs a severity bump on
a campaign that was already acting, not a blocked user. That argues against a
budget so tight the score stops carrying information. It is still tight enough
that a persona being systematically flagged fails the gate.

**Per persona, never averaged.** One persona always being flagged is a different
failure from a uniform low rate, and a pooled average hides it. The pooled
figure is reported *in addition to* the per-persona figures, never instead.

Row counts above are v2's, where the 100-row and 300-row gates happen to select
the same seven personas. After a v3 build they must be recomputed and the
100-row gate applied to whatever the new partitions contain.

---

## 2. Recall under abstention

Windows with 1–2 requests abstain from scoring. That is a coverage rule, not an
attack threshold — two requests have no meaningful inter-arrival statistics.

The old wording, "a window that declined to score is not a miss", is true of the
conditional metric and misleading on its own. **An abstaining attack window is
not detected by this layer.** The Go detectors still inspected those requests,
so nothing is lost on the request path — but nothing was gained from the model
either, and a report that omits this claims credit it did not earn.

Three numbers, reported together, per scenario:

| Metric | Definition |
| --- | --- |
| **Coverage** | scored attack windows ÷ all attack windows |
| **Conditional recall** | detections ÷ **scored** attack windows |
| **Operational recall** | detections ÷ **all** attack windows |

`operational recall = conditional recall × coverage`. **Conditional recall is
never reported alone.**

Coverage is also reported for benign traffic, since the fraction of traffic this
layer declines to assess is a property of the layer.

### Why this matters most where it is hardest

Abstention is not uniform. In v2 it concentrates in exactly the two scenarios
that are the whole honest test of this layer:

| Scenario | Scored | Abstained | Max operational recall |
| --- | --- | --- | --- |
| `api_flood` | 264 | 0 | 100.0% |
| `credential_stuffing` | 263 | 1 | 99.6% |
| `enumeration` | 263 | 1 | 99.6% |
| `path_traversal` | 263 | 1 | 99.6% |
| `sqli_probe` | 261 | 3 | 98.9% |
| **`slow_brute_force`** | 250 | 12 | **95.4%** |
| **`low_and_slow_enumeration`** | 245 | 16 | **93.9%** |

Across all attacks only 34 of 1,843 rows abstain, so pooled conditional and
operational recall barely diverge — which is precisely why the pooled number
must not be the one reported. A 6.1% ceiling on `low_and_slow_enumeration`
would otherwise be published as perfect recall on the scenario that matters
most.

---

## 3. Detection delay

> **Model detection delay is measured from the first attack request to the
> timestamp of the first fully-observed window whose anomaly score exceeds the
> threshold. Abstaining windows count as non-detections and extend it. Model
> detection delay and policy-enforcement delay are reported separately, together
> with the control-plane scheduling lag.**

Both delays share the same origin — the first attack request — and differ in
what they measure reaching:

| Delay | Measured to |
| --- | --- |
| **Model detection** | the first window whose score exceeds the threshold |
| **Policy enforcement** | the moment a policy key was written and applied |

Four rules make the definition usable.

**Do not compute delay as `windows × 60`.** An attack rarely begins on a window
boundary — a campaign starting at `12:00:47` has 13 seconds in its first window,
and multiplying a window count by 60 charges it a full minute it never used. Use
real timestamps and report the window count alongside as a separate, integer
figure.

**Abstaining windows count as non-detections and extend the delay.** A window
that declined to score cannot exceed a threshold. Skipping it would measure delay
against a timeline the runtime does not have.

**The scheduling lag is reported separately, not folded in.** Scoring waits for
the window to close, so an assessment is up to 60 seconds behind the traffic it
describes, plus the control plane's own cycle (currently 30s). Burying that in a
single number makes a fast model look slow and hides which half to fix.

**Undetected campaigns are reported as undetected.** They are never given an
imputed delay and never dropped from the denominator. A mean delay computed only
over successes is a mean over the easy cases.

### What the frozen dataset cannot answer

A constraint rather than a rule, because it decides where the measurement runs.

`metadata.csv` carries `window_start` and nothing finer. The attack interval
itself lives in the run manifest's `attacks.jsonl`, which is **not copied into
the frozen dataset**, and individual request arrival times live only in the raw
capture under `datasets/raw/` — gitignored, and reproducible only by rerunning.

So the dataset alone supports delay at **whole-window granularity**. Timestamp
precision needs one of:

- an `attack_start` column added to `metadata.csv` at build time (v3), or
- a join back to the raw capture for the runs being measured.

Policy-enforcement delay is not in the dataset under any option — it comes from
the control plane's own policy-write records, gathered at evaluation time.
Reporting it means capturing those alongside the scoring run.

## 4. Data admitted to evaluation

> **A window is admitted only if `interval_fully_observed` is true.**

In v2 this excludes 1,580 rows, 9.2% of the dataset. The reason is not the
obvious one.

**No telemetry was lost.** Across all 1,580 incomplete windows: zero
`telemetry_dropped_in_window`, zero `telemetry_defects`, zero `timeouts`. All
1,580 are the **first or last window of a capture run** — collection started or
stopped part-way through a minute.

That makes them partial observations of a full minute, and the distortion runs
one way:

| Scenario | Complete median `request_count` | Incomplete median | Ratio |
| --- | --- | --- | --- |
| `benign` | 9 | 4 | 0.44 |
| `api_flood` | 1,198 | 580 | 0.48 |
| `enumeration` | 92 | 47 | 0.51 |
| `sqli_probe` | 47 | 24.5 | 0.52 |
| `slow_brute_force` | 7 | 5 | 0.71 |
| `low_and_slow_enumeration` | 5 | 4 | 0.80 |

They also abstain at **33.0%** against **4.4%** for complete windows.

A truncated minute therefore *looks quiet* — which is the low-and-slow
signature. Keeping these rows adds benign-labelled windows that imitate the
attack shape, and attack windows that understate the attack. The contamination
points directly at the two held-out scenarios, so these rows are removed at
build time rather than filtered by whoever remembers to.

Excluding them costs little and unbalances nothing:

| | v2 as built | admitted |
| --- | --- | --- |
| Rows | 17,160 | 15,580 (−9.2%) |
| Benign | 15,317 | 13,877 |
| Attack | 1,843 | 1,703 |
| Rows per attack scenario | 261–264 | 241–244 |

### Completeness against scoreability

The two conditions are independent and both are reported:

| Category | v2 rows | % |
| --- | --- | --- |
| Complete and scoreable | 14,901 | 86.8% |
| Complete but abstained | 679 | 4.0% |
| Incomplete but scoreable | 1,058 | 6.2% |
| Incomplete and abstained | 522 | 3.0% |

### Missing outcomes are never zero-filled

Stated because it is the obvious wrong fix and the schema already forbids it. An
unknown outcome stays `null` in the dataset. Imputation happens at
vectorisation, from medians fitted on the training partition only and reloaded
byte-identically at runtime from `medians.json`. Writing 0 into an unmeasured
field would make *unknown* look like *normal*, which is the specific confusion
[the zero-versus-unknown rules](anomaly-features.md#zero-versus-unknown) exist
to prevent.

---

## 5. Benign holdout

Attack scenarios are held out already. Benign behaviour must be too, or nothing
tests whether the model's notion of *normal* survives contact with clients it
was not fitted on.

> **Three whole capture runs are reserved for test. They contribute no rows to
> train or validation, benign or attack.**

Runs are evenly sized (24 runs, mean 715 rows, min 680, max 736), so three runs
is roughly 12.5% of the data.

**Why runs and not a persona.** Holding a benign persona out of training is the
right move for a classifier and the wrong one here. This is a one-class model:
it learns *normal* from the training partition alone. Remove `mobile_poller`
from train and the model has never seen regular polling, so it will very likely
score it anomalous — the experiment fails close to by construction, and what it
measures is whether "normal" extrapolates to an unseen behaviour, not whether
the model avoids flagging regular clients.

It is also expensive. Against v2's 9,236 training rows:

| Holdout | Train rows lost |
| --- | --- |
| `mobile_poller` | −14.8% |
| `dead_link_visitor` | −12.7% |
| both | −27.4% |

Holding out whole runs costs less, keeps all nine personas in the model's notion
of normal, and tests the question deployment actually asks: does this generalise
to clients and sessions it was not fitted on.

**If an unseen-persona test is wanted later**, it is a separate experiment with
its own budget, reported as an unseen-persona false-positive rate. It is not
folded into the per-persona budget in §1, because the two measure different
claims.

---

## 6. Required v3 build changes

The rules above take effect only when a build enforces them. v2 is frozen and
stays as it is.

| Change | Status today |
| --- | --- |
| `interval_fully_observed` required for every partition | not built |
| Split membership assigned by whole `run_id` | partly — grouping is `(run_id, client_identity, replay_group)`, not run |
| Three runs reserved entirely for test | not built |
| Assert train is benign-only | **not built** |
| Assert reserved scenarios never leave test | enforced (`check_reserved`) |
| `features.csv` is `row_id` plus the feature columns | enforced |
| No group key spans two partitions | enforced (`check_split_disjoint`) |
| Labels independent of detector output | enforced (`check_labels_independent_of_detectors`) |
| Empty paths fail the build in strict mode | enforced (`check_no_empty_paths`) |
| Scenario × split × run count table in `evaluation.md` | not built |
| Protocol version and commit hash in `versions.json` | not built |
| `attack_start` in `metadata.csv` for delay measurement | not built |

### Three guards that used to guard nothing

`control-plane/iasg/anomaly/checks.py` defines `check_split_disjoint`,
`check_labels_independent_of_detectors` and `check_no_empty_paths`. All three
are written, documented, and unit-tested in `test_anomaly_dataset.py`, and
`build()` now calls all three (`control-plane/iasg/dataset/build.py:314,322`) —
`check_split_disjoint` and `check_labels_independent_of_detectors` raise
`LeakageCheckFailed` on failure, and `check_no_empty_paths` raises in
`--strict` mode. This section is kept as a record that they were once written
but not wired in, so the gap doesn't get silently reintroduced.

**There is still no benign-only-train assertion.** `splits.assign` never
returns `train` for a labelled attack, so the property holds structurally —
but it is the single most load-bearing claim in the design, and it should fail
loudly rather than rely on one branch staying correct.

### Recording which protocol a result was measured under

This page is allowed to change, which is exactly why a result must name the
version it was judged by. The build writes the protocol's file path and the
repository commit hash into `versions.json`, and any reported metric cites it.
Otherwise a threshold chosen under one budget gets compared against a number
produced under another, and nothing in the artefacts says so.

---

## 7. Known limits

Recorded so they are not rediscovered as findings.

**The held-out scenarios are not as quiet as intended.**
`slow_brute_force` at one login every 8 seconds produces 7.5 failures a minute
against a brute-force threshold of 5, and the enumeration detector has no rate
threshold at all — it matches path patterns, so slowing that scenario down
cannot put it under the detector. Both still produce genuinely missed minutes
(28% of `low_and_slow_enumeration` windows see no detector and no block), so the
dataset supports the claim that this layer catches what the detectors miss. The
scenarios need redesigning before that claim can be made cleanly.

**These features describe behaviour and cannot identify every malicious
payload.** A single SQL injection request may have entirely ordinary timing,
size, path diversity and response status. The deterministic detectors are not
replaced by this layer and must keep running alongside it.

---

## 8. To recompute after a v3 build

The rules above are fixed. These figures are not, and every one of them is
quoted from v2 in this page:

- Benign rows per persona in val and test, and which personas clear the 100-row
  test-support gate in §1, with rule-of-three bounds for those that do not.
- Abstention counts and the per-scenario operational-recall ceilings in §2.
- The completeness-against-scoreability table in §4.
- Train-partition size after the three reserved runs are removed.
