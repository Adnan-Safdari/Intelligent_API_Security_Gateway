> **Datasets are no longer in the repository.** The `datasets/v1`–`v4` and
> `part5-fresh` captures referenced below were removed from git and are kept
> outside it; the commands still work once a dataset is placed back under
> `datasets/`. Release images no longer ship a trained model.

# Anomaly Model — Training Runs

**This page has three iterations. The first two, against `datasets/v2`, are
below and still accurate as history. The third — three more models against
`datasets/v3`/`v4`, and the finding that pooled recall was the wrong number to
chase — is under "Iteration 3" further down, and changes the conclusion: the
recommended next step is deterministic rules, not another model.**

| | Iteration 1 (baseline) | Iteration 2 (login-regularity) |
| --- | --- | --- |
| **Model** | `iforest-v2-spec1` | `iforest-v2-regularity` |
| **Trees** | 200 | 500 |
| **Features** | 12 (dataset's own) | 12 + an engineered 13th, repeated 10x |
| **`slow_brute_force` operational recall** | 5.3% | **93.9%** |
| **Pooled attack operational recall** | 2.1% | **22.0%** |
| **Dataset** | `datasets/v2` — 17,160 rows, 24 runs, feature spec **v1** | same |
| **Measured against** | [Evaluation Protocol](anomaly-evaluation.md) | same |
| **Deployable** | **No** | **No** — for a different reason, see below |

**Headline: the first model detected 2.1% of attack windows at the protocol's
budget. The second detects 22.0%, and 93.9% of `slow_brute_force` specifically
— one of the two held-out scenarios this layer exists for — with no new false
positives anywhere.** Getting there took three ideas that looked reasonable
and turned out not to work, each for a different mechanical reason, and one
that did. All of it is recorded below, including the wrong turns, because the
reasons they failed are what make the fix that worked trustworthy rather than
lucky.

---

## Iteration 1: baseline

Train is benign-only, as the design requires: 9,236 windows, no attacks. The
threshold is chosen on validation; test was read once, at the end.

| Split | Rows | Benign | Attack |
| --- | --- | --- | --- |
| `train` | 9,236 | 9,236 | 0 |
| `val` | 3,837 | 3,221 | 616 |
| `test` | 4,087 | 2,860 | 1,227 |

Coverage on test — the fraction of windows the layer scores at all, with 1–2
request windows abstaining:

| | Rows | Scored | Abstained | Coverage |
| --- | --- | --- | --- | --- |
| All | 4,087 | 3,814 | 273 | 93.3% |
| Attack | 1,227 | 1,195 | 32 | 97.4% |
| Benign | 2,860 | 2,619 | 241 | 91.6% |

### Result at the protocol threshold

The protocol selects the threshold so no gated persona exceeds 1.0% false
positives. That binds at `forgetful_user` and yields a threshold of −0.7528.

| Scenario | Rows | Coverage | Conditional recall | **Operational recall** |
| --- | --- | --- | --- | --- |
| `credential_stuffing` | 121 | 0.992 | 0.100 | **0.099** |
| `slow_brute_force` | 262 | 0.954 | 0.056 | **0.053** |
| `api_flood` | 99 | 1.000 | 0.000 | **0.000** |
| `enumeration` | 110 | 1.000 | 0.000 | **0.000** |
| `low_and_slow_enumeration` | 261 | 0.939 | 0.000 | **0.000** |
| `path_traversal` | 187 | 0.995 | 0.000 | **0.000** |
| `sqli_probe` | 187 | 0.989 | 0.000 | **0.000** |
| **Pooled** | **1,227** | **0.974** | **0.022** | **0.021** |

Pooled benign false positives: 5 of 2,619 (0.19%). All five are
`forgetful_user`, and all five are run-edge windows.

### Two independent failures

#### 1. The forest cannot extrapolate

`api_flood` runs at a median of 1,196 requests per minute. Benign training
traffic tops out at **20**. It is detected 0% of the time.

The cause is structural, not statistical. Every split in every tree was learned
from benign data whose `request_count` never exceeds 20, so every value at or
above 20 follows an identical path through the forest. Holding all other
features at their training medians and varying only `request_count`:

| `request_count` | `score_samples` |
| --- | --- |
| 5 | −0.408149 |
| 16 | −0.458093 |
| 20 | −0.465714 |
| 25 | −0.465714 |
| 1,196 | −0.465714 |
| 5,000 | −0.465714 |
| 100,000 | −0.465714 |

**The model cannot distinguish 20 requests per minute from 100,000.** All of
them score −0.4657, which is nowhere near the −0.7528 threshold — so a flood
scores as *less* anomalous than 1% of ordinary benign windows.

For contrast, the data is trivially separable on this axis: benign test traffic
has p99 = 16 and max = 20, while `api_flood` has a minimum of 25. **The rule
`request_count > 16` catches 100% of `api_flood` at roughly 1% false
positives.** The deterministic `api_flooding` detector already covers this
ground, which is why the gap matters less than it looks — but a layer that
cannot see a 150× flood should not be described as detecting volume anomalies.

#### 2. `forgetful_user` is the binding constraint

Each persona's own 1% limit on validation, sorted. The threshold becomes the
minimum, so one persona sets it for everybody:

| Persona | 1% limit | Val rows |
| --- | --- | --- |
| **`forgetful_user`** | **−0.7528** | 397 |
| `shopper` | −0.6450 | 410 |
| `impatient` | −0.6124 | 444 |
| `browser` | −0.5924 | 459 |
| `dead_link_visitor` | −0.5648 | 446 |
| `search_heavy` | −0.5624 | 489 |
| `mobile_poller` | −0.4935 | 352 |

`forgetful_user` sits a full 0.108 below the next persona. Relaxing to the
*pooled* 1% threshold (−0.6999) lifts `slow_brute_force` from 5.3% to **95.4%**
— but then:

| Persona | False positives at pooled 1% |
| --- | --- |
| **`forgetful_user`** | **29 / 325 = 8.92%** |
| every other persona | 0 / 2,294 = **0.00%** |

This is exactly the failure the per-persona rule was written to expose: a
pooled 1.11% that is really 8.92% on one persona and zero everywhere else. The
rule is working correctly. It is the model that cannot separate these cases.

And the confusion is a real one, not an artifact. The feature specification
warns about it directly — "a genuine user who mistypes a password three times"
produces a high `login_failure_ratio`, "and the training set contains that case
on purpose." Median feature values:

| Feature | `forgetful_user` (benign) | `slow_brute_force` (attack) | Other benign |
| --- | --- | --- | --- |
| `request_count` | 7.000 | 7.000 | 9.000 |
| `login_ratio` | 0.000 | 1.000 | 0.000 |
| `login_failure_ratio` | 0.000 | 1.000 | 0.000 |
| `interarrival_cv` | 0.274 | **0.027** | 0.344 |
| `unique_path_ratio` | 0.889 | 0.143 | 0.545 |

At the median the two are clearly distinguishable. The overlap is in
`forgetful_user`'s tail — the minority of its windows that *do* contain failed
logins. Those windows are, in this feature space, a slow brute force at seven
requests a minute. The one feature that separates them is `interarrival_cv`
(0.027 machine-regular against 0.274 human-bursty), and an unsupervised forest
that samples all twelve features uniformly has no reason to weight it.

### The operating curve (iteration 1)

Threshold chosen on validation benign at each pooled budget; recall measured on
test. This is the model's real characteristic:

| Budget | Threshold | Benign FP | `api_flood` | `cred_stuffing` | `enumeration` | `low_and_slow` | `path_traversal` | `slow_brute` | `sqli_probe` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.5% | −0.7419 | 0.34% | 0.000 | 0.207 | 0.000 | 0.000 | 0.000 | 0.084 | 0.000 |
| **1%** | **−0.6999** | **1.11%** | 0.000 | 0.207 | 0.000 | 0.000 | 0.000 | **0.954** | 0.000 |
| 2% | −0.6351 | 2.10% | 0.000 | 0.983 | 0.000 | 0.000 | 0.000 | 0.954 | 0.000 |
| 5% | −0.5637 | 5.23% | 1.000 | 0.992 | 0.945 | 0.034 | 0.166 | 0.954 | 0.000 |
| 10% | −0.5216 | 11.19% | 1.000 | 0.992 | 1.000 | 0.356 | 0.968 | 0.954 | 0.011 |
| 20% | −0.4796 | 21.95% | 1.000 | 0.992 | 1.000 | 0.939 | 0.984 | 0.954 | 0.952 |

Read this as the honest summary of what the layer can do:

- **`slow_brute_force` is genuinely detectable** — 95.4% at a 1% pooled budget,
  and it does not improve further with a looser one. This is the layer's stated
  purpose, and on this scenario it works.
- **`low_and_slow_enumeration` is not** — 0% until a 10% budget, and it needs
  20% to reach 93.9%. No usable operating point exists for it.
- The loud scenarios only appear at 5%+, and only because the threshold has
  fallen far enough to catch their fixed −0.60 score, not because the model
  ranks them well.

### Things that did not fix iteration 1

**Applying the protocol's admission rule made it worse.** Dropping run-edge
(half-observed) windows from both training and evaluation moved pooled
operational recall from 2.1% to **0.9%**, and the threshold from −0.7528 to
−0.7639. The run-edge windows were a plausible culprit — all five false
positives are run-edge — but removing them refits the model and its score
distribution, and `forgetful_user` still binds. Run-edge contamination is a real
defect in v2; it is not what is holding this model back.

## Iteration 2: a login-regularity feature

The finding above pointed at `interarrival_cv` as the one feature separating
`forgetful_user` from `slow_brute_force`. Three ways of acting on that were
tried and rejected before the fourth worked, each ruled out by measurement
rather than by argument.

| Attempt | Result | Why it fails |
| --- | --- | --- |
| Log-transform `request_count` | No change | A monotonic transform preserves whether a value is beyond the training maximum. It moves where the boundary sits, not whether one exists. |
| Scale/weight `interarrival_cv` | No effect at all | IsolationForest picks a split threshold from a feature's own observed range; scaling that feature does not change which points fall on which side of it. Confirmed on synthetic data: scaling one column by 1000× left `score_samples` bit-for-bit identical. |
| Duplicate the raw `interarrival_cv` column | Made it worse | This does change the forest — it raises how often a feature is drawn — but `interarrival_cv` is not a clean attack signal. `mobile_poller` (benign, automated) has a *lower* median (0.011) than `slow_brute_force` (0.027): polling scripts are more mechanically regular than the attack. Amplifying it flags legitimate polling instead. |

The first two are dead ends specific to how IsolationForest is built, not
things a different threshold or more data would fix. The third showed the
real problem: `interarrival_cv` alone conflates two different kinds of
regularity, one benign and one not.

### The feature that worked

```
login_regularity = login_ratio * max(0.0, 1.0 - interarrival_cv)
```

Near zero unless a window both talks to the login endpoint *and* arrives on a
near-fixed cadence. Neither half is a signal alone — `login_ratio` is
triggered by an honest mistyped password, `interarrival_cv` is triggered by
automated polling — but no benign persona in this dataset does both at once:

| Group | p50 | p90 | p99 | max |
| --- | --- | --- | --- | --- |
| `mobile_poller` (benign) | 0.000 | 0.000 | 0.000 | 0.000 |
| other benign (pooled) | 0.000 | 0.000 | 0.056 | 0.084 |
| `forgetful_user` (benign) | 0.000 | 0.098 | 0.397 | 0.624 |
| `credential_stuffing` (attack) | 0.657 | 0.681 | 0.711 | 0.725 |
| `slow_brute_force` (attack) | 0.973 | 0.983 | 0.988 | 0.993 |

`forgetful_user`'s worst case (0.624) sits below `slow_brute_force`'s entire
range (0.973 and up). `mobile_poller` is a flat, provable zero, because
`login_ratio` is exactly zero for a client that never touches `/api/login`.

### Repetition, and why it needs 500 trees

Added as a thirteenth column, the feature barely moved anything: `slow_brute_force`
recall went from 5.3% to 6.5%. IsolationForest draws a split feature uniformly
at random at every node, so one column among thirteen gets roughly a 1-in-13
hearing no matter how well it separates the classes — the clean isolation
shown in the table above was being diluted by the other twelve dimensions.
There is no per-feature weight to set instead; the only lever that changes
draw frequency is adding more copies of the column, which is safe here
specifically because the feature is a provable zero for every benign persona
except the one already gated (`forgetful_user`), so duplicating it cannot
manufacture a new false positive out of automated traffic the way duplicating
raw `interarrival_cv` did.

Repeating it 10 times was not tuned to the best-looking number — it was the
first point that stopped being a coin flip. At the default 200 trees, five
different random seeds with 10 repeats gave `slow_brute_force` recall ranging
from **0.11 to 0.94** on the identical data: the run that looked good was
luck, not signal. Raising the forest to 500 trees made every seed tested land
on 0.939. (The plain 12-feature baseline above did not have this problem —
its recall varied only 0.031–0.053 across the same five seeds at 200 trees —
so 200 stays the default and 500 applies only when this feature is enabled.)

### Result

Threshold still chosen on validation, per-persona, at the 1% budget; test read
once. All numbers below come from the same `evaluate.py` used for iteration 1.

| Scenario | Iteration 1 | Iteration 2 |
| --- | --- | --- |
| `slow_brute_force` | 0.053 | **0.939** |
| `credential_stuffing` | 0.099 | **0.198** |
| `api_flood` | 0.000 | 0.000 |
| `enumeration` | 0.000 | 0.000 |
| `low_and_slow_enumeration` | 0.000 | 0.000 |
| `path_traversal` | 0.000 | 0.000 |
| `sqli_probe` | 0.000 | 0.000 |
| **Pooled** | **0.021** | **0.220** |

Threshold moved from −0.7528 to −0.7991, still bound by `forgetful_user`, still
at **exactly the same 5 false positives** it had before (1.54%, unchanged) —
this feature improved detection without costing anything in false positives.
Every other persona remains at 0.00%.

Two scenarios are honestly unmoved. `low_and_slow_enumeration` — the other
held-out scenario — never touches the login endpoint, so `login_regularity` is
uniformly zero for it; this feature has nothing to say about enumeration. The
loud, high-volume attacks are still invisible for the same extrapolation
reason as iteration 1 — this work did not touch that failure at all.

**`idle` and `one_shot` are permanently invisible to this measurement**,
independent of which model is used: every `idle` and `one_shot` test window
has 1–2 requests and abstains from scoring, so their `scored` count is zero
in both iterations. This is not a defect introduced here — it was already
true of iteration 1, just not previously surfaced per-persona.

## Iteration 3: v3/v4, and the metric that was wrong

Iterations 1 and 2 above are frozen history against `datasets/v2`. A v3
dataset (`datasets/v3`, schema `v2`, 13 features) and a v4 dataset
(`datasets/v4`, schema `v3`, 14 features — `unmatched_route_ratio` inserted,
see [Feature Specification](anomaly-features.md)) were built next, and three
more Isolation Forest models were fit and measured the same way (1%
per-persona budget, threshold on validation, test read once):

| Model | Dataset | Pooled operational recall | Pooled false positives |
| --- | --- | --- | --- |
| `v3-iforest` (baseline) | v3 | 5.6% | 0.12% |
| `v3-iforest-regularity` (+ login-regularity, reproducing iteration 2) | v3 | **27.4%** | 0.16% |
| `v4-iforest` (+ `unmatched_route_ratio`) | v4 | 6.4% | 0.16% |

**The second row is a trap, not a win.** Pooled recall counts every
attack-minute, and most attack-minutes are already caught or blocked by the
gateway's own deterministic detectors — a model that re-detects those adds
nothing. The number that matters is coverage of the minutes the gateway
*missed entirely*: in `datasets/v4`'s test split there are 76 such
attack-minutes (`label=1`, no detector fired, nothing blocked — 64 are
`low_and_slow_enumeration`, 10 are the opening minutes of `slow_brute_force`).
Measured against that honest target:

| Model | Missed-minutes caught |
| --- | --- |
| `v3-iforest` (baseline) | **10 / 76** — all ten are `slow_brute_force` opening minutes |
| `v3-iforest-regularity` | **0 / 76** — it only re-catches attacks the gateway had already stopped |
| `v4-iforest` | **10 / 76** — `unmatched_route_ratio` is perfect in the data; the model cannot use it |

The third row is the more durable finding. Across all 23 collection runs,
`unmatched_route_ratio` is **0.0% for every benign persona** — including
`dead_link_visitor`, who exists specifically to produce ordinary 404s — and
53.6–99.9% for the three scanning/traversal attacks. The separation is exact.
But an Isolation Forest only ever trains on benign traffic, where this column
is a constant zero across all 8,883 training rows. A model cannot learn a
dividing line from a column that never moves, so a scanner arriving at 0.54
looks like nothing has changed. **This is not fixable by tuning the model**:
the better a feature separates attackers from normal traffic, the flatter it
is in training, and the more invisible it is to an anomaly detector trained
only on that traffic. No threshold adjustment changes this either — the
scanning attacks score 0% at every threshold, because the model never learned
to use the feature at all.

**The conclusion drawn from this (full analysis: `attack-detection-options.pdf`
at the repo root) is to stop engineering features for the model and build
deterministic rules instead**: a per-address ratio of requests to
non-existent pages, and a per-address streak of consecutive failed-login
minutes, together simulated at 65/76 missed-minutes caught with 0 false
positives on 13,572 benign minutes — because both signals are exact and
explainable, which is exactly what an Isolation Forest cannot use them for.
The Isolation Forest's ongoing job, per that analysis, narrows to the 10
opening minutes of a slow attack that no rule has enough history to flag yet
— which `v3-iforest`'s baseline result above already demonstrates it does at
10/10.

**What has since shipped, and where it differs from that recommendation.**
`internal/signals/unknown_route_scanning.go` and the `consecutive_failed_logins`
rename of `brute_force.go` (see [Detection Signals](detection-signals.md)) are
deterministic Go detectors covering the same ground, but by different
mechanics than the analysis proposed: route scanning is detected by counting
*distinct* unmatched paths in a window rather than the ratio of unmatched
requests, and brute force still counts a streak of consecutive failed
*requests* per login target rather than consecutive failed *minutes*. Both are
marked advisory-only — see [Detection Signals](detection-signals.md) — so
today they feed the control plane rather than the gateway's own blocking
reflex, which is a stricter posture than the recommendation assumed for rules
that "hold on new attacks." Nobody has re-run the missed-minutes measurement
against the shipped Go detectors; the 65/76 and 75/76 figures above are the
offline simulation's numbers, not a confirmed result of what is running today.

## Deployability

### v2 (iterations 1–2)

`datasets/v2` is frozen under feature spec **v1** (12 features). The runtime now
declares spec **v3** (14 features — `unmatched_route_ratio` and
`endpoint_method_deviation` were both added since). The artifact records its
own schema honestly, so `ModelScorer` refuses to load it rather than feeding a
model a column it was never fitted on:

```json
"feature_schema_version": "v1",
"runtime_schema_version": "v2",
"runtime_loadable": false
```

The 13th feature cannot be retrofitted onto v2: it is derived from per-window
`endpoint_counts`, which was an in-memory build artifact and was never exported
to the frozen files. Producing a loadable model requires a dataset built under
spec v2 — which requires raw capture, which is gitignored and no longer on disk.

**Iteration 2 has a second, independent reason it cannot deploy even once that
is fixed.** `login_regularity` is computed in `train.py`/`evaluate.py`, not in
`ModelScorer.score()`. Loading it into the runtime as-is would hand the model a
12-wide vector when it was fitted on 22, and fail immediately — which is
exactly what its `metadata.json` says:

```json
"runtime_loadable": false,
"engineered_features": {
  "login_regularity": {
    "formula": "login_ratio * max(0.0, 1.0 - interarrival_cv)",
    "repeated": 10
  }
}
```

Deploying this model needs `ModelScorer.score()` extended to compute the same
feature the same way — a small, well-defined piece of work, and deliberately
not done here since it was out of scope for this pass.

### v3/v4 (iteration 3)

Only `v4-iforest` is loadable by the runtime **today**. Its
`feature_schema_version` is `v3`, matching the current
`FEATURE_SPEC_VERSION` in `control-plane/iasg/anomaly/spec.py`:

```json
"feature_schema_version": "v3",
"runtime_schema_version": "v3",
"runtime_loadable": true
```

`v3-iforest` and `v3-iforest-regularity` both say `"feature_schema_version":
"v2"`, and were stamped `runtime_loadable: true` when trained — but that
stamp is a claim about the runtime *at that moment*, not a durable one. Both
were trained on 2026-09-09 at 12:31 UTC, roughly ten minutes before the same
day's spec bump to v3 (`unmatched_route_ratio`, `datasets/v4` frozen at
12:44 UTC). The runtime has since moved on, so `ModelScorer.reload()` would
reject both today (`"v2" != "v3"`) despite what their own metadata says. A
model's `runtime_loadable` field is only ever a snapshot of the runtime it was
trained against — worth remembering before trusting it without checking the
current `FEATURE_SPEC_VERSION` too.

None of the three is recommended for deployment regardless of loadability.
Section "Iteration 3" above found that the highest-recall model
(`v3-iforest-regularity`) adds nothing on the metric that matters
(missed-minutes caught), and that the feature engineered specifically for
scanning (`unmatched_route_ratio`) is structurally invisible to this model
family. `v3-iforest`'s baseline — unmodified, no engineered features — is the
one worth keeping, and only as a second layer behind deterministic rules, per
`attack-detection-options.pdf`.

## What to do next

1. **Do not loosen the budget to make the number look better.** The pooled 1%
   figure at iteration 1 was 8.92% on one persona. The per-persona rule is the
   only reason that was visible, and it should stay the mechanism regardless of
   which model is measured against it.
2. **Stop engineering features for this model family.** Two independent
   attempts (`login_regularity` reproduced on v3; `unmatched_route_ratio` on
   v4) both confirmed the same structural limit in section "Iteration 3"
   above — the more exact a feature is, the flatter it is in training, and the
   less an Isolation Forest can use it. Any future engineered feature should
   be assumed to fail the same way unless there's a specific reason to expect
   otherwise.
3. **Verify the shipped Go detectors against the missed-minutes measurement.**
   `unknown_route_scanning.go` and the reworked `brute_force.go` cover the same
   ground as the recommended rules in `attack-detection-options.pdf`, but by
   different mechanics (distinct-path counting, not a ratio; a
   consecutive-failed-*request* streak, not a consecutive-failed-*minute*
   one). Nobody has re-run the 65/76 or 75/76 figures against what's actually
   running. That's the open item, not writing new rules.
4. **The extrapolation failure is still open.** Any `request_count` beyond the
   benign training range still collapses to one score. The deterministic
   `api_flooding` detector covers this today; a monotone, non-saturating signal
   alongside the forest would let this layer see it too — though per the point
   above, don't expect an engineered feature to be the fix.
5. **If `v4-iforest` is ever deployed**, promote it to `models/current` (the
   path `Settings.model_path` actually reads) and treat it strictly as a
   second layer behind the deterministic detectors, not the primary defense
   for either held-out scenario — see "Deployability" above.

## Reproducing this

```bash
cd control-plane && python -m venv .venv && .venv/bin/pip install -e ".[dev,ml]"

# Iteration 1 -- baseline, 12 features. --allow-schema-mismatch is required
# because v2 is spec v1 and this runtime is spec v2; the artifact records
# that it is not loadable here regardless.
PYTHONPATH=. .venv/bin/python -m iasg.ml.train \
  --dataset ../datasets/v2 --out ../models/v2-iforest \
  --version iforest-v2-spec1 --allow-schema-mismatch

# Iteration 2 -- adds the login-regularity feature and trains 500 trees.
PYTHONPATH=. .venv/bin/python -m iasg.ml.train \
  --dataset ../datasets/v2 --out ../models/v2-iforest-regularity \
  --version iforest-v2-regularity --allow-schema-mismatch \
  --login-regularity-feature

# Evaluate either one against the protocol: per-persona budget, coverage,
# both recalls. evaluate.py reads engineered_features from metadata.json and
# reconstructs the same vector shape automatically.
PYTHONPATH=. .venv/bin/python -m iasg.ml.evaluate \
  --dataset ../datasets/v2 --artifact ../models/v2-iforest-regularity \
  --budget 0.01 --out ../models/v2-iforest-regularity/evaluation.json

# Iteration 3 -- v3 (schema v2, 13 features) baseline and login-regularity.
PYTHONPATH=. .venv/bin/python -m iasg.ml.train \
  --dataset ../datasets/v3 --out ../models/v3-iforest --version v3-iforest
PYTHONPATH=. .venv/bin/python -m iasg.ml.train \
  --dataset ../datasets/v3 --out ../models/v3-iforest-regularity \
  --version v3-iforest-regularity --login-regularity-feature

# v4 (schema v3, 14 features -- unmatched_route_ratio added). Matches the
# current runtime spec, so no --allow-schema-mismatch is needed here.
PYTHONPATH=. .venv/bin/python -m iasg.ml.train \
  --dataset ../datasets/v4 --out ../models/v4-iforest --version v4-iforest

PYTHONPATH=. .venv/bin/python -m iasg.ml.evaluate \
  --dataset ../datasets/v4 --artifact ../models/v4-iforest \
  --budget 0.01 --out ../models/v4-iforest/evaluation.json
```

`model.joblib` is gitignored — it is exactly reproducible from the frozen
dataset and a fixed seed. `metadata.json` and `evaluation.json` are kept,
because they are what makes a claim about this model checkable. The
missed-minutes numbers in "Iteration 3" above are a separate, offline join of
`features.csv`/`metadata.csv`/`quality.csv` on `row_id` — not something
`iasg.ml.evaluate` produces — documented in full in
`attack-detection-options.pdf`.
