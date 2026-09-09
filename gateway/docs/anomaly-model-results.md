# Anomaly Model — First Training Run

| | |
| --- | --- |
| **Model** | `iforest-v2-spec1`, scikit-learn IsolationForest (200 trees, `random_state=42`) |
| **Dataset** | `datasets/v2` — 17,160 rows, 24 runs, feature spec **v1** (12 features) |
| **Measured against** | [Evaluation Protocol](anomaly-evaluation.md) |
| **Deployable** | **No** — see [Why this model cannot be deployed](#why-this-model-cannot-be-deployed) |

**Headline: at the protocol's false-positive budget this model detects 2.1% of
attack windows.** That number is real, but it is not the interesting one. The
model has genuine signal — it finds 95.4% of `slow_brute_force`, one of the two
held-out scenarios, at a *pooled* 1% budget. What destroys it is a single
benign persona whose traffic overlaps the attack region, and the protocol's
per-persona rule correctly refusing to look away from that.

---

## What was trained

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

## Result at the protocol threshold

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

## Two independent failures

### 1. The forest cannot extrapolate

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

### 2. `forgetful_user` is the binding constraint

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

## The operating curve

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

## Things that did not work

**Applying the protocol's admission rule made it worse.** Dropping run-edge
(half-observed) windows from both training and evaluation moved pooled
operational recall from 2.1% to **0.9%**, and the threshold from −0.7528 to
−0.7639. The run-edge windows were a plausible culprit — all five false
positives are run-edge — but removing them refits the model and its score
distribution, and `forgetful_user` still binds. Run-edge contamination is a real
defect in v2; it is not what is holding this model back.

## Why this model cannot be deployed

`datasets/v2` is frozen under feature spec **v1** (12 features). The runtime now
declares spec **v2** (13 features — `endpoint_method_deviation` was added). The
artifact records its own schema honestly, so `ModelScorer` refuses to load it
rather than feeding a model a column it was never fitted on:

```json
"feature_schema_version": "v1",
"runtime_schema_version": "v2",
"runtime_loadable": false
```

The 13th feature cannot be retrofitted onto v2: it is derived from per-window
`endpoint_counts`, which was an in-memory build artifact and was never exported
to the frozen files. Producing a loadable model requires a dataset built under
spec v2 — which requires raw capture, which is gitignored and no longer on disk.

## What to do next

1. **Do not loosen the budget to make the number look better.** The pooled 1%
   figure is 8.92% on one persona. The per-persona rule is the only reason that
   is visible, and it should stay.
2. **Separating `forgetful_user` from `slow_brute_force` is the whole problem.**
   `interarrival_cv` already distinguishes them (0.274 against 0.027). An
   unsupervised forest weighting twelve features uniformly cannot exploit that;
   a model that can — or a feature that makes the distinction sharper — is worth
   more here than any amount of retuning.
3. **The extrapolation failure needs an answer even if the detectors cover it.**
   Any value beyond the benign training range collapses to one score. A
   monotone, extrapolating signal alongside the forest would fix it.
4. **A v3 dataset is still required** for anything deployable, and separately
   for the admission rule and run-level benign holdout the protocol specifies.

## Reproducing this

```bash
cd control-plane && python -m venv .venv && .venv/bin/pip install -e ".[dev,ml]"

# Train. --allow-schema-mismatch is required because v2 is spec v1 and this
# runtime is spec v2; the artifact records that it is not loadable here.
PYTHONPATH=. .venv/bin/python -m iasg.ml.train \
  --dataset ../datasets/v2 --out ../models/v2-iforest \
  --version iforest-v2-spec1 --allow-schema-mismatch

# Evaluate against the protocol: per-persona budget, coverage, and both recalls.
PYTHONPATH=. .venv/bin/python -m iasg.ml.evaluate \
  --dataset ../datasets/v2 --artifact ../models/v2-iforest \
  --budget 0.01 --out ../models/v2-iforest/evaluation.json
```

`model.joblib` is gitignored — it is exactly reproducible from the frozen
dataset and a fixed seed. `metadata.json` and `evaluation.json` are kept,
because they are what makes a claim about this model checkable.
