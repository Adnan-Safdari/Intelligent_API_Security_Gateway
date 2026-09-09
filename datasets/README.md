# Anomaly Datasets

Frozen datasets for the control plane's anomaly layer, built from real gateway
telemetry by `control-plane/iasg/dataset/build.py`.

**The contract these files implement is
[`gateway/docs/anomaly-features.md`](../gateway/docs/anomaly-features.md).** If
this page and that page disagree, that page wins. This one describes the
artefacts on disk; that one defines what the numbers in them mean.

**How these datasets are scored is
[`gateway/docs/anomaly-evaluation.md`](../gateway/docs/anomaly-evaluation.md)** —
the false-positive budget, the three recall metrics, detection delay, and which
rows are admitted at all. It lives outside the frozen directories because it is
revised; each dataset's own `evaluation.md` records what was decided when that
dataset was built.

## What one row is

**One resolved client address's activity during one non-overlapping 60-second
window**, aligned to `:00` UTC.

- Window membership is by **arrival time**, never completion time. A request
  that arrives at `12:00:59` and completes at `12:01:02` belongs to the
  `12:00` window.
- **A window with no requests is not a row.** An inactive client produces
  *absence*, not a zero — creating zero rows for every idle address would bury
  the dataset in samples of nothing happening.
- Windows with 1–2 requests **are** kept, marked `insufficient_history`, and
  abstain from scoring. That is a coverage rule, not an attack threshold: two
  requests have no meaningful inter-arrival statistics. The Go detectors
  inspect those requests regardless, so abstaining costs nothing on the
  request path.

## Versions

A frozen dataset is never rebuilt in place. A model trained on `v1` has no way
to notice that its inputs changed underneath it, so a change means a new
directory.

| | `v1/` | `v2/` |
| --- | --- | --- |
| Rows | 85 | 17,160 |
| Capture runs | 1 | 24 |
| Benign / attack | 58 / 27 | 15,317 / 1,843 |
| Attack rate | 31.8% | 10.7% |
| Spec version | `v1` | `v1` |
| Built | 2026-09-07T06:23:32Z | 2026-09-08T17:34:01Z |

`v1` is the first end-to-end build — enough to prove the pipeline, too small to
fit a model on. **`v2` is the one to use.** Its 10.7% attack rate is deliberate:
real API traffic is overwhelmingly benign, and a balanced dataset would teach a
model to expect an attack every other minute.

Both share the same eleven files and the same schema.

---

## The files

Every version directory contains these eleven. Four are the dataset, one is the
same data in another shape, and six are provenance.

| File | Role |
| --- | --- |
| `features.csv` | The only thing a model may see |
| `metadata.csv` | Labels and identity — never model inputs |
| `splits.csv` | Partition assignment |
| `quality.csv` | Measurement completeness |
| `rows.jsonl` | All four of the above, rejoined, one JSON object per row |
| `medians.json` | Imputation values, fitted on train only |
| `held_out_scenarios.txt` | Scenarios that exist only in test |
| `evaluation.md` | How success will be measured, written before any model |
| `manifest.json` | A SHA-256 per file |
| `versions.json` | Build environment and run ids |
| `FROZEN` | Freeze timestamp |

### Why four CSVs instead of one table

**The split between them is the leakage guard.** `features.csv` *physically
cannot* contain an address, a label or a timestamp, because those live in
`metadata.csv`. The build runs `check_feature_header` and
`check_no_identifying_columns` **against the written file** — not against the
code that wrote it — and raises `LeakageCheckFailed` if `features.csv` has any
column that is not one of the twelve.

A guarantee that depends on nobody adding the wrong column is not a guarantee.
Making it structural means "don't train on the label" cannot be forgotten.

All four files carry `row_id` as the first column, have identical row counts,
and are sorted by `(window_start, run_id, ip)` with `row_id` assigned 1..N
after that sort.

---

## `features.csv`

`row_id` plus exactly twelve numeric columns, in a frozen order. Order is part
of the contract — a vector is positional, so reordering the columns would
silently retrain their meanings while every test still passed.

Columns 1–7 are computable from **arrival alone**. Columns 8–12 need a
**settled response**. That division is what the runtime availability guarantee
rests on: at scoring time a request still in flight contributes to the first
seven and to none of the last five.

| # | Column | Definition | Null when | Null % (v2) |
| --- | --- | --- | --- | --- |
| 1 | `request_count` | N requests in the window | never | 0% |
| 2 | `peak_1s_requests` | largest of 60 one-second buckets | never | 0% |
| 3 | `interarrival_cv` | population stdev of arrival gaps ÷ mean gap | fewer than 3 requests, or mean gap 0 | 7.0% |
| 4 | `unique_path_ratio` | distinct paths ÷ N | never | 0% |
| 5 | `dominant_route_ratio` | most-used `(method, route template)` ÷ N | never | 0% |
| 6 | `post_ratio` | POST requests ÷ N | never — 0 if none | 0% |
| 7 | `login_ratio` | `POST /api/login` ÷ N | never — 0 if none | 0% |
| 8 | `login_failure_ratio` | confirmed `invalid_credentials` ÷ logins **with a known outcome** | logins occurred, none resolved | 1.2% |
| 9 | `backend_404_ratio` | backend 404s ÷ backend responses with a known status | no backend status available | 2.5% |
| 10 | `backend_5xx_ratio` | backend 500–599 ÷ backend responses with a known status | no backend status available | 2.5% |
| 11 | `mean_request_body_bytes` | sum ÷ count of **completely measured** bodies | none measured | 2.5% |
| 12 | `p95_upstream_duration_ms` | sorted durations at `ceil(0.95 × n)`, one-based | no completed durations | 2.5% |

Every ratio is in `[0, 1]`. Population standard deviation means `ddof = 0`,
stated explicitly so nobody has to guess which convention a library defaulted
to.

### Details that are load-bearing

**Paths are not lexically cleaned.** `/api/../../etc/passwd` keeps its `..`
segments. Collapsing them before measuring path diversity would erase exactly
the behaviour a traversal probe exhibits. (Known gap: a double-encoded `%252e`
decodes once to the literal `%2e` and is counted as a distinct path.)

**`<unmatched>` is a category, not a null.** A path matching no configured
route template lands in a reserved bucket. A scanner walking unmatched paths
produces a large bucket there, and that is informative — treating it as missing
data would discard the signal.

**Gateway-generated statuses are excluded from features 9 and 10**, from both
numerator and denominator. A 403 the enforcer wrote, a 429 from the rate
limiter, a 413 from the body cap and a 502 from an unreachable backend are the
gateway talking about itself. Mixing them in would mean **enforcement changed
the features of the address it enforced against**.

**Feature 8's denominator is deliberately not "all login attempts."** A login
the gateway refused never reached the backend, so its outcome is unknown.
Counting it as a non-failure would let blocking an attacker improve that
attacker's failure ratio.

**Login attempts are identified by method and route** (`POST /api/login`), not
by the telemetry event's `loginAttempt` flag — even though that flag is the
configured, verified notion. The flag is written on the *completion* record,
and feature 7 is arrival-derived. Reading it would mean a login still in flight
did not count as a login, letting an attacker shrink their own `login_ratio` by
making the backend slow.

**There is no "requests per second" feature.** With a fixed 60-second window it
is `request_count / 60` — the same number twice, which teaches a model nothing
and costs a column.

---

## `metadata.csv`

`row_id, run_id, ip, window_start, label, scenario, persona`

| Column | Meaning |
| --- | --- |
| `run_id` | Which capture run produced the row (`run1`..`run24` in v2) |
| `ip` | Resolved client address. **Groups requests; never a feature.** |
| `window_start` | ISO-8601 UTC, `:00`-aligned |
| `label` | `0` benign, `1` attack |
| `scenario` | `benign` plus seven attack types |
| `persona` | Benign behaviour profile; attack rows repeat the scenario name |

**The address is not in the feature array in any form** — not as an integer,
not hashed, not bucketed. A model that learns addresses learns this lab's
address pool rather than behaviour, and one address can be a whole office
behind a shared network.

**Labels come from the run manifest**, recorded before traffic starts. They are
never derived from detector output, `fired`, `riskScore`, `decision` or HTTP
status. A dataset labelled by the detectors can only teach a model to reproduce
the detectors *including their mistakes* — it would score well while being
worthless, since the entire point of this layer is to catch what the detectors
miss.

A high `login_failure_ratio` does not make a row an attack. A genuine user who
mistypes a password three times produces one, and the training set contains
that case on purpose.

### Scenario and persona composition (v2)

| Scenario | Rows | | Persona | Rows |
| --- | --- | --- | --- | --- |
| `benign` | 15,317 | | `impatient` | 2,112 |
| `api_flood` | 264 | | `search_heavy` | 2,107 |
| `credential_stuffing` | 264 | | `browser` | 2,102 |
| `enumeration` | 264 | | `shopper` | 2,099 |
| `path_traversal` | 264 | | `forgetful_user` | 2,099 |
| `sqli_probe` | 264 | | `dead_link_visitor` | 2,099 |
| `slow_brute_force` | 262 | | `mobile_poller` | 2,094 |
| `low_and_slow_enumeration` | 261 | | `idle` | 394 |
| | | | `one_shot` | 211 |

---

## `splits.csv`

`row_id, split, group_key` — where `group_key` is `run_id|ip`.

### v2 partitions

| Split | Rows | Benign | Attack | Attack % | Unique IPs |
| --- | --- | --- | --- | --- | --- |
| `train` | 9,236 | 9,236 | **0** | 0.00% | 72 |
| `val` | 3,837 | 3,221 | 616 | 16.05% | 77 |
| `test` | 4,087 | 2,860 | 1,227 | 30.02% | 79 |

**Train contains no attacks, by design.** This is an anomaly model fitted on
what normal looks like, not a classifier. An anomaly model fitted on attacks is
a classifier with two examples of each attack, which is a different thing built
badly.

The threshold is chosen on **validation** against a fixed false-positive
budget. **Test is looked at once.**

### How a row is assigned

```
reserved scenario  -> test, always, regardless of the hash
label == 0         -> bucket < 0.6 train, < 0.8 val, else test
label == 1         -> bucket < 0.5 val,   else test        (never train)
```

`bucket` is `sha256("iasg-v1|" + run_id + "|" + ip + "|" + replay_group)`,
first 16 hex digits over 2^64. **Deterministic, not random** — a rebuild
reproduces the same split without storing it, and a random shuffle would make
two builds of the same run incomparable.

**Groups are placed whole.** In v2: 1,896 groups, **0 spanning more than one
split**. One address's windows cannot land on both sides, so a model cannot
memorise an address in training and then be graded on that same address's other
minutes.

A reserved scenario found outside test raises `ReservedScenarioMisplaced`
rather than being quietly corrected. Moving it would hide that the splitter was
asked to do the wrong thing.

---

## `quality.csv`

`row_id` plus eleven counters and flags, carried alongside every row and
**never in the feature array**.

These exist to separate *an incomplete measurement* from *unusual behaviour*.
Without them, a collection outage looks exactly like an address that went
quiet.

| Column | Meaning | Non-zero (v2) |
| --- | --- | --- |
| `known_status_count` | Backend responses with a status, settled at scoring time | 97.5% |
| `login_attempts` | Total login attempts in the window | 5.7% |
| `login_attempts_known_outcome` | Denominator of feature 8 | 4.4% |
| `complete_body_measurements` | Denominator of feature 11 | 97.5% |
| `complete_duration_measurements` | Denominator of feature 12 | 97.5% |
| `pending_at_scoring` | Arrived in-window, not yet settled | 0.1% |
| `timeouts` | Upstream timeouts — no status, no duration | 0% |
| `telemetry_dropped_in_window` | Telemetry dropped rather than delaying traffic | 0% |
| `interval_fully_observed` | Whole 60s observed, no gap, drop or stream trim | 90.8% true |
| `insufficient_history` | `1 <= request_count <= 2` | 7.0% |
| `telemetry_defects` | Malformed records, e.g. an empty path | 0% |

The null counts in `features.csv` are exactly explained here: the 1,201
`interarrival_cv` nulls are the 1,201 `insufficient_history` rows, and the 422
nulls in features 9–12 are the 422 rows with no known backend status.

**`telemetry_dropped_in_window` cannot be attributed to an address.** The
gateway's drop counter is process-wide, so the flag is window-wide. It says
"something was lost during this minute" — enough to distrust every row in that
minute, not enough to say whose.

---

## Zero versus unknown

The extractor must never conflate these, and neither should anything reading
the files.

| Situation | Feature value | Quality field |
| --- | --- | --- |
| No login requests occurred | `login_ratio`, `login_failure_ratio` = **0** | — |
| Logins occurred, outcomes unavailable | `login_failure_ratio` = **null** | `login_attempts_known_outcome` |
| Request definitely had no body | body size **0**, counted | `complete_body_measurements` |
| Body truncated or refused | body size **unknown**, not counted | `complete_body_measurements` |
| Gateway-generated 403 / 429 / 413 / 502 | **not** a backend response, in no ratio | `known_status_count` |
| Backend request timed out | recorded timeout, **no** status, **no** duration | `timeouts` |
| Request still in flight at scoring | arrival features only | `pending_at_scoring` |

**Unknowns stay empty in the CSVs and `null` in the JSONL. Imputation happens
later and elsewhere** — at vectorisation time, from `medians.json`.

---

## `rows.jsonl`

One JSON object per line, containing everything the four CSVs hold, rejoined:

```json
{
  "row_id": 1,
  "run_id": "run1",
  "ip": "203.0.113.10",
  "window_start": "2026-09-08T12:43:00+00:00",
  "label": 0,
  "scenario": "benign",
  "persona": "browser",
  "split": "test",
  "features": { "request_count": 2.0, "interarrival_cv": null, ... },
  "quality":  { "known_status_count": 2, "insufficient_history": true, ... }
}
```

For reading, debugging and eyeballing a single window. **Do not train from it**
— it has the label sitting next to the features, which is the exact adjacency
the four-file split exists to prevent.

## `medians.json`

One median per feature, **fitted on the training partition only**, and reused
byte-identically at runtime.

```json
{"medians": {"request_count": 8.0, "interarrival_cv": 0.3233347736185087, ...},
 "spec_version": "v1"}
```

A median computed over the whole dataset would leak the test partition into the
model through the back door. Shipping the file rather than recomputing at
serving time is what stops training and runtime from imputing differently.

Median replacement **cannot repair a broken telemetry pipeline**. It will
happily produce a full column of the same number and hide the fact that nothing
was ever measured. If a feature has no usable training measurements at all, fix
its collection or remove it from the schema before freezing.

## `held_out_scenarios.txt`

```
slow_brute_force
low_and_slow_enumeration
```

These appear **only in test** — zero rows in train, zero in val. They stay
deliberately under the Go detectors' thresholds, so they are the only honest
measure of whether this layer catches what the detectors miss. A threshold
tuned against them would measure nothing.

Why they are hard, in medians:

| Scenario | `request_count` | `peak_1s` | `unique_path_ratio` | `interarrival_cv` |
| --- | --- | --- | --- | --- |
| `benign` | 8 | 1 | 0.75 | 0.329 |
| `api_flood` | 1,231 | 24 | 0.0008 | 0.359 |
| `credential_stuffing` | 119 | 3 | 0.0084 | 0.342 |
| `enumeration` | 92 | 3 | 0.098 | 0.314 |
| `path_traversal` | 74 | 2 | 0.213 | 0.289 |
| `sqli_probe` | 47 | 2 | 0.021 | 0.345 |
| **`slow_brute_force`** | **7** | **1** | 0.143 | **0.027** |
| **`low_and_slow_enumeration`** | **5** | **1** | **0.80** | **0.021** |

The five tunable attacks are loud. The two held-out ones are not: they sit at
benign request volume with a benign one-per-second peak, and
`low_and_slow_enumeration` has *higher* path diversity than normal traffic.
Only `interarrival_cv` separates them — machine-regular timing where humans are
bursty. That single column is why the feature is allowed to be null rather than
imputed with an invented value.

## `evaluation.md`

Written by the build, **before any model is fit**. Deciding what counts as
success after seeing the scores is how a result gets talked into existing.

It fixes four measurements, and names what must not be averaged away:

1. **False positives on benign test traffic, per persona** — reported
   separately, never pooled. One persona always being flagged is a different
   failure from a uniform low rate, and the average hides it.
2. **Detection per attack scenario**, per scenario and not pooled.
3. **Coverage**, with abstentions counted as abstentions.
4. **Detection delay**, in windows.

It also records anything unplanned the build encountered, such as windows
dropped from addresses not in the run manifest.

**Superseded in part.** v2's copy says "a fixed false-positive budget" without a
number, and "a window that declined to score is not a miss" — true of the
conditional metric, misleading alone, since an abstaining attack window is not
detected by this layer either. Both are corrected in the
[Evaluation Protocol](../gateway/docs/anomaly-evaluation.md), which fixes the
budget at 1.0% per gated persona and requires coverage, conditional recall and
operational recall to be reported together. v2's file is left untouched: it is
hashed in `manifest.json`, and it is the record of what was decided then.

## `manifest.json`

A SHA-256 per file, plus `spec_version`, the run ids, and the row count. What
makes a frozen dataset **checkable** rather than just labelled frozen.

`manifest.json` and `FROZEN` are excluded from their own digest set.

```bash
cd control-plane && PYTHONPATH=. python -c \
  "from iasg.dataset.build import verify; print(verify('../datasets/v2') or 'OK')"
```

Both `v1` and `v2` currently verify clean.

## `versions.json`

Build provenance: `built_at`, `python`, `platform`, `spec_version`, and the run
ids. Enough to tell whether two datasets came from the same environment when
their numbers disagree.

## `FROZEN`

A single ISO-8601 timestamp. Its presence makes `build()` raise
`DatasetFrozen`. A frozen dataset is not rebuilt in place — a model trained on
it has no way to notice that its inputs changed underneath.

`--force` overrides this. It is for correcting a build that was wrong within
minutes of making it, not for editing history. **A frozen dataset that has been
edited is worse than one that was never frozen**, because its manifest still
claims it is intact.

---

## Reading the dataset

```python
import csv

def load(version, name):
    with open(f"datasets/{version}/{name}.csv") as fh:
        return {r["row_id"]: r for r in csv.DictReader(fh)}

features = load("v2", "features")
splits   = load("v2", "splits")
labels   = load("v2", "metadata")   # evaluation only, never an input

train = [features[i] for i in features if splits[i]["split"] == "train"]
```

Empty string means null. Impute from `medians.json` — never from statistics
computed over the file you just loaded, which would include val and test.

## Rebuilding

Raw capture lives in `datasets/raw/` and is **gitignored**: hundreds of
megabytes of JSONL, reproducible from a rerun, and containing every request
path a run drove. The frozen dataset is the artefact, and its manifest is what
makes it checkable.

```bash
cd control-plane

# Capture. Refuses to run without Redis -- the in-memory fallback would
# produce an empty run that looks like quiet traffic.
PYTHONPATH=. .venv/bin/python -m iasg.dataset.capture \
  --run-id run25 --out datasets/raw/run25

# Build. Writes all eleven files, runs the leakage checks, freezes, verifies.
PYTHONPATH=. .venv/bin/python -m iasg.dataset.build \
  --runs datasets/raw/run1 datasets/raw/run2 --out datasets/v3
```

Use `IASG_CONFIG=configs/config.collect.yaml` for a capture run. The default
caps are tuned for a hot demo window, not a dataset.

Attack traffic must come from `203.0.113.x` (RFC 5737). `policy/writer.py`
refuses to police private, loopback and reserved addresses, so an attack from
localhost produces no policy at all and looks broken.

## What this layer is allowed to do

Stated here because it bounds how much the dataset's quality matters.

The anomaly score is worth **at most one severity rung**, and only on a
campaign that already earned an action on evidence alone. **It never originates
enforcement.** An unsupervised model fit on a small laboratory dataset is the
last input that should be trusted to block somebody by itself.

These features describe *behaviour* and cannot identify every malicious
payload. A single SQL injection request may have entirely ordinary timing,
size, path diversity and response status — there is nothing anomalous about one
request. The deterministic detectors are not replaced by this layer and must
keep running alongside it.
