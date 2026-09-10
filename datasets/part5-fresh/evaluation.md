# Evaluation plan

Written by the build, before any model is fit. Deciding what counts as
success after seeing the scores is how a result gets talked into existing.

## What this dataset contains

- Rows: 721
- Split: test=155, train=418, val=148
- Attack rows: 77
- Abstaining rows (1-2 requests): 34
- Rows in an incompletely observed minute: 1

### Scenarios

- `api_flood`: 11 rows
- `benign`: 644 rows
- `credential_stuffing`: 11 rows
- `enumeration`: 11 rows
- `low_and_slow_enumeration`: 11 rows
- `path_traversal`: 11 rows
- `slow_brute_force`: 11 rows
- `sqli_probe`: 11 rows

### Benign rows per persona

- `browser`: 88 rows
- `dead_link_visitor`: 88 rows
- `forgetful_user`: 88 rows
- `idle`: 16 rows
- `impatient`: 88 rows
- `mobile_poller`: 92 rows
- `one_shot`: 8 rows
- `search_heavy`: 88 rows
- `shopper`: 88 rows

## How it will be measured

1. **False positives on benign test traffic, per persona.** Reported
   separately, never averaged: one persona always being flagged is a
   different failure from a uniform low rate, and the average hides it.
2. **Detection per attack scenario**, per scenario and not pooled.
3. **Coverage**, with abstentions counted as abstentions. A window that
   declined to score is not a miss -- the Go detectors inspected those
   requests regardless.
4. **Detection delay**, in windows.

The threshold is chosen against a fixed false-positive budget on
**validation**. Test is looked at once.

## Held out

- `slow_brute_force`
- `low_and_slow_enumeration`

These never appear outside test. They stay deliberately under the Go
detectors' thresholds, so they are the only honest measure of whether
this layer catches what the detectors miss.
