# Evaluation plan

Written by the build, before any model is fit. Deciding what counts as
success after seeing the scores is how a result gets talked into existing.

## What this dataset contains

- Rows: 85
- Split: test=44, train=26, val=15
- Attack rows: 27
- Abstaining rows (1-2 requests): 17
- Rows in an incompletely observed minute: 1

### Scenarios

- `api_flood`: 4 rows
- `benign`: 58 rows
- `credential_stuffing`: 4 rows
- `enumeration`: 4 rows
- `low_and_slow_enumeration`: 3 rows
- `path_traversal`: 4 rows
- `slow_brute_force`: 4 rows
- `sqli_probe`: 4 rows

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
