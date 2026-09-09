# Evaluation plan

Written by the build, before any model is fit. Deciding what counts as
success after seeing the scores is how a result gets talked into existing.

## What this dataset contains

- Rows: 17160
- Split: test=4087, train=9236, val=3837
- Attack rows: 1843
- Abstaining rows (1-2 requests): 1201
- Rows in an incompletely observed minute: 1580

### Scenarios

- `api_flood`: 264 rows
- `benign`: 15317 rows
- `credential_stuffing`: 264 rows
- `enumeration`: 264 rows
- `low_and_slow_enumeration`: 261 rows
- `path_traversal`: 264 rows
- `slow_brute_force`: 262 rows
- `sqli_probe`: 264 rows

### Benign rows per persona

- `browser`: 2102 rows
- `dead_link_visitor`: 2099 rows
- `forgetful_user`: 2099 rows
- `idle`: 394 rows
- `impatient`: 2112 rows
- `mobile_poller`: 2094 rows
- `one_shot`: 211 rows
- `search_heavy`: 2107 rows
- `shopper`: 2099 rows

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
