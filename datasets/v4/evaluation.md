# Evaluation plan

Written by the build, before any model is fit. Deciding what counts as
success after seeing the scores is how a result gets talked into existing.

## What this dataset contains

- Rows: 16438
- Split: test=3825, train=8883, val=3730
- Attack rows: 1768
- Abstaining rows (1-2 requests): 1122
- Rows in an incompletely observed minute: 1501

### Scenarios

- `api_flood`: 253 rows
- `benign`: 14670 rows
- `credential_stuffing`: 253 rows
- `enumeration`: 253 rows
- `low_and_slow_enumeration`: 251 rows
- `path_traversal`: 253 rows
- `slow_brute_force`: 252 rows
- `sqli_probe`: 253 rows

### Benign rows per persona

- `browser`: 2015 rows
- `dead_link_visitor`: 2011 rows
- `forgetful_user`: 2013 rows
- `idle`: 378 rows
- `impatient`: 2016 rows
- `mobile_poller`: 2006 rows
- `one_shot`: 202 rows
- `search_heavy`: 2015 rows
- `shopper`: 2014 rows

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
