# Part 5 fresh validation

Run `part5-fresh` used the collection configuration and the unchanged
ten-minute traffic plan on 2026-09-10. It exercised eight sessions of every
benign persona (including `forgetful_user` and `dead_link_visitor`), both
held-out low-and-slow scenarios, and all existing attack scenarios.

The capture recorded 20,654 arrivals, 20,650 completions, and no stream trim
losses. It built 721 one-minute windows (77 attack, 644 benign). The advisory
artifact was retrained only from frozen `datasets/v4`; its threshold was fixed
by that dataset's validation partition at `-0.6269392937796316`. The fresh run
was never used to train or select a threshold.

`datasets/part5-fresh/fresh-validation.json` contains the machine-readable
report. “Rules” means deterministic detector evidence, not a policy write;
advisory ML remains non-enforcing in every view.

## Per-persona false positives

Cells are `false positives / evaluated minutes`; `—` means every minute
abstained from advisory scoring.

| Persona | Rules only | Advisory ML only | Rules + advisory ML |
| --- | ---: | ---: | ---: |
| browser | 0 / 88 | 0 / 88 | 0 / 88 |
| dead-link visitor | 0 / 88 | 0 / 87 | 0 / 88 |
| forgetful user | 0 / 88 | 8 / 88 | 8 / 88 |
| idle | 0 / 16 | — (16 abstained) | 0 / 16 |
| impatient | 0 / 88 | 9 / 87 | 9 / 88 |
| mobile poller | 0 / 92 | 0 / 84 | 0 / 92 |
| one shot | 1 / 8 | — (8 abstained) | 1 / 8 |
| search heavy | 0 / 88 | 0 / 88 | 0 / 88 |
| shopper | 0 / 88 | 8 / 88 | 8 / 88 |
| **pooled** | **1 / 644 (0.16%)** | **25 / 610 (4.10%)** | **26 / 644 (4.04%)** |

This is deliberately not described as zero false positives: the deterministic
result includes one `one_shot` minute, while the advisory and combined views
flagged failed-login, impatient, and shopper traffic. Each persona has fewer
than the 100-minute gating minimum, so the per-persona values are observations,
not a passed false-positive budget.

## Attack recall by scenario

Cells are detected minutes / 11 attack minutes. All attack minutes were
scorable by the advisory model in this run.

| Scenario | Rules only | Advisory ML only | Rules + advisory ML |
| --- | ---: | ---: | ---: |
| API flood | 10 / 11 (90.9%) | 10 / 11 (90.9%) | 10 / 11 (90.9%) |
| credential stuffing | 11 / 11 (100%) | 11 / 11 (100%) | 11 / 11 (100%) |
| enumeration | 11 / 11 (100%) | 0 / 11 (0%) | 11 / 11 (100%) |
| low-and-slow enumeration | 6 / 11 (54.5%) | 0 / 11 (0%) | 6 / 11 (54.5%) |
| path traversal | 11 / 11 (100%) | 0 / 11 (0%) | 11 / 11 (100%) |
| slow brute force | 10 / 11 (90.9%) | 11 / 11 (100%) | 11 / 11 (100%) |
| SQL injection probe | 11 / 11 (100%) | 8 / 11 (72.7%) | 11 / 11 (100%) |
| **pooled** | **70 / 77 (90.9%)** | **40 / 77 (51.9%)** | **71 / 77 (92.2%)** |

## Gateway-missed attack-minute coverage

A gateway miss is an attack minute with no deterministic detector evidence and
no gateway refusal. This definition prevents a request already stopped by a
policy or reflex from being misreported as a detector blind spot.

| Scenario | Gateway-missed minutes | Advisory ML coverage of misses | Combined coverage of misses |
| --- | ---: | ---: | ---: |
| API flood | 1 | 0 / 1 | 0 / 1 |
| low-and-slow enumeration | 5 | 0 / 5 | 0 / 5 |
| slow brute force | 1 | 1 / 1 | 1 / 1 |
| **total** | **7** | **1 / 7 (14.3%)** | **1 / 7 (14.3%)** |

The low-and-slow enumeration misses are therefore a real unresolved gap in
this fresh run. The thresholds were not adjusted after observing it.
