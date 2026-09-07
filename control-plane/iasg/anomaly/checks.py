"""
Checks a dataset has to pass before it is frozen.

These are the guarantees the specification makes stated as assertions. They run
over a built dataset rather than over the code, because most of them are about
what ended up in the files -- and the files are what a model is trained from.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from iasg.anomaly.spec import FEATURE_NAMES

# Anything that could identify a row, name its label, or carry a detector's
# opinion. Checked by name against features.csv, which is a blunt instrument on
# purpose: the real guard is that these live in a different file, and this
# catches the case where somebody wires them into the wrong one.
FORBIDDEN_FEATURE_COLUMNS = (
    "ip",
    "address",
    "client_ip",
    "run_id",
    "session_id",
    "scenario",
    "label",
    "window_start",
    "ts",
    "timestamp",
    "fired",
    "signals",
    "risk_score",
    "riskScore",
    "decision",
    "policy",
    "confidence",
    "status",
)


@dataclass(frozen=True)
class CheckFailure:
    check: str
    detail: str

    def __str__(self) -> str:
        return f"{self.check}: {self.detail}"


def check_feature_header(path: str | Path) -> list[CheckFailure]:
    """
    features.csv is exactly row_id plus the twelve, in order.

    This is the leakage guarantee made physical. It cannot contain an address,
    a label or a timestamp because there is no column for one.
    """
    with open(path, newline="") as handle:
        header = next(csv.reader(handle), [])

    expected = ["row_id", *FEATURE_NAMES]
    if header != expected:
        extra = [c for c in header if c not in expected]
        missing = [c for c in expected if c not in header]
        detail = f"header is {header}"
        if extra:
            detail += f"; unexpected {extra}"
        if missing:
            detail += f"; missing {missing}"
        if sorted(header) == sorted(expected):
            detail += " (order matters: a vector is positional)"
        return [CheckFailure("feature_header", detail)]
    return []


def check_no_identifying_columns(path: str | Path) -> list[CheckFailure]:
    with open(path, newline="") as handle:
        header = next(csv.reader(handle), [])
    found = [c for c in header if c.lower() in {f.lower() for f in FORBIDDEN_FEATURE_COLUMNS}]
    if found:
        return [CheckFailure("identifying_columns", f"features.csv carries {found}")]
    return []


def check_split_disjoint(rows: Iterable[dict]) -> list[CheckFailure]:
    """
    No group key appears in two partitions.

    Groups are placed whole, so one address's windows cannot be split across
    train and test. Otherwise a model can memorise an address in training and
    be graded on the same address's other minutes.
    """
    seen: dict[tuple, str] = {}
    failures: list[CheckFailure] = []
    for row in rows:
        key = (row.get("run_id"), row.get("ip"))
        split = row.get("split")
        previous = seen.setdefault(key, split)
        if previous != split:
            failures.append(
                CheckFailure("split_disjoint", f"{key} appears in {previous} and {split}")
            )
    return failures


def check_reserved_scenarios_held_out(
    rows: Iterable[dict], reserved: Sequence[str]
) -> list[CheckFailure]:
    """
    Reserved scenarios appear only in test.

    slow_brute_force and low_and_slow_enumeration exist to be unseen. A
    threshold tuned against them measures nothing, because the whole claim is
    that this layer catches attacks staying deliberately under the detectors'
    thresholds.
    """
    reserved_set = set(reserved)
    failures = []
    for row in rows:
        if row.get("scenario") in reserved_set and row.get("split") != "test":
            failures.append(
                CheckFailure(
                    "reserved_held_out",
                    f"{row.get('scenario')} placed in {row.get('split')}",
                )
            )
    return failures


def check_labels_independent_of_detectors(rows: Iterable[dict]) -> list[CheckFailure]:
    """
    A row that fired signals but is not in the run manifest labels 0.

    A dataset labelled by the detectors can only teach a model to reproduce the
    detectors, mistakes included, and it would score well while being worthless
    -- the point of this layer is to catch what they miss.
    """
    failures = []
    for row in rows:
        fired = row.get("fired") or ""
        attacker = str(row.get("manifest_attacker", "")).lower() in ("1", "true", "yes")
        if fired and not attacker and str(row.get("label")) not in ("0", "False", "false"):
            failures.append(
                CheckFailure(
                    "label_independence",
                    f"row {row.get('row_id')} labelled {row.get('label')} on detector output alone",
                )
            )
    return failures


def check_no_empty_paths(rows: Iterable) -> list[CheckFailure]:
    """A path is always present in a well-formed record; an empty one is a
    telemetry defect, and in strict mode it fails the build."""
    failures = []
    for row in rows:
        defects = getattr(row, "quality", None)
        if defects is not None and defects.telemetry_defects:
            failures.append(
                CheckFailure(
                    "telemetry_defects",
                    f"{row.ip} at {row.window_start.isoformat()} has "
                    f"{defects.telemetry_defects} malformed record(s)",
                )
            )
    return failures
