"""
Turning a row into the array a model sees.

Nothing but the versioned numerical features crosses this boundary. The address, the
timestamp, the label, the run, the detector output and the enforcement decision
are all metadata, and a model that learns any of them learns this laboratory
rather than behaviour.
"""

from __future__ import annotations

from typing import Sequence

from iasg.anomaly.extract import WindowRow
from iasg.anomaly.impute import Medians
from iasg.anomaly.spec import FEATURE_NAMES


def to_vector(row: WindowRow, medians: Medians) -> tuple[float, ...]:
    """Positional in FEATURE_NAMES order, unknowns filled from the training
    medians."""
    return medians.apply(row.feature_tuple())


def abstains(row: WindowRow) -> bool:
    """
    Whether this row declines to be scored.

    A one- or two-request window has no meaningful inter-arrival statistics, so
    it abstains rather than being scored badly. This costs no coverage on the
    request path -- the Go detectors inspected those requests regardless -- but
    an abstention must be reported as an abstention and never counted as a miss.
    """
    return row.quality.insufficient_history


def header() -> Sequence[str]:
    """The feature matrix's columns, and nothing else. checks.py asserts a
    written features.csv matches this exactly."""
    return FEATURE_NAMES
