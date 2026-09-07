"""
Filling in unknowns, from the training partition only.

Unknowns stay None all the way through extraction. They are replaced here and
nowhere else, with medians learned from the training rows alone and written to
medians.json, so runtime reuses byte-identical numbers rather than recomputing
anything. A median taken over the whole dataset would leak the test partition
into the model through the back door.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from iasg.anomaly.spec import FEATURE_NAMES, FEATURE_SPEC_VERSION


class UnmeasuredFeature(ValueError):
    """
    Raised when a feature has no usable training measurement at all.

    Median replacement cannot repair a broken telemetry pipeline. Left to
    itself it produces a full column of the same number and hides the fact that
    nothing was ever measured, which is worse than a crash: the model trains,
    scores well on a column of constants, and nobody learns that the collection
    was broken until it is in production.
    """


@dataclass(frozen=True)
class Medians:
    values: dict[str, float]
    spec_version: str = FEATURE_SPEC_VERSION

    @classmethod
    def fit(cls, rows: Iterable, strict: bool = True) -> "Medians":
        """
        Learn one median per feature from the training rows.

        strict=False is for exploratory work only. It substitutes 0.0 for a
        feature nothing measured, which is exactly the silent failure above --
        never use it to produce a dataset that will be frozen.
        """
        columns: dict[str, list[float]] = {name: [] for name in FEATURE_NAMES}
        for row in rows:
            for name in FEATURE_NAMES:
                value = row.features[name]
                if value is not None:
                    columns[name].append(float(value))

        values: dict[str, float] = {}
        for name in FEATURE_NAMES:
            if columns[name]:
                values[name] = statistics.median(columns[name])
            elif strict:
                raise UnmeasuredFeature(
                    f"{name} has no measurement in the training partition; "
                    "fix its collection or remove it from the schema before freezing"
                )
            else:
                values[name] = 0.0
        return cls(values=values)

    def save(self, path: str | Path) -> None:
        payload = {"spec_version": self.spec_version, "medians": self.values}
        Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> "Medians":
        payload = json.loads(Path(path).read_text())
        version = payload.get("spec_version")
        if version != FEATURE_SPEC_VERSION:
            # A vector is positional. Medians fitted under another spec version
            # would be applied to columns that may mean something else, and
            # nothing downstream could notice.
            raise ValueError(
                f"medians.json is spec {version!r}, this code is {FEATURE_SPEC_VERSION!r}"
            )
        medians = payload.get("medians") or {}
        missing = [name for name in FEATURE_NAMES if name not in medians]
        if missing:
            raise ValueError(f"medians.json is missing {', '.join(missing)}")
        return cls(values={name: float(medians[name]) for name in FEATURE_NAMES})

    def apply(self, vector: Sequence[float | None]) -> tuple[float, ...]:
        if len(vector) != len(FEATURE_NAMES):
            raise ValueError(f"expected {len(FEATURE_NAMES)} features, got {len(vector)}")
        return tuple(
            float(value) if value is not None else self.values[name]
            for name, value in zip(FEATURE_NAMES, vector)
        )
