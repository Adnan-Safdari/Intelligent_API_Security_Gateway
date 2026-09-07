"""
Which partition a row goes to.

Groups are placed whole. The group key is (run_id, ip) plus a replay group, so
one address's windows cannot land on both sides -- otherwise a model memorises
an address in training and is graded on the same address's other minutes.

Train is benign only: this is an anomaly model, fitted on what normal looks
like. The threshold is chosen on validation and nowhere else, and test is
looked at once.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

TRAIN, VAL, TEST = "train", "val", "test"

# Scenarios that must never be seen while tuning. They exist to test the claim
# that this layer catches attacks deliberately staying under the detectors'
# thresholds -- a threshold tuned against them would measure nothing.
RESERVED_SCENARIOS = ("slow_brute_force", "low_and_slow_enumeration")


class ReservedScenarioMisplaced(ValueError):
    """Raised rather than corrected. A reserved scenario outside test
    invalidates the evaluation, and quietly moving it would hide that the
    splitter was asked to do the wrong thing."""


@dataclass(frozen=True)
class Split:
    seed: str = "iasg-v1"
    val_fraction: float = 0.5

    def group_key(self, run_id: str, ip: str, replay_group: str = "") -> tuple[str, str, str]:
        return (run_id, ip, replay_group)

    def _bucket(self, key: tuple[str, str, str]) -> float:
        """
        Deterministic from the key, so a rebuild reproduces the same split
        without storing one. A random shuffle would make two builds of the same
        run incomparable.
        """
        digest = hashlib.sha256((self.seed + "|" + "|".join(key)).encode()).hexdigest()
        return int(digest[:16], 16) / float(1 << 64)

    def assign(
        self, key: tuple[str, str, str], label: int, scenario: str
    ) -> str:
        if scenario in RESERVED_SCENARIOS:
            # Held out whole, regardless of the hash.
            return TEST
        if label == 0:
            # Benign traffic spreads across all three: train needs it to learn
            # normal, and val and test need it to measure false positives.
            bucket = self._bucket(key)
            if bucket < 0.6:
                return TRAIN
            return VAL if bucket < 0.8 else TEST
        # Attacks are never in train. An anomaly model fitted on attacks is a
        # classifier with two examples of each attack, which is not what this
        # is.
        return VAL if self._bucket(key) < self.val_fraction else TEST


def check_reserved(rows: Sequence[dict]) -> None:
    for row in rows:
        if row.get("scenario") in RESERVED_SCENARIOS and row.get("split") != TEST:
            raise ReservedScenarioMisplaced(
                f"{row['scenario']} placed in {row.get('split')!r}, must be test"
            )
