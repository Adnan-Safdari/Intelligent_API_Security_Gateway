"""
What was measurable, kept apart from what was measured.

Without these a collection outage looks exactly like an address that went
quiet. They are metadata: never model inputs, never in the feature array, and
physically in a different file from it once a dataset is built.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class WindowQuality:
    known_status_count: int = 0
    login_attempts: int = 0
    login_attempts_known_outcome: int = 0
    complete_body_measurements: int = 0
    complete_duration_measurements: int = 0

    # Arrived in-window and had not settled when the window was scored. A
    # window full of these is incomplete, not sparse.
    pending_at_scoring: int = 0
    timeouts: int = 0

    # Process-wide at the gateway, so this is window-wide and cannot be
    # attributed to one address. It says something was lost during this minute,
    # which is enough to distrust every row in the minute and not enough to say
    # whose. Filled in from the health heartbeat, not from the requests.
    telemetry_dropped_in_window: int = 0
    interval_fully_observed: bool = True

    insufficient_history: bool = False

    # Malformed records -- an empty path, an unparseable timestamp. Counted
    # rather than repaired, because a repaired defect is one nobody ever finds.
    telemetry_defects: int = 0

    def as_dict(self) -> dict[str, int | bool]:
        return asdict(self)


@dataclass(frozen=True)
class WindowHealth:
    """
    The heartbeat's verdict on one window, which no per-request record can
    give: telemetry the gateway dropped, and whether the whole sixty seconds
    was observed with no gap, drop or stream trim.
    """

    dropped: int = 0
    fully_observed: bool = True
