"""
The one implementation.

Runtime scores a window by calling extract with as_of=now. The dataset build
produces a training row by calling extract with as_of=window_end. There is no
second function, which is what makes the availability guarantee structural
instead of a rule somebody has to keep remembering:

    a request that arrived at 12:00:59 and completed at 12:01:02, in a window
    scored at 12:01:00, contributes its arrival and none of its response.

Filling that training row in with the response that arrived two seconds later
produces a model expecting information the runtime will never have, and the
failure is silent -- offline metrics look good and production quietly
underperforms.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

from iasg.anomaly.quality import WindowHealth, WindowQuality
from iasg.anomaly.records import RequestRecord
from iasg.anomaly.spec import (
    AUTH_INVALID_CREDENTIALS,
    FEATURE_NAMES,
    INSUFFICIENT_HISTORY_MAX,
    KNOWN_AUTH_OUTCOMES,
    P95,
    WINDOW_SECONDS,
)
from iasg.anomaly.windows import window_end


@dataclass(frozen=True)
class WindowRow:
    """
    One address's activity in one window.

    The address and the window are here because a row has to be identifiable,
    and they are never features. That is enforced physically when a dataset is
    written: they go in metadata.csv, and the build fails if features.csv
    carries any column outside the versioned schema.
    """

    ip: str
    window_start: datetime
    features: dict[str, float | None]
    quality: WindowQuality

    def feature_tuple(self) -> tuple[float | None, ...]:
        """Positional, in FEATURE_NAMES order. Unknowns stay None; imputation
        happens later, from training-partition medians only."""
        return tuple(self.features[name] for name in FEATURE_NAMES)


def _settled(record: RequestRecord, as_of: datetime) -> bool:
    """
    The single availability predicate. Everything about what the runtime could
    and could not have known reduces to this one line.
    """
    return record.completed_ts is not None and record.completed_ts <= as_of


def extract(
    records: Sequence[RequestRecord],
    window_start: datetime,
    as_of: datetime,
    health: WindowHealth | None = None,
) -> WindowRow:
    """
    Summarise one address's window.

    records must already be this address's requests whose arrival fell in this
    window; windows.assign does that grouping. as_of is the instant being asked
    about -- now at runtime, the window's end at build time.
    """
    records = sorted(records, key=lambda r: r.arrival_ts)
    total = len(records)
    if total == 0:
        raise ValueError("a window with no requests is not a row")

    settled = [r for r in records if _settled(r, as_of)]

    features: dict[str, float | None] = {}

    # -- Arrival-derived. Every in-window record counts, settled or not. ------
    features["request_count"] = float(total)
    features["peak_1s_requests"] = float(_peak_one_second(records, window_start))
    features["interarrival_cv"] = _interarrival_cv(records)
    features["unique_path_ratio"] = len({r.path for r in records}) / total
    features["dominant_route_ratio"] = _dominant_route_ratio(records) / total
    features["post_ratio"] = sum(1 for r in records if r.method == "POST") / total

    logins = [r for r in records if r.is_login]
    features["login_ratio"] = len(logins) / total

    # -- Completion-derived. Only settled records. ---------------------------
    settled_logins = [r for r in logins if _settled(r, as_of)]
    known_outcome = [r for r in settled_logins if r.auth_outcome in KNOWN_AUTH_OUTCOMES]
    if not logins:
        # No login was attempted, so there were no failures. Zero, not unknown.
        features["login_failure_ratio"] = 0.0
    elif not known_outcome:
        # Logins happened but nothing came back. The denominator is
        # deliberately not "all attempts": a login the gateway refused never
        # reached the backend, and counting it as a non-failure would let
        # blocking an attacker improve their failure ratio.
        features["login_failure_ratio"] = None
    else:
        failures = sum(1 for r in known_outcome if r.auth_outcome == AUTH_INVALID_CREDENTIALS)
        features["login_failure_ratio"] = failures / len(known_outcome)

    backend = [r for r in settled if r.has_backend_status]
    features["backend_404_ratio"] = _status_ratio(backend, lambda s: s == 404)
    features["backend_5xx_ratio"] = _status_ratio(backend, lambda s: 500 <= s <= 599)

    bodies = [r.request_body_bytes for r in settled if r.request_body_bytes is not None]
    # A confirmed empty body is 0 and counts. A refused or unreadable one is
    # unknown and counts toward neither side.
    features["mean_request_body_bytes"] = (sum(bodies) / len(bodies)) if bodies else None

    durations = [r.upstream_duration_ms for r in settled if r.upstream_duration_ms is not None]
    features["p95_upstream_duration_ms"] = _p95(durations)

    # Runtime windowing replaces this with the largest ready endpoint/method
    # deviation visible in the window.  Offline dataset preparation leaves it
    # unknown until a training-partition baseline is fitted; deterministic
    # missing-value handling makes that absence explicit rather than a zero.
    features["endpoint_method_deviation"] = None

    health = health or WindowHealth()
    quality = WindowQuality(
        known_status_count=len(backend),
        login_attempts=len(logins),
        login_attempts_known_outcome=len(known_outcome),
        complete_body_measurements=len(bodies),
        complete_duration_measurements=len(durations),
        pending_at_scoring=total - len(settled),
        timeouts=sum(1 for r in settled if r.timed_out),
        telemetry_dropped_in_window=health.dropped,
        interval_fully_observed=health.fully_observed,
        insufficient_history=total <= INSUFFICIENT_HISTORY_MAX,
        telemetry_defects=sum(1 for r in records if not r.path),
    )

    ip = records[0].ip
    return WindowRow(ip=ip, window_start=window_start, features=features, quality=quality)


def _peak_one_second(records: Sequence[RequestRecord], start: datetime) -> int:
    """
    The busiest of sixty one-second buckets.

    This is what separates 60 requests spread evenly from 60 in a single
    second, which request_count alone cannot see.
    """
    buckets = Counter()
    for record in records:
        offset = (record.arrival_ts.astimezone(timezone.utc) - start).total_seconds()
        bucket = int(offset)
        # Clamped rather than trusted. A caller that grouped correctly never
        # produces an out-of-range bucket; one that did not would otherwise
        # invent a 61st second rather than failing visibly at its own boundary.
        buckets[min(max(bucket, 0), WINDOW_SECONDS - 1)] += 1
    return max(buckets.values())


def _interarrival_cv(records: Sequence[RequestRecord]) -> float | None:
    """
    Population standard deviation of the arrival gaps over their mean.

    Null below three requests, because two gaps are the fewest that can vary,
    and null on a zero mean, because a coefficient of variation is undefined
    without a positive one. Inventing a number there would place a value where
    there is no measurement.
    """
    if len(records) < 3:
        return None
    gaps = [
        (b.arrival_ts - a.arrival_ts).total_seconds() * 1000.0
        for a, b in zip(records, records[1:])
    ]
    mean = statistics.fmean(gaps)
    if mean <= 0:
        return None
    # ddof=0, stated in the spec so nobody has to guess which convention a
    # library defaulted to.
    return statistics.pstdev(gaps) / mean


def _dominant_route_ratio(records: Sequence[RequestRecord]) -> int:
    counts = Counter((r.method, r.route_template) for r in records)
    return max(counts.values())


def _status_ratio(backend: Sequence[RequestRecord], predicate) -> float | None:
    """Null when no backend status is available at all -- there is nothing to
    take a ratio of, and 0.0 would claim there was."""
    if not backend:
        return None
    return sum(1 for r in backend if predicate(r.upstream_status)) / len(backend)


def _p95(values: Iterable[int]) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    # One-based after ceil: 1 value gives index 1, 20 gives 19, 21 gives 20.
    index = math.ceil(P95 * len(ordered))
    return float(ordered[index - 1])


def extract_all(
    grouped: dict[tuple[str, datetime], list[RequestRecord]],
    as_of: datetime,
    health: dict[datetime, WindowHealth] | None = None,
) -> list[WindowRow]:
    """
    Extract every grouped window. Health is looked up per window because it is
    a property of the minute, not of the address.
    """
    health = health or {}
    rows = [
        extract(records, start, as_of, health.get(start))
        for (_, start), records in grouped.items()
    ]
    return sorted(rows, key=lambda row: (row.window_start, row.ip))


def build_as_of(window_start: datetime) -> datetime:
    """
    What the dataset build passes. Named so a build never writes `now` by
    accident -- the one mistake that would quietly undo the whole guarantee.
    """
    return window_end(window_start)
