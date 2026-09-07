"""
Which 60-second window a request belongs to.

Arrival time decides, exclusively. A request that arrived at 12:00:59 and
finished at 12:01:02 is in the 12:00 window whatever happened afterwards --
otherwise a burst straddling a boundary reads as two smaller ones, and slow
requests are what an attack produces, so the error would not be random.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from iasg.anomaly.records import RequestRecord
from iasg.anomaly.spec import WINDOW_SECONDS


def window_start(ts: datetime) -> datetime:
    """
    Floor to the aligned window. Aligned to the epoch in UTC rather than to the
    first request seen, so two processes reading the same traffic agree on
    where the boundaries are without coordinating.
    """
    ts = ts.astimezone(timezone.utc)
    epoch_seconds = int(ts.timestamp())
    return datetime.fromtimestamp(
        epoch_seconds - (epoch_seconds % WINDOW_SECONDS), tz=timezone.utc
    )


def window_end(start: datetime) -> datetime:
    return start + timedelta(seconds=WINDOW_SECONDS)


def in_window(record: RequestRecord, start: datetime) -> bool:
    """Half-open: [window_start, window_end). A request on the boundary belongs
    to the window it starts, and to exactly one window."""
    return start <= record.arrival_ts.astimezone(timezone.utc) < window_end(start)


def assign(records: Iterable[RequestRecord]) -> dict[tuple[str, datetime], list[RequestRecord]]:
    """
    Group records by (address, window).

    Only windows with at least one request exist as keys. A window with no
    requests is not a row at all -- an inactive client produces absence, not a
    zero, and manufacturing zero rows for every idle address would bury the
    dataset in samples of nothing happening.
    """
    grouped: dict[tuple[str, datetime], list[RequestRecord]] = defaultdict(list)
    for record in records:
        grouped[(record.ip, window_start(record.arrival_ts))].append(record)
    return dict(grouped)
