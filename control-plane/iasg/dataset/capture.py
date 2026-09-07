"""
Drain the gateway's telemetry streams to disk, losslessly enough to be honest
about what was lost.

Two things make this more than a copy loop.

Its own consumer group. Redis delivers every entry to every group
independently, so capture reads the same streams the agent does without
disturbing it, and sees clean requests the agent never receives. Nothing in
models.py has to change to make that work, which matters because the line that
returns no Evidence for a request that fired nothing is what campaign formation
depends on.

Trim detection. A capture run can always outlast its stream cap -- prevention
can be exceeded, so it is not relied on. Each batch compares the stream's
oldest surviving id against the last id this group was handed. If the stream's
head has moved past it, entries went by unread, and the affected minutes are
recorded as lost rather than silently read as quiet.
"""

from __future__ import annotations

import json
import os
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from iasg.anomaly.spec import FEATURE_SPEC_VERSION
from iasg.dataset.layout import (
    CAPTURE_GROUP,
    STREAM_ARRIVALS,
    STREAM_EVENTS,
    STREAM_HEALTH,
    RawRun,
)

# Which stream field holds the JSON payload, per stream.
PAYLOAD_FIELD = {
    STREAM_EVENTS: "event",
    STREAM_ARRIVALS: "arrival",
    STREAM_HEALTH: "health",
}


def _entry_id_sort_key(entry_id: str) -> tuple[int, int]:
    """Redis ids are <ms>-<seq>. Compared numerically, because '10-0' sorts
    before '9-0' as text and a trim check must not be fooled by that."""
    ms, _, seq = entry_id.partition("-")
    try:
        return int(ms), int(seq or 0)
    except ValueError:
        return (0, 0)


@dataclass
class StreamStats:
    captured: int = 0
    trim_losses: list[dict[str, Any]] = field(default_factory=list)

    @property
    def entries_lost(self) -> bool:
        return bool(self.trim_losses)


class Capture:
    """
    Drains three streams into one run directory.

    Durability order is append, flush, fsync, then ack -- in that order and not
    another. Acking first would let a crash between the ack and the write lose
    entries permanently, with the group's cursor already past them and no way
    to notice.
    """

    def __init__(self, store, run: RawRun, run_id: str, consumer: str = "capture-1") -> None:
        self._store = store
        self._run = run
        self._run_id = run_id
        self._consumer = consumer
        self._files: dict[str, TextIO] = {}
        self._stats: dict[str, StreamStats] = {
            stream: StreamStats() for stream in PAYLOAD_FIELD
        }
        self._started = datetime.now(timezone.utc)

    def __enter__(self) -> "Capture":
        self._files = {
            STREAM_ARRIVALS: open(self._run.arrivals, "a"),
            STREAM_EVENTS: open(self._run.completions, "a"),
            STREAM_HEALTH: open(self._run.health, "a"),
        }
        for stream in PAYLOAD_FIELD:
            self._store.ensure_group(stream, CAPTURE_GROUP)
        return self

    def __exit__(self, *exc) -> None:
        for handle in self._files.values():
            handle.close()
        self._files = {}

    def drain_once(self, batch_size: int = 500) -> int:
        """One pass over all three streams. Returns entries written."""
        return sum(self._drain_stream(stream, batch_size) for stream in PAYLOAD_FIELD)

    def run(self, seconds: float, batch_size: int = 500, poll: float = 0.5) -> None:
        """
        Drain until the deadline, or until interrupted.

        SIGINT and SIGTERM stop after the current batch is durable rather than
        mid-write, so an operator ending a run early still gets a directory
        that reflects exactly what was acked.
        """
        stopping = {"now": False}

        def _stop(*_):
            stopping["now"] = True

        previous = {
            sig: signal.signal(sig, _stop) for sig in (signal.SIGINT, signal.SIGTERM)
        }
        deadline = time.monotonic() + seconds
        try:
            while not stopping["now"] and time.monotonic() < deadline:
                if self.drain_once(batch_size) == 0:
                    time.sleep(poll)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            # A final pass, so entries written while the loop was sleeping are
            # not left behind by a clean exit.
            self.drain_once(batch_size)
            self.write_manifest()

    def _drain_stream(self, stream: str, batch_size: int) -> int:
        self._check_for_trim(stream)

        entries = self._store.read_group(
            stream, CAPTURE_GROUP, self._consumer, batch_size
        )
        if not entries:
            return 0

        handle = self._files[stream]
        field_name = PAYLOAD_FIELD[stream]
        written: list[str] = []
        for entry_id, fields in entries:
            payload = fields.get(field_name)
            if payload is None:
                # An entry in a shape this run does not understand. Recorded as
                # a defect and acked, because leaving it pending would stall
                # the group behind one malformed record forever.
                payload = json.dumps({"_unparsed": fields})
            handle.write(payload.rstrip("\n") + "\n")
            written.append(entry_id)

        handle.flush()
        os.fsync(handle.fileno())
        # Only now. The entries are on disk, so an ack cannot lose them.
        self._store.ack(stream, CAPTURE_GROUP, *written)

        self._stats[stream].captured += len(written)
        return len(written)

    def _check_for_trim(self, stream: str) -> None:
        """
        Did the stream's head move past what this group was handed?

        If so, entries were trimmed before being read. They are gone -- the
        point is not to recover them but to record that a hole exists, so the
        windows overlapping it are marked rather than read as a quiet minute.
        """
        first = self._store.stream_first_id(stream)
        last_delivered = self._store.group_last_delivered(stream, CAPTURE_GROUP)
        if not first or not last_delivered or last_delivered == "0-0":
            return
        if _entry_id_sort_key(first) <= _entry_id_sort_key(last_delivered):
            return

        loss = {
            "stream": stream,
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "last_delivered_id": last_delivered,
            "first_surviving_id": first,
        }
        losses = self._stats[stream].trim_losses
        # One record per distinct gap. A gap that persists across polls is the
        # same loss seen twice, and counting it twice would overstate it.
        if not losses or losses[-1]["first_surviving_id"] != first:
            losses.append(loss)

    def write_manifest(self) -> None:
        """
        What this run captured and what it knows it lost.

        Written at the end and rewritten on every drain cycle's exit, so an
        interrupted run still describes itself. A run with no manifest is not
        usable -- labels come from the manifest, never from detector output.
        """
        existing: dict[str, Any] = {}
        if self._run.manifest.exists():
            try:
                existing = json.loads(self._run.manifest.read_text())
            except json.JSONDecodeError:
                existing = {}

        existing.update(
            {
                "run_id": self._run_id,
                "spec_version": FEATURE_SPEC_VERSION,
                "capture": {
                    "group": CAPTURE_GROUP,
                    "consumer": self._consumer,
                    "started_at": self._started.isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "streams": {
                        stream: {
                            "captured": stats.captured,
                            "entries_lost": stats.entries_lost,
                            "trim_losses": stats.trim_losses,
                        }
                        for stream, stats in self._stats.items()
                    },
                },
            }
        )
        self._run.manifest.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")

    @property
    def stats(self) -> dict[str, StreamStats]:
        return dict(self._stats)


def main(argv: list[str] | None = None) -> int:
    import argparse

    from iasg.config import Settings
    from iasg.store import open_store

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out", required=True, help="datasets/raw/<run_id>")
    parser.add_argument("--seconds", type=float, default=600.0)
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args(argv)

    # from_env, not Settings(): the bare constructor takes the dataclass
    # defaults and ignores IASG_REDIS_URL entirely, so under Compose it looks
    # for Redis on localhost and finds nothing.
    settings = Settings.from_env()
    store = open_store(settings)
    # open_store falls back to an in-memory store on an unreachable Redis and
    # only prints a warning. That fallback is right for the agent and wrong
    # here: capture would drain a store nothing writes to and produce an empty
    # run that looks like a quiet network.
    if type(store).__name__ != "RedisStore":
        print("[capture] refusing to run without Redis: nothing would be captured")
        return 1

    run = RawRun.at(args.out)
    with Capture(store, run, args.run_id) as capture:
        capture.run(args.seconds, args.batch_size)

    for stream, stats in capture.stats.items():
        note = " (ENTRIES LOST)" if stats.entries_lost else ""
        print(f"[capture] {stream}: {stats.captured} entries{note}")
    print(f"[capture] manifest at {run.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
