"""
Capture: its own group, durable before acking, and honest about what it lost.
"""

from __future__ import annotations

import json

import pytest

from iasg.dataset.capture import Capture, _entry_id_sort_key
from iasg.dataset.layout import (
    CAPTURE_GROUP,
    STREAM_ARRIVALS,
    STREAM_EVENTS,
    STREAM_HEALTH,
    RawRun,
)
from iasg.store.memory import MemoryStore


def seeded_store(events=3, arrivals=3, health=2) -> MemoryStore:
    store = MemoryStore()
    for i in range(arrivals):
        store.append(STREAM_ARRIVALS, {"arrival": json.dumps({"requestId": f"r{i}"})})
    for i in range(events):
        store.append(STREAM_EVENTS, {"event": json.dumps({"requestId": f"r{i}"})})
    for i in range(health):
        store.append(STREAM_HEALTH, {"health": json.dumps({"seq": i + 1})})
    return store


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_capture_drains_all_three_streams(tmp_path):
    store = seeded_store()
    run = RawRun.at(tmp_path / "run1")
    with Capture(store, run, "run1") as capture:
        assert capture.drain_once() == 8

    assert len(lines(run.arrivals)) == 3
    assert len(lines(run.completions)) == 3
    assert len(lines(run.health)) == 2


def test_capture_uses_its_own_group_and_leaves_the_agents_alone():
    """
    Redis delivers every entry to every group independently. That is what lets
    capture see clean requests without changing Evidence semantics -- the line
    in models.py that returns nothing for a request that fired nothing is what
    campaign formation depends on, and it must not be touched to make capture
    work.
    """
    store = seeded_store()
    store.ensure_group(STREAM_EVENTS, "iasg-agent")

    # Drain with the agent's group first, then capture's. Both see everything.
    agent_batch = store.read_group(STREAM_EVENTS, "iasg-agent", "agent-1", 500)
    assert len(agent_batch) == 3

    capture_batch = store.read_group(STREAM_EVENTS, CAPTURE_GROUP, "capture-1", 500)
    assert len(capture_batch) == 3
    assert [eid for eid, _ in agent_batch] == [eid for eid, _ in capture_batch]


def test_entries_are_on_disk_before_they_are_acked(tmp_path):
    """
    Acking first would let a crash between the ack and the write lose entries
    permanently, with the group's cursor already past them and nothing able to
    notice.
    """
    store = seeded_store(events=2, arrivals=0, health=0)
    run = RawRun.at(tmp_path / "run1")
    seen_at_ack: dict[str, int] = {}

    real_ack = store.ack

    def watching_ack(stream, group, *ids):
        seen_at_ack[stream] = len(lines(run.completions))
        return real_ack(stream, group, *ids)

    store.ack = watching_ack
    with Capture(store, run, "run1") as capture:
        capture.drain_once()

    assert seen_at_ack[STREAM_EVENTS] == 2


def test_unacked_entries_are_redelivered_after_a_crash(tmp_path):
    """A capture that died before acking replays rather than losing."""
    store = seeded_store(events=2, arrivals=0, health=0)
    run = RawRun.at(tmp_path / "run1")

    store.ack = lambda *args, **kwargs: 0  # the crash: nothing is ever acked
    with Capture(store, run, "run1") as capture:
        capture.drain_once()

    pending = store.read_pending(STREAM_EVENTS, CAPTURE_GROUP, "capture-1", 500)
    assert len(pending) == 2


def test_a_trim_that_ate_unread_entries_is_recorded(tmp_path):
    """
    Prevention can always be exceeded -- a long enough run outruns any cap --
    so the loss is detected and recorded instead of being read as a quiet
    minute.
    """
    store = MemoryStore()
    for i in range(10):
        store.append(STREAM_EVENTS, {"event": json.dumps({"requestId": f"r{i}"})})

    run = RawRun.at(tmp_path / "run1")
    with Capture(store, run, "run1") as capture:
        # Read three, then let the stream lose the next two before the second
        # pass reaches them.
        store.read_group(STREAM_EVENTS, CAPTURE_GROUP, "capture-1", 3)
        store.ack(STREAM_EVENTS, CAPTURE_GROUP, *[f"{i}-0" for i in (1, 2, 3)])
        store.trim(STREAM_EVENTS, 5)

        capture.drain_once()
        capture.write_manifest()

    manifest = json.loads(run.manifest.read_text())
    events = manifest["capture"]["streams"][STREAM_EVENTS]
    assert events["entries_lost"] is True
    loss = events["trim_losses"][0]
    assert loss["last_delivered_id"] == "3-0"
    assert loss["first_surviving_id"] == "6-0"


def test_an_untrimmed_stream_reports_no_loss(tmp_path):
    """Without this the trim check could report a loss on every run and the
    flag would mean nothing."""
    store = seeded_store()
    run = RawRun.at(tmp_path / "run1")
    with Capture(store, run, "run1") as capture:
        capture.drain_once()
        capture.drain_once()
        capture.write_manifest()

    manifest = json.loads(run.manifest.read_text())
    for stream in (STREAM_EVENTS, STREAM_ARRIVALS, STREAM_HEALTH):
        assert manifest["capture"]["streams"][stream]["entries_lost"] is False


def test_the_same_gap_is_not_counted_twice(tmp_path):
    """A gap that persists across polls is one loss seen repeatedly."""
    store = MemoryStore()
    for i in range(10):
        store.append(STREAM_EVENTS, {"event": "{}"})
    run = RawRun.at(tmp_path / "run1")
    with Capture(store, run, "run1") as capture:
        store.read_group(STREAM_EVENTS, CAPTURE_GROUP, "capture-1", 3)
        store.trim(STREAM_EVENTS, 5)
        capture.drain_once()
        capture.drain_once()
        capture.drain_once()

    assert len(capture.stats[STREAM_EVENTS].trim_losses) == 1


def test_redis_ids_compare_numerically_not_as_text():
    """'10-0' sorts before '9-0' as text, and a trim check fooled by that
    would report losses that did not happen and miss ones that did."""
    assert _entry_id_sort_key("10-0") > _entry_id_sort_key("9-0")
    assert _entry_id_sort_key("1700000000000-1") > _entry_id_sort_key("1700000000000-0")


def test_an_entry_in_an_unknown_shape_is_recorded_not_skipped(tmp_path):
    """Leaving it pending would stall the group behind one malformed record
    forever; dropping it would lose a request with no trace."""
    store = MemoryStore()
    store.append(STREAM_EVENTS, {"something_else": "surprise"})
    run = RawRun.at(tmp_path / "run1")
    with Capture(store, run, "run1") as capture:
        assert capture.drain_once() == 1

    written = lines(run.completions)
    assert written[0]["_unparsed"] == {"something_else": "surprise"}


def test_the_manifest_survives_an_interrupted_run(tmp_path):
    run = RawRun.at(tmp_path / "run1")
    run.manifest.write_text(json.dumps({"scenario": "credential-stuffing"}))

    store = seeded_store(events=1, arrivals=0, health=0)
    with Capture(store, run, "run1") as capture:
        capture.drain_once()
        capture.write_manifest()

    manifest = json.loads(run.manifest.read_text())
    # The generator's section is preserved: labels come from it, and capture
    # overwriting it would destroy the only record of what the run drove.
    assert manifest["scenario"] == "credential-stuffing"
    assert manifest["run_id"] == "run1"
