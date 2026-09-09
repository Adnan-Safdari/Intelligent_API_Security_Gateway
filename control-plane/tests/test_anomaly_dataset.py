"""
Windowing, the two-stream join, imputation, and the checks a dataset must pass
before it is frozen.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from iasg.anomaly.checks import (
    check_feature_header,
    check_labels_independent_of_detectors,
    check_no_identifying_columns,
    check_reserved_scenarios_held_out,
    check_split_disjoint,
)
from iasg.anomaly.extract import WindowRow, extract
from iasg.anomaly.impute import Medians, UnmeasuredFeature
from iasg.anomaly.quality import WindowQuality
from iasg.anomaly.records import RequestRecord, join, parse_ts
from iasg.anomaly.spec import FEATURE_NAMES, UNMATCHED_ROUTE
from iasg.anomaly.vector import abstains, to_vector
from iasg.anomaly.windows import assign, in_window, window_end, window_start

WINDOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Windowing
# ---------------------------------------------------------------------------


def test_a_slow_request_stays_in_the_window_it_arrived_in():
    """The straddling case, at the level of window assignment rather than
    feature values."""
    record = RequestRecord(
        request_id="c",
        arrival_ts=WINDOW + timedelta(seconds=59),
        ip="203.0.113.10",
        method="GET",
        path="/api/products",
        completed_ts=WINDOW + timedelta(seconds=62),
    )
    assert window_start(record.arrival_ts) == WINDOW
    assert window_start(record.completed_ts) == WINDOW + timedelta(seconds=60)
    assert in_window(record, WINDOW)


def test_windows_are_half_open_so_a_request_lands_in_exactly_one():
    boundary = RequestRecord(
        request_id="edge",
        arrival_ts=window_end(WINDOW),
        ip="203.0.113.10",
        method="GET",
        path="/",
    )
    assert not in_window(boundary, WINDOW)
    assert in_window(boundary, window_end(WINDOW))


def test_windows_align_to_the_clock_not_to_the_first_request():
    """Two processes reading the same traffic must agree on the boundaries
    without coordinating."""
    ragged = datetime(2026, 9, 7, 12, 0, 37, 481_000, tzinfo=timezone.utc)
    assert window_start(ragged) == WINDOW


def test_assign_groups_by_address_and_window_and_creates_nothing_else():
    records = [
        RequestRecord("a", WINDOW, "203.0.113.10", "GET", "/"),
        RequestRecord("b", WINDOW + timedelta(seconds=30), "203.0.113.10", "GET", "/"),
        RequestRecord("c", WINDOW + timedelta(seconds=90), "203.0.113.10", "GET", "/"),
        RequestRecord("d", WINDOW, "203.0.113.11", "GET", "/"),
    ]
    grouped = assign(records)
    assert set(grouped) == {
        ("203.0.113.10", WINDOW),
        ("203.0.113.10", WINDOW + timedelta(seconds=60)),
        ("203.0.113.11", WINDOW),
    }
    assert len(grouped[("203.0.113.10", WINDOW)]) == 2
    # No key exists for an address's quiet minute. Absence, not a zero row.
    assert ("203.0.113.11", WINDOW + timedelta(seconds=60)) not in grouped


# ---------------------------------------------------------------------------
# Parsing and the two-stream join
# ---------------------------------------------------------------------------


def test_go_nanosecond_timestamps_parse_and_never_round_forward():
    """Truncating rather than rounding keeps a timestamp from crossing a window
    boundary on its way through the parser."""
    parsed = parse_ts("2026-09-07T12:00:59.999999999Z")
    assert parsed == datetime(2026, 9, 7, 12, 0, 59, 999_999, tzinfo=timezone.utc)
    assert window_start(parsed) == WINDOW


def test_an_unparseable_timestamp_is_none_rather_than_an_exception():
    assert parse_ts("not a time") is None
    assert parse_ts("") is None
    assert parse_ts(None) is None


def test_join_keeps_an_arrival_with_no_completion():
    """The in-flight case the arrival stream exists for. Dropping it would
    erase the request from its window entirely."""
    records = join(
        [{"requestId": "a", "arrivalTs": "2026-09-07T12:00:00Z", "ip": "203.0.113.10",
          "method": "GET", "path": "/api/products", "routeTemplate": "/api/products"}],
        [],
    )
    assert len(records) == 1
    assert records[0].completed_ts is None


def test_join_recovers_a_completion_whose_arrival_was_dropped():
    """The arrival queue overflows exactly during the traffic worth measuring,
    so a lost arrival must degrade the record rather than delete the request."""
    records = join(
        [],
        [{"requestId": "a", "arrivalTs": "2026-09-07T12:00:00Z", "ts": "2026-09-07T12:00:00.05Z",
          "ip": "203.0.113.10", "method": "GET", "path": "/api/products",
          "responseOrigin": "backend", "upstreamStatus": 200, "upstreamDurationMs": 12}],
    )
    assert len(records) == 1
    assert records[0].arrival_ts == WINDOW
    assert records[0].upstream_status == 200


def test_the_arrival_record_wins_on_arrival_side_fields():
    """It was written before anything in the chain could alter them."""
    records = join(
        [{"requestId": "a", "arrivalTs": "2026-09-07T12:00:00Z", "ip": "203.0.113.10",
          "method": "GET", "path": "/api/../../etc/passwd", "routeTemplate": UNMATCHED_ROUTE}],
        [{"requestId": "a", "arrivalTs": "2026-09-07T12:00:30Z", "ts": "2026-09-07T12:00:00.05Z",
          "ip": "10.0.0.1", "method": "POST", "path": "/etc/passwd",
          "responseOrigin": "backend", "upstreamStatus": 404}],
    )
    record = records[0]
    assert record.arrival_ts == WINDOW
    assert record.path == "/api/../../etc/passwd"
    assert record.method == "GET"
    assert record.ip == "203.0.113.10"
    assert record.upstream_status == 404


def test_a_record_with_no_request_id_is_dropped_rather_than_guessed():
    assert join([{"arrivalTs": "2026-09-07T12:00:00Z"}], []) == []


# ---------------------------------------------------------------------------
# Imputation
# ---------------------------------------------------------------------------


def rows_for_medians(values):
    out = []
    for value in values:
        features = {name: 1.0 for name in FEATURE_NAMES}
        features["interarrival_cv"] = value
        out.append(
            WindowRow(
                ip="203.0.113.10", window_start=WINDOW,
                features=features, quality=WindowQuality(),
            )
        )
    return out


def test_medians_come_from_the_training_rows_and_ignore_unknowns():
    rows = rows_for_medians([1.0, None, 3.0, None, 5.0])
    medians = Medians.fit(rows)
    assert medians.values["interarrival_cv"] == 3.0


def test_a_feature_nothing_measured_fails_rather_than_becoming_a_constant():
    """
    Median replacement cannot repair a broken telemetry pipeline. Left alone it
    produces a full column of the same number and hides the fact that nothing
    was ever measured.
    """
    rows = rows_for_medians([None, None, None])
    with pytest.raises(UnmeasuredFeature) as excinfo:
        Medians.fit(rows)
    assert "interarrival_cv" in str(excinfo.value)


def test_medians_round_trip_byte_identically(tmp_path):
    """Runtime reuses the saved numbers rather than recomputing anything, so a
    saved file that did not reload exactly would be a silent train/serve skew."""
    medians = Medians.fit(rows_for_medians([1.0, 2.0, 6.0]))
    path = tmp_path / "medians.json"
    medians.save(path)
    assert Medians.load(path).values == medians.values


def test_medians_from_another_spec_version_are_refused(tmp_path):
    """A vector is positional. Medians fitted under another version would be
    applied to columns that may mean something else."""
    path = tmp_path / "medians.json"
    path.write_text(json.dumps({"spec_version": "v0", "medians": {n: 0.0 for n in FEATURE_NAMES}}))
    with pytest.raises(ValueError, match="v0"):
        Medians.load(path)


def test_to_vector_fills_unknowns_and_keeps_feature_order():
    medians = Medians.fit(rows_for_medians([2.0, 4.0]))
    row = rows_for_medians([None])[0]
    vector = to_vector(row, medians)
    assert len(vector) == len(FEATURE_NAMES)
    assert vector[FEATURE_NAMES.index("interarrival_cv")] == 3.0
    assert all(isinstance(v, float) for v in vector)


def test_a_two_request_window_abstains_rather_than_being_scored():
    records = [
        RequestRecord(f"r{i}", WINDOW + timedelta(seconds=i), "203.0.113.10", "GET", "/")
        for i in range(2)
    ]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert abstains(row) is True


# ---------------------------------------------------------------------------
# Dataset checks
# ---------------------------------------------------------------------------


def write_csv(path, header, rows=()):
    lines = [",".join(header)]
    lines += [",".join(str(c) for c in row) for row in rows]
    path.write_text("\n".join(lines) + "\n")


def test_feature_header_must_be_exactly_row_id_plus_the_twelve(tmp_path):
    good = tmp_path / "features.csv"
    write_csv(good, ["row_id", *FEATURE_NAMES])
    assert check_feature_header(good) == []


def test_an_address_column_in_the_feature_matrix_fails_the_build(tmp_path):
    """The leakage guarantee made physical: a model that learns addresses
    learns this laboratory's address pool rather than behaviour."""
    bad = tmp_path / "features.csv"
    write_csv(bad, ["row_id", *FEATURE_NAMES, "ip"])
    assert check_feature_header(bad)
    assert check_no_identifying_columns(bad)


def test_reordered_features_fail_because_a_vector_is_positional(tmp_path):
    shuffled = [FEATURE_NAMES[1], FEATURE_NAMES[0], *FEATURE_NAMES[2:]]
    path = tmp_path / "features.csv"
    write_csv(path, ["row_id", *shuffled])
    failures = check_feature_header(path)
    assert failures
    assert "order matters" in str(failures[0])


def test_one_address_cannot_appear_in_two_partitions():
    rows = [
        {"run_id": "r1", "ip": "203.0.113.10", "split": "train"},
        {"run_id": "r1", "ip": "203.0.113.10", "split": "test"},
    ]
    assert check_split_disjoint(rows)
    assert check_split_disjoint(rows[:1]) == []


def test_a_reserved_scenario_outside_test_fails():
    """slow_brute_force exists to be unseen. A threshold tuned against it
    measures nothing."""
    reserved = ["slow_brute_force", "low_and_slow_enumeration"]
    assert check_reserved_scenarios_held_out(
        [{"scenario": "slow_brute_force", "split": "val"}], reserved
    )
    assert check_reserved_scenarios_held_out(
        [{"scenario": "slow_brute_force", "split": "test"}], reserved
    ) == []


def test_a_window_that_fired_signals_but_is_not_in_the_manifest_labels_zero():
    """
    Labels come from the run manifest, written before traffic starts. A dataset
    labelled by the detectors can only teach a model to reproduce them,
    mistakes included.
    """
    fired_but_benign = {
        "row_id": 7, "fired": "brute_force,api_flooding",
        "manifest_attacker": "false", "label": "1",
    }
    assert check_labels_independent_of_detectors([fired_but_benign])

    correctly_zero = dict(fired_but_benign, label="0")
    assert check_labels_independent_of_detectors([correctly_zero]) == []
