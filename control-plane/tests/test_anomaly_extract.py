"""
The extractor, and the guarantee that there is only one of it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from iasg.anomaly.extract import WindowRow, build_as_of, extract, extract_all
from iasg.anomaly.quality import WindowHealth
from iasg.anomaly.records import RequestRecord, join, parse_ts
from iasg.anomaly.spec import FEATURE_NAMES, UNMATCHED_ROUTE
from iasg.anomaly.windows import assign, window_start

WINDOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)


def req(
    offset_ms: int,
    *,
    request_id: str | None = None,
    ip: str = "203.0.113.10",
    method: str = "GET",
    path: str = "/api/products",
    route: str = "/api/products",
    completed_ms: int | None = None,
    origin: str | None = "backend",
    status: int | None = 200,
    duration: int | None = 5,
    body: int | None = 0,
    auth: str | None = None,
    outcome: str | None = "completed",
) -> RequestRecord:
    arrival = WINDOW + timedelta(milliseconds=offset_ms)
    completed = None if completed_ms is None else WINDOW + timedelta(milliseconds=completed_ms)
    return RequestRecord(
        request_id=request_id or f"r{offset_ms}",
        arrival_ts=arrival,
        ip=ip,
        method=method,
        path=path,
        route_template=route,
        completed_ts=completed,
        response_origin=origin if completed else None,
        upstream_outcome=outcome if completed else None,
        upstream_status=status if completed else None,
        upstream_duration_ms=duration if completed else None,
        request_body_bytes=body if completed else None,
        auth_outcome=auth if completed else None,
    )


# ---------------------------------------------------------------------------
# The test the whole design rests on.
# ---------------------------------------------------------------------------


def test_build_and_runtime_agree_field_for_field():
    """
    One fixture, extracted twice: once as the runtime scoring at the window's
    end, once as the build producing a training row for the same instant. The
    rows must be identical.

    The straddling request -- arrived at 12:00:59, completes at 12:01:02 -- is
    the whole point. Its arrival counts; its response does not exist yet. A
    build that filled it in would train a model expecting information the
    runtime never has, and the failure would be silent.
    """
    records = [
        # Two the backend has not answered yet, and one that arrived at
        # 12:00:59 and completes at 12:01:02 -- after the window closed.
        req(0, request_id="a"),
        req(1_000, request_id="b"),
        req(59_000, request_id="c", completed_ms=62_000, status=404),
    ]

    as_of = build_as_of(WINDOW)
    assert as_of == WINDOW + timedelta(seconds=60)

    runtime_row = extract(records, WINDOW, as_of=WINDOW + timedelta(seconds=60))
    build_row = extract(records, WINDOW, as_of=build_as_of(WINDOW))

    assert runtime_row.features == build_row.features
    assert runtime_row.quality == build_row.quality

    assert build_row.features["request_count"] == 3
    # 404 arrived two seconds after the window closed, so no backend status is
    # available and the ratio is unknown rather than zero.
    assert build_row.features["backend_404_ratio"] is None
    assert build_row.quality.known_status_count == 0
    assert build_row.quality.pending_at_scoring == 3


def test_a_later_as_of_does_see_the_late_response():
    """
    The counterpart. If as_of made no difference the test above would pass for
    the wrong reason -- it would prove the extractor ignores completions, not
    that it respects availability.
    """
    records = [
        req(0, request_id="a", completed_ms=10),
        req(59_000, request_id="c", completed_ms=62_000, status=404),
    ]
    at_close = extract(records, WINDOW, as_of=WINDOW + timedelta(seconds=60))
    later = extract(records, WINDOW, as_of=WINDOW + timedelta(seconds=90))

    assert at_close.features["backend_404_ratio"] == 0.0
    assert later.features["backend_404_ratio"] == 0.5
    assert at_close.quality.pending_at_scoring == 1
    assert later.quality.pending_at_scoring == 0


# ---------------------------------------------------------------------------
# Zero versus unknown, which the specification says must never be conflated.
# ---------------------------------------------------------------------------


def test_no_logins_is_zero_but_unanswered_logins_are_unknown():
    none_attempted = extract([req(0, completed_ms=10)], WINDOW, WINDOW + timedelta(seconds=60))
    assert none_attempted.features["login_ratio"] == 0.0
    assert none_attempted.features["login_failure_ratio"] == 0.0

    login = req(0, method="POST", path="/api/login", route="/api/login", completed_ms=10, auth="unknown")
    unanswered = extract([login], WINDOW, WINDOW + timedelta(seconds=60))
    assert unanswered.features["login_ratio"] == 1.0
    assert unanswered.features["login_failure_ratio"] is None
    assert unanswered.quality.login_attempts == 1
    assert unanswered.quality.login_attempts_known_outcome == 0


def test_a_refused_login_cannot_improve_an_attackers_failure_ratio():
    """
    Three failed logins and one the gateway refused. The refusal never reached
    the backend, so its outcome is unknown and it stays out of the denominator.
    Counting it as a non-failure would mean blocking an attacker made their
    numbers look better.
    """
    failed = [
        req(i * 1000, request_id=f"f{i}", method="POST", path="/api/login",
            route="/api/login", completed_ms=i * 1000 + 10, status=401,
            auth="invalid_credentials")
        for i in range(3)
    ]
    refused = req(
        4000, request_id="blocked", method="POST", path="/api/login", route="/api/login",
        completed_ms=4010, origin="gateway", status=None, duration=None,
        auth="unknown", outcome=None,
    )
    row = extract(failed + [refused], WINDOW, WINDOW + timedelta(seconds=60))

    assert row.features["login_failure_ratio"] == 1.0
    assert row.quality.login_attempts == 4
    assert row.quality.login_attempts_known_outcome == 3


def test_gateway_statuses_stay_out_of_backend_ratios():
    """
    A 429 the rate limiter wrote and a 502 from an unreachable backend are the
    gateway talking about itself. Mixing them in would mean enforcement changed
    the features of the address it enforced against.
    """
    records = [
        req(0, request_id="ok", completed_ms=10, status=200),
        req(1000, request_id="limited", completed_ms=1010, origin="gateway", status=None, duration=None),
        req(2000, request_id="badgw", completed_ms=2010, origin="gateway", status=None, duration=None),
    ]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.quality.known_status_count == 1
    assert row.features["backend_5xx_ratio"] == 0.0
    assert row.features["backend_404_ratio"] == 0.0


def test_confirmed_empty_body_counts_but_an_unmeasured_one_does_not():
    records = [
        req(0, request_id="empty", completed_ms=10, body=0),
        req(1000, request_id="sized", completed_ms=1010, body=100),
        req(2000, request_id="refused", completed_ms=2010, body=None),
    ]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.features["mean_request_body_bytes"] == 50.0
    assert row.quality.complete_body_measurements == 2


def test_a_timeout_has_no_duration_and_one_is_never_invented():
    records = [
        req(0, request_id="fast", completed_ms=10, duration=20),
        req(1000, request_id="slow", completed_ms=5000, origin="gateway", status=None,
            duration=None, outcome="timeout"),
    ]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.features["p95_upstream_duration_ms"] == 20.0
    assert row.quality.complete_duration_measurements == 1
    assert row.quality.timeouts == 1


# ---------------------------------------------------------------------------
# Individual features.
# ---------------------------------------------------------------------------


def test_peak_1s_separates_a_burst_from_the_same_count_spread_out():
    burst = [req(i * 10, request_id=f"b{i}") for i in range(20)]
    spread = [req(i * 3000, request_id=f"s{i}") for i in range(20)]

    burst_row = extract(burst, WINDOW, WINDOW + timedelta(seconds=60))
    spread_row = extract(spread, WINDOW, WINDOW + timedelta(seconds=60))

    assert burst_row.features["request_count"] == spread_row.features["request_count"]
    assert burst_row.features["peak_1s_requests"] == 20
    assert spread_row.features["peak_1s_requests"] == 1


@pytest.mark.parametrize("count", [1, 2])
def test_interarrival_cv_is_unknown_below_three_requests(count):
    records = [req(i * 1000, request_id=f"r{i}") for i in range(count)]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.features["interarrival_cv"] is None
    assert row.quality.insufficient_history is True


def test_interarrival_cv_is_zero_for_a_perfect_metronome():
    """A mobile poller on a fixed interval. Low variation is benign, and the
    dataset has to contain that case or the model learns otherwise."""
    records = [req(i * 5000, request_id=f"r{i}") for i in range(6)]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.features["interarrival_cv"] == 0.0
    assert row.quality.insufficient_history is False


def test_interarrival_cv_is_unknown_when_every_arrival_shares_an_instant():
    records = [req(0, request_id=f"r{i}") for i in range(4)]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.features["interarrival_cv"] is None


def test_unmatched_is_a_bucket_not_a_null():
    """A scanner walking paths no template matches shares one <unmatched>
    bucket per method, and that concentration is informative."""
    records = [
        req(i * 100, request_id=f"s{i}", path=f"/admin/{i}", route=UNMATCHED_ROUTE)
        for i in range(10)
    ]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.features["dominant_route_ratio"] == 1.0
    assert row.features["unique_path_ratio"] == 1.0


def test_traversal_segments_survive_into_path_diversity():
    """Collapsing ../ before measuring would erase exactly the behaviour the
    traversal detector exists to catch."""
    records = [
        req(0, request_id="a", path="/api/../../etc/passwd", route=UNMATCHED_ROUTE),
        req(100, request_id="b", path="/api/../../etc/shadow", route=UNMATCHED_ROUTE),
    ]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.features["unique_path_ratio"] == 1.0


def test_route_templates_stop_ordinary_browsing_looking_like_a_scan():
    browsing = [
        req(i * 500, request_id=f"p{i}", path=f"/api/products/{i}", route="/api/products/{id}")
        for i in range(20)
    ]
    row = extract(browsing, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.features["unique_path_ratio"] == 1.0
    assert row.features["dominant_route_ratio"] == 1.0


@pytest.mark.parametrize(
    "count,expected_index",
    [(1, 1), (20, 19), (21, 20)],
)
def test_p95_uses_the_one_based_ceiling_index(count, expected_index):
    records = [
        req(i * 100, request_id=f"r{i}", completed_ms=i * 100 + 10, duration=i + 1)
        for i in range(count)
    ]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.features["p95_upstream_duration_ms"] == float(expected_index)


def test_an_empty_path_is_counted_as_a_defect_not_repaired():
    records = [req(0, request_id="a", path=""), req(100, request_id="b")]
    row = extract(records, WINDOW, WINDOW + timedelta(seconds=60))
    assert row.quality.telemetry_defects == 1


def test_health_is_a_property_of_the_minute_not_the_address():
    row = extract(
        [req(0, completed_ms=10)],
        WINDOW,
        WINDOW + timedelta(seconds=60),
        health=WindowHealth(dropped=17, fully_observed=False),
    )
    assert row.quality.telemetry_dropped_in_window == 17
    assert row.quality.interval_fully_observed is False


def test_every_feature_is_present_on_every_row():
    """A missing key is a KeyError at vectorisation time, far from the cause."""
    row = extract([req(0, completed_ms=10)], WINDOW, WINDOW + timedelta(seconds=60))
    assert set(row.features) == set(FEATURE_NAMES)
    assert len(row.feature_tuple()) == 12


def test_an_empty_window_is_not_a_row():
    with pytest.raises(ValueError):
        extract([], WINDOW, WINDOW + timedelta(seconds=60))
