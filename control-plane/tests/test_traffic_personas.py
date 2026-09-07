"""
The traffic harness.

The interesting tests run a persona's plan through the real extractor and
assert the feature that persona exists to teach. A persona that no longer
produces benign login failures is a persona that has stopped doing its job, and
nothing else in the pipeline would say so -- the dataset would simply become
separable on that column and the model would learn a rule instead of a
behaviour.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from iasg.anomaly.extract import extract
from iasg.anomaly.records import RequestRecord
from iasg.anomaly.windows import assign
from testing.traffic import attacks as attack_lib
from testing.traffic import personas as persona_lib
from testing.traffic.generate import coverage, plan_run, write_labels
from testing.traffic.identity import (
    IdentityNotTrusted,
    observed_addresses,
    peer_network,
    preflight,
    require_trusted_identity,
)
from testing.traffic.plan import Plan, Request
from testing.traffic.pools import ATTACKERS, BENIGN, RESERVED, Pool, PoolExhausted, session_id

W = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)


def records_from(plan: Plan, ip: str = "203.0.113.10", status_for=None):
    """
    Turn a plan into the telemetry it would produce.

    The backend is simulated only where a persona's point depends on it -- a
    404 for a dead link, a 401 for a wrong password. Everything else is a 200,
    because the persona is not making a claim about it.
    """
    records = []
    for i, step in enumerate(plan.steps):
        at = W + timedelta(seconds=step.offset)
        status, auth = 200, None
        if status_for is not None:
            status, auth = status_for(step.request)
        records.append(RequestRecord(
            request_id=f"{ip}-{i}", arrival_ts=at, ip=ip,
            method=step.request.method, path=step.request.path,
            route_template=step.request.route_template,
            completed_ts=at + timedelta(milliseconds=20),
            response_origin="backend", upstream_outcome="completed",
            upstream_status=status, upstream_duration_ms=10,
            request_body_bytes=len(str(step.request.body or "")),
            auth_outcome=auth,
        ))
    return records


def first_window(records):
    grouped = assign(records)
    key = min(grouped)
    return extract(grouped[key], key[1], key[1] + timedelta(seconds=60))


# ---------------------------------------------------------------------------
# Each persona teaches what it claims to
# ---------------------------------------------------------------------------


def test_forgetful_user_produces_benign_login_failures():
    """
    The single most important benign persona. Without it,
    login_failure_ratio separates perfectly in training and the model learns
    that one wrong password is an attack -- so the first real person who
    mistypes theirs gets throttled.
    """
    def statuses(request):
        if request.path == "/api/login":
            wrong = request.body["password"] != "correct-horse"
            return (401, "invalid_credentials") if wrong else (200, "success")
        return 200, None

    plan = persona_lib.forgetful_user(random.Random(3))
    row = first_window(records_from(plan, status_for=statuses))

    assert row.features["login_failure_ratio"] > 0
    assert row.features["login_failure_ratio"] < 1.0
    assert row.quality.login_attempts >= 3


def test_dead_link_visitor_produces_benign_404s():
    """Otherwise every 404 reads as enumeration, and a site that deleted some
    products flags its own users."""
    def statuses(request):
        missing = request.path.startswith("/api/products/9")
        return (404 if missing else 200), None

    plan = persona_lib.dead_link_visitor(random.Random(5))
    records = records_from(plan, status_for=statuses)
    rows = [extract(v, k[1], k[1] + timedelta(seconds=60)) for k, v in assign(records).items()]

    # Across the session, not within one arbitrary minute: a visitor who
    # happened to hit only live links for sixty seconds is still this persona,
    # and pinning the assertion to the first window makes it depend on the seed.
    ratios = [r.features["backend_404_ratio"] for r in rows]
    assert any(ratio and 0.0 < ratio < 1.0 for ratio in ratios)


def test_mobile_poller_has_a_low_cv_and_is_benign():
    """
    Exactly what a naive "regular timing means bot" rule flags. Real polling
    looks like this, and the dataset has to contain it.
    """
    plan = persona_lib.mobile_poller(random.Random(11))
    row = first_window(records_from(plan))
    assert row.features["interarrival_cv"] < 0.1


def test_search_heavy_keeps_query_strings_out_of_path_diversity():
    """If query strings ever leaked into the path, this session would look like
    a scanner walking a new endpoint every few seconds."""
    plan = persona_lib.search_heavy(random.Random(13))
    row = first_window(records_from(plan))
    assert row.features["unique_path_ratio"] < 1.0
    assert row.features["dominant_route_ratio"] == 1.0


def test_impatient_spikes_without_being_an_attack():
    plan = persona_lib.impatient(random.Random(2))
    row = first_window(records_from(plan))
    assert row.features["peak_1s_requests"] >= 3


def test_one_shot_produces_an_abstaining_row():
    plan = persona_lib.one_shot(random.Random(1))
    row = first_window(records_from(plan))
    assert row.quality.insufficient_history is True
    assert row.features["interarrival_cv"] is None


def test_idle_leaves_a_window_with_no_row_at_all():
    """A window with no requests is absence, not a zero row."""
    plan = persona_lib.idle(random.Random(1), seconds=180.0)
    grouped = assign(records_from(plan))
    starts = sorted(start for _, start in grouped)
    assert len(starts) == 2
    # There is a gap: the two windows are not adjacent minutes.
    assert starts[1] - starts[0] > timedelta(seconds=60)


def test_shopper_logs_in_without_failing():
    def statuses(request):
        return (200, "success") if request.path == "/api/login" else (200, None)

    plan = persona_lib.shopper(random.Random(7))
    records = records_from(plan, status_for=statuses)
    rows = [extract(v, k[1], k[1] + timedelta(seconds=60)) for k, v in assign(records).items()]
    with_login = [r for r in rows if r.quality.login_attempts > 0]
    assert with_login
    assert all(r.features["login_failure_ratio"] == 0.0 for r in with_login)


def test_every_persona_is_documented_and_reachable():
    assert set(persona_lib.PERSONAS) == set(persona_lib.TEACHES)
    for name, build in persona_lib.PERSONAS.items():
        assert len(build(random.Random(1))) >= 1, name


# ---------------------------------------------------------------------------
# Attacks, and the reserved ones in particular
# ---------------------------------------------------------------------------


def test_slow_brute_force_stays_under_the_detector_threshold():
    """
    One attempt every eight seconds. If this ever became fast enough for
    internal/signals/brute_force.go to fire, it would stop being a test of
    whether this layer catches what the detectors miss.
    """
    plan = attack_lib.slow_brute_force(random.Random(1), seconds=600.0)
    offsets = [s.offset for s in plan.steps]
    gaps = [b - a for a, b in zip(offsets, offsets[1:])]
    assert min(gaps) > 7.0
    # At most eight attempts a minute, well under any per-minute threshold.
    assert max(sum(1 for o in offsets if m * 60 <= o < (m + 1) * 60)
               for m in range(10)) <= 8


def test_slow_brute_force_is_still_visible_in_the_window_shape():
    """The claim this scenario exists to test: nothing about one request is
    unusual, but the window is."""
    def statuses(request):
        return (401, "invalid_credentials") if request.path == "/api/login" else (200, None)

    plan = attack_lib.slow_brute_force(random.Random(1), seconds=600.0)
    row = first_window(records_from(plan, status_for=statuses))
    assert row.features["login_ratio"] == 1.0
    assert row.features["login_failure_ratio"] == 1.0
    assert row.features["interarrival_cv"] < 0.1


def test_low_and_slow_enumeration_shows_up_as_path_diversity():
    plan = attack_lib.low_and_slow_enumeration(random.Random(1), seconds=600.0)
    row = first_window(records_from(plan))
    assert row.features["unique_path_ratio"] > 0.5
    assert row.features["dominant_route_ratio"] < 0.6


def test_reserved_scenarios_agree_with_the_splitter():
    from iasg.dataset.splits import RESERVED_SCENARIOS

    assert set(attack_lib.RESERVED) == set(RESERVED_SCENARIOS)
    assert not set(attack_lib.TUNABLE) & set(attack_lib.RESERVED)


# ---------------------------------------------------------------------------
# Address pools
# ---------------------------------------------------------------------------


def test_an_address_is_never_reused_inside_a_run():
    """Reuse would silently merge two sessions into one group key, and no later
    check could tell."""
    pool = Pool(("203.0.113.10", "203.0.113.11"))
    assert pool.take() != pool.take()
    with pytest.raises(PoolExhausted):
        pool.take()


def test_the_pools_do_not_overlap():
    assert not set(BENIGN) & set(ATTACKERS)
    assert not set(RESERVED) & set(ATTACKERS)
    assert not set(RESERVED) & set(BENIGN)


def test_every_address_is_in_the_documentation_range():
    """policy/writer.py refuses to police anything else, so an attack from
    outside this range correctly produces no policy and looks broken."""
    for address in BENIGN + ATTACKERS + RESERVED:
        assert address.startswith("203.0.113.")


def test_reserved_scenarios_get_addresses_from_the_reserved_pool():
    """A held-out scenario sharing an address with a tunable one would put the
    same group key on both sides of the split."""
    assignments = plan_run(seed=1)
    reserved_ips = {a.ip for a in assignments if a.name in attack_lib.RESERVED}
    tunable_ips = {a.ip for a in assignments if a.name in attack_lib.TUNABLE}
    assert reserved_ips <= set(RESERVED)
    assert not reserved_ips & tunable_ips


def test_session_id_is_run_and_address():
    assert session_id("run1", "203.0.113.10") == "run1|203.0.113.10"


# ---------------------------------------------------------------------------
# The identity pre-flight
# ---------------------------------------------------------------------------


def test_preflight_passes_when_the_gateway_records_every_address():
    recorded = {}
    result = preflight(
        ["203.0.113.10", "203.0.113.11"],
        send=lambda ip: recorded.setdefault(f"iasg:ip:{ip}:latest", "{}"),
        lookup=recorded.get,
    )
    assert result.ok
    require_trusted_identity(result)


def test_preflight_refuses_when_every_persona_collapsed_into_one_address():
    """
    The failure this exists for. Docker Desktop sometimes allocates a subnet
    config.yaml does not trust, X-Forwarded-For is ignored, and forty personas
    become one client -- with no error anywhere and no way to detect it
    afterwards.
    """
    recorded = {}
    result = preflight(
        ["203.0.113.10", "203.0.113.11"],
        # The gateway records the peer address instead of the header.
        send=lambda ip: recorded.setdefault("iasg:ip:192.168.65.1:latest", "{}"),
        lookup=recorded.get,
        observed=lambda: observed_addresses(lambda _: list(recorded)),
    )
    assert not result.ok
    assert result.observed_instead == ["192.168.65.1"]

    with pytest.raises(IdentityNotTrusted) as excinfo:
        require_trusted_identity(result)
    message = str(excinfo.value)
    assert "192.168.65.1" in message
    assert "trusted_proxies" in message


def test_preflight_says_so_when_nothing_was_recorded_at_all():
    result = preflight(["203.0.113.10"], send=lambda ip: None, lookup=lambda k: None)
    with pytest.raises(IdentityNotTrusted, match="Redis"):
        require_trusted_identity(result)


def test_peer_network_names_the_subnet_to_add():
    assert peer_network("192.168.65.1") == "192.168.65.0/24"


# ---------------------------------------------------------------------------
# Labels are written from the plan, before traffic
# ---------------------------------------------------------------------------


def test_labels_are_written_from_the_plan_not_from_what_happened(tmp_path):
    """
    attacks.jsonl exists before a single request is sent. Written afterwards it
    would be a second opinion about the traffic rather than a record of what
    was launched, and that is exactly the door detector output gets in by.
    """
    assignments = plan_run(seed=1, benign_per_persona=1, seconds=60.0)
    write_labels(tmp_path, "run1", assignments, W)

    import json

    attacks = [json.loads(l) for l in (tmp_path / "attacks.jsonl").read_text().splitlines()]
    sessions = [json.loads(l) for l in (tmp_path / "sessions.jsonl").read_text().splitlines()]

    assert {a["scenario"] for a in attacks} == set(attack_lib.SCENARIOS)
    assert all(a["ip"].startswith("203.0.113.") for a in attacks)
    # Benign sessions are recorded but are not attacks.
    benign = [s for s in sessions if s["kind"] == "benign"]
    assert benign
    assert not {s["ip"] for s in benign} & {a["ip"] for a in attacks}


def test_coverage_names_the_feature_a_missing_persona_costs():
    """A run without forgetful_user has no benign login failures, and the
    warning has to say that rather than just counting sessions."""
    full = plan_run(seed=1, benign_per_persona=1)
    assert coverage(full) == []

    without = [a for a in full if a.name != "forgetful_user"]
    gaps = coverage(without)
    assert len(gaps) == 1
    assert "login_failure_ratio" in gaps[0]
