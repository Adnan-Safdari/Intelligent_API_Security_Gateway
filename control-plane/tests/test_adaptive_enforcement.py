"""Properties of the adaptive decision and analyst-control path."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

from iasg.adaptive.baseline import BaselineLearner, EndpointKey, MemoryBaselineRepository
from iasg.adaptive.config import AdaptiveConfig
from iasg.adaptive.controller import AdaptiveController
from iasg.adaptive.lifecycle import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_RECOMMENDED,
    Lifecycle,
    MemoryLifecycleRepository,
)
from iasg.adaptive.risk import AnomalyObservation, calculate_risk
from iasg.adaptive.windows import WindowConsumer
from iasg.anomaly.spec import FEATURE_NAMES
from iasg.config import Settings
from iasg.ml.scorer import ModelScorer
from iasg.models import ACTION_MONITOR, ACTION_TEMP_BLOCK, ACTION_THROTTLE, Campaign, Evidence, PolicyDecision
from iasg.policy.writer import PolicyWriter
from iasg.store.memory import MemoryStore


NOW = datetime(2026, 9, 8, tzinfo=timezone.utc)


def config(**changes) -> AdaptiveConfig:
    return dataclasses.replace(AdaptiveConfig(), **changes).validate()


def campaign(confidence=0.95) -> Campaign:
    return Campaign(
        campaign_id="c1", type="Credential Stuffing", confidence=confidence,
        ips=["203.0.113.5"], reason="repeated login failures", severity="high",
        event_count=12,
    )


def evidence(count=3):
    return [
        Evidence(
            timestamp=NOW + timedelta(seconds=index), ip="203.0.113.5",
            endpoint="/api/login", method="POST", detector="bruteforce",
            severity="high",
        )
        for index in range(count)
    ]


def test_login_and_products_learn_different_thresholds():
    cfg = dataclasses.replace(
        AdaptiveConfig().baseline,
        warmup_windows=3,
        cooldown_seconds=0,
        minimum_threshold_rpm=1,
        maximum_threshold_rpm=1000,
    )
    repository = MemoryBaselineRepository()
    learner = BaselineLearner(repository, cfg)
    login = EndpointKey.of("POST", "/api/login")
    products = EndpointKey.of("GET", "/api/products")

    for index in range(3):
        at = NOW + timedelta(minutes=index)
        learner.observe(login, 5, trusted=True, now=at)
        learner.observe(products, 100, trusted=True, now=at)

    login_summary = repository.get_baseline(login)
    product_summary = repository.get_baseline(products)
    assert login_summary.ready and product_summary.ready
    assert login_summary.derived_threshold < product_summary.derived_threshold


def test_attack_and_enforced_windows_never_enter_the_baseline():
    cfg = dataclasses.replace(AdaptiveConfig().baseline, warmup_windows=3)
    repository = MemoryBaselineRepository()
    learner = BaselineLearner(repository, cfg)
    key = EndpointKey.of("POST", "/api/login")

    learner.observe(key, 500, trusted=False, now=NOW)
    summary = repository.get_baseline(key)
    assert summary.sample_count == 0
    assert summary.observed_rate == 500
    assert not summary.ready


def test_baseline_threshold_is_clamped_and_cooldown_prevents_oscillation():
    cfg = dataclasses.replace(
        AdaptiveConfig().baseline,
        warmup_windows=3,
        minimum_threshold_rpm=10,
        maximum_threshold_rpm=50,
        cooldown_seconds=300,
        hysteresis_ratio=0,
    )
    repository = MemoryBaselineRepository()
    learner = BaselineLearner(repository, cfg)
    key = EndpointKey.of("GET", "/api/products")
    for index, value in enumerate((1000, 1000, 1000)):
        learner.observe(key, value, trusted=True, now=NOW + timedelta(minutes=index))
    summary = repository.get_baseline(key)
    assert summary.derived_threshold == 50
    version = summary.version
    learner.observe(key, 1, trusted=True, now=NOW + timedelta(minutes=3))
    assert repository.get_baseline(key).version == version


def test_risk_is_bounded_and_fully_explained():
    result = calculate_risk(
        AdaptiveConfig(), campaign(), evidence(100),
        anomaly=AnomalyObservation(True, 1.0, "iforest-test", "v2"),
    )
    assert 0 <= result.score <= 100
    assert 0 <= result.confidence <= 1
    assert set(result.explanation["components"]) == {
        "deterministic", "behavioural", "campaign", "ml",
    }
    assert result.explanation["ml"]["anomaly_score"] == 1.0
    assert result.explanation["final"]["configuration_version"] == 1


def test_ml_anomaly_alone_can_only_monitor_and_is_not_confidence():
    result = calculate_risk(
        AdaptiveConfig(), None, [],
        anomaly=AnomalyObservation(True, 1.0, "iforest-test", "v2"),
    )
    assert result.action == ACTION_MONITOR
    assert result.confidence == 0
    assert "not policy confidence" in result.explanation["ml"]["note"]


def test_even_an_adversarial_ml_weight_cannot_buy_an_action():
    """
    The 5% default ml_weight is a default, not the invariant. The invariant is
    risk.py:192 -- deterministic_count == 0 returns Monitor unconditionally,
    before weights are ever consulted. Proven here at ml_weight=1.0, the most
    favourable configuration ML could be given.
    """
    config = dataclasses.replace(
        AdaptiveConfig(),
        risk=dataclasses.replace(
            AdaptiveConfig().risk,
            deterministic_weight=0.0, behavioural_weight=0.0,
            campaign_weight=0.0, ml_weight=1.0,
        ),
    ).validate()

    result = calculate_risk(
        config, None, [],
        anomaly=AnomalyObservation(True, 1.0, "iforest-test", "v2"),
    )

    assert result.score == 100.0, "ML alone can still fill the score"
    assert result.action == ACTION_MONITOR, "but score alone never authorises an action"


def test_ml_can_be_the_margin_into_throttle_but_not_into_block():
    """
    _guard's strong-anomaly counterfactual (risk.py:211-219) exists only on
    the ACTION_TEMP_BLOCK branch. Below, deterministic and campaign evidence
    alone total 41 -- one point under the 45-point throttle line -- and the
    model's advisory 5 points are what carry it across. The throttle branch
    (risk.py:221-227) never asks whether ML was load-bearing for that, so ML
    still cannot act alone but it *can* decide a throttle in a way it could
    not have decided a block. This pins that asymmetry rather than letting
    "ML is advisory" imply something the code does not actually enforce.
    """
    row = Evidence(
        timestamp=NOW, ip="203.0.113.5", endpoint="/api/login", method="POST",
        detector="bruteforce", severity="low",
    )
    strong_anomaly = AnomalyObservation(True, 1.0, "iforest-test", "v2")

    with_ml = calculate_risk(AdaptiveConfig(), campaign(0.7), [row], anomaly=strong_anomaly)
    without_ml = calculate_risk(AdaptiveConfig(), campaign(0.7), [row], anomaly=AnomalyObservation())

    assert without_ml.score == 41.0
    assert without_ml.action == ACTION_MONITOR, "below the throttle line without ML"
    assert with_ml.score == 46.0
    assert with_ml.action == ACTION_THROTTLE, "ML supplied the margin, unguarded on this branch"


def test_two_signals_on_one_request_are_not_two_blocking_observations():
    rows = [
        dataclasses.replace(row, stream_id="same-request")
        for row in evidence(2)
    ]
    result = calculate_risk(
        AdaptiveConfig(), campaign(), rows,
        anomaly=AnomalyObservation(True, 1.0, "iforest-test", "v2"),
    )

    assert result.explanation["deterministic_evidence_count"] == 1
    assert result.action != ACTION_TEMP_BLOCK


def test_ml_plus_repeated_evidence_can_throttle_but_strong_campaign_can_block():
    advisory = AnomalyObservation(True, 1.0, "iforest-test", "v2")
    low_campaign = campaign(0.1)
    throttled = calculate_risk(AdaptiveConfig(), low_campaign, evidence(2), anomaly=advisory)
    blocked = calculate_risk(AdaptiveConfig(), campaign(0.95), evidence(3), anomaly=advisory)

    assert throttled.action == ACTION_THROTTLE
    assert blocked.action == ACTION_TEMP_BLOCK


def test_warmup_behaviour_cannot_create_enforcement():
    result = calculate_risk(
        AdaptiveConfig(), None, [], observed_rate=10000,
        anomaly=AnomalyObservation(False),
    )
    assert result.action == ACTION_MONITOR
    assert result.explanation["baseline"]["baseline_ready"] is False


def decision(action=ACTION_THROTTLE) -> PolicyDecision:
    return PolicyDecision(
        ip="203.0.113.5", action=action, campaign_id="c1", confidence=0.9,
        ttl_seconds=300, risk_score=80,
        explanation={"deterministic_evidence_count": 3, "final": {}},
    )


def test_modes_have_materially_different_lifecycles():
    cases = [
        ("monitor", STATUS_RECOMMENDED, False),
        ("manual", STATUS_PENDING, False),
        ("automatic", STATUS_RECOMMENDED, True),
    ]
    for mode, status, enforce in cases:
        repository = MemoryLifecycleRepository()
        row, should_enforce, _ = Lifecycle(repository).stage(
            decision(), dataclasses.replace(AdaptiveConfig(), mode=mode), now=NOW,
        )
        assert (row.status, should_enforce) == (status, enforce)


def test_manual_mode_requires_an_explicit_approval_transition():
    repository = MemoryLifecycleRepository()
    lifecycle = Lifecycle(repository)
    row, enforce, _ = lifecycle.stage(
        decision(), dataclasses.replace(AdaptiveConfig(), mode="manual"), now=NOW,
    )
    assert not enforce and lifecycle.approved() == []
    repository.mark_status(row.decision.policy_id, STATUS_APPROVED, "analyst")
    assert lifecycle.approved() == [row.decision]


def test_active_same_scope_policy_is_never_renewed_by_recurring_evidence():
    repository = MemoryLifecycleRepository()
    lifecycle = Lifecycle(repository)
    original = dataclasses.replace(decision(), issued_at=NOW)
    row, enforce, _ = lifecycle.stage(original, AdaptiveConfig(), now=NOW)
    assert enforce
    lifecycle.activated(row.decision)

    repeated = dataclasses.replace(decision(), issued_at=NOW + timedelta(seconds=10))
    _, enforce, why = lifecycle.stage(
        repeated, AdaptiveConfig(), now=NOW + timedelta(seconds=10)
    )

    assert not enforce
    assert len(repository.rows) == 1
    assert "not renewed" in why


def test_mode_change_creates_the_new_mode_lifecycle_state():
    repository = MemoryLifecycleRepository()
    lifecycle = Lifecycle(repository)
    monitor = dataclasses.replace(AdaptiveConfig(), mode="monitor")
    manual = dataclasses.replace(AdaptiveConfig(), mode="manual")
    lifecycle.stage(dataclasses.replace(decision(), issued_at=NOW), monitor, now=NOW)

    row, enforce, _ = lifecycle.stage(
        dataclasses.replace(decision(), issued_at=NOW + timedelta(seconds=10)),
        manual,
        now=NOW + timedelta(seconds=10),
    )

    assert not enforce
    assert row.status == STATUS_PENDING
    assert len(repository.rows) == 2


def test_automatic_mode_cannot_exceed_its_action_ceiling():
    base = AdaptiveConfig()
    guarded = dataclasses.replace(
        base,
        guardrails=dataclasses.replace(base.guardrails, maximum_automatic_action="throttle"),
    )
    result = calculate_risk(guarded, campaign(), evidence(20))
    assert result.action == ACTION_THROTTLE


def test_writer_rechecks_every_automatic_action_ceiling_at_redis_boundary():
    base = AdaptiveConfig()
    guarded = dataclasses.replace(
        base,
        guardrails=dataclasses.replace(base.guardrails, maximum_automatic_action="monitor"),
    )
    settings = dataclasses.replace(Settings(), adaptive=guarded)
    store = MemoryStore()
    proposed = dataclasses.replace(
        decision(ACTION_THROTTLE),
        source="adaptive",
        requests_per_minute=60,
        mode="automatic",
    )

    written, notes = PolicyWriter(store, settings).write([proposed])

    assert written == 0
    assert any("action ceiling" in note for note in notes)


def test_writer_rechecks_monitor_mode_at_the_redis_boundary():
    base = AdaptiveConfig()
    monitor = dataclasses.replace(base, mode="monitor")
    settings = dataclasses.replace(Settings(), adaptive=monitor)
    store = MemoryStore()
    writer = PolicyWriter(store, settings)
    proposed = dataclasses.replace(decision(ACTION_TEMP_BLOCK), source="adaptive", mode="monitor")
    written, notes = writer.write([proposed])
    assert written == 0
    assert store.keys("policy:*") == []
    assert any("cannot auto-enforce" in note for note in notes)


def test_adaptive_policy_uses_canonical_temporary_block_wire_action():
    settings = Settings()
    store = MemoryStore()
    proposed = dataclasses.replace(
        decision(ACTION_TEMP_BLOCK), source="adaptive", mode="automatic"
    )

    written, _ = PolicyWriter(store, settings).write([proposed])

    assert written == 1
    payload = json.loads(store.get(f"policy:{proposed.ip}"))
    assert payload["action"] == "temporary_block"


def test_model_features_cannot_carry_sensitive_request_fields():
    forbidden = {"body", "password", "token", "cookie", "authorization", "ip", "user_agent"}
    assert forbidden.isdisjoint(FEATURE_NAMES)
    assert "endpoint_method_deviation" in FEATURE_NAMES


def test_runtime_learning_requires_complete_heartbeat_coverage():
    store = MemoryStore()
    settings = dataclasses.replace(Settings(), batch_size=10)
    arrival = {
        "requestId": "r1", "arrivalTs": NOW.isoformat(), "ip": "203.0.113.5",
        "method": "POST", "path": "/api/login", "routeTemplate": "/api/login",
    }
    event = {
        **arrival, "ts": (NOW + timedelta(seconds=1)).isoformat(),
        "responseOrigin": "backend", "upstreamStatus": 401,
        "decision": "allow", "fired": [],
    }
    store.append(settings.arrival_stream, {"arrival": json.dumps(arrival)})
    store.append(settings.evidence_stream, {"event": json.dumps(event)})
    for offset in range(60):
        store.append(settings.health_stream, {"health": json.dumps({
            "at": (NOW + timedelta(seconds=offset)).isoformat(),
            "seq": offset + 1, "droppedTotal": 0, "arrivalsDroppedTotal": 0,
        })})

    rows = WindowConsumer(store, settings).completed(NOW + timedelta(minutes=1, seconds=5))

    assert len(rows) == 1
    assert rows[0].safe_to_learn
    assert rows[0].route_counts == {("POST", "/api/login"): 1}


def test_emergency_blocklist_is_an_explicit_global_override_even_in_monitor_mode(tmp_path):
    base = AdaptiveConfig()
    cfg = dataclasses.replace(
        base,
        mode="monitor",
        guardrails=dataclasses.replace(base.guardrails, blocklist=("203.0.113.0/24",)),
    )
    repository = MemoryLifecycleRepository()
    controller = AdaptiveController(
        MemoryBaselineRepository(), repository,
        ModelScorer(str(tmp_path / "missing.joblib"), str(tmp_path / "missing.json")),
        cfg,
    )

    selected, enforce, _ = controller.decisions(campaign(0.1), evidence(1))[0]

    assert enforce
    assert selected.action == ACTION_TEMP_BLOCK
    assert selected.mode == "manual_override"
    assert selected.scope == "client"


def test_emergency_override_bypasses_adaptive_change_cooldown():
    repository = MemoryLifecycleRepository()
    lifecycle = Lifecycle(repository)
    active = dataclasses.replace(decision(ACTION_THROTTLE), issued_at=NOW)
    row, _, _ = lifecycle.stage(active, AdaptiveConfig(), now=NOW)
    lifecycle.activated(row.decision)
    emergency = dataclasses.replace(
        decision(ACTION_TEMP_BLOCK),
        issued_at=NOW + timedelta(seconds=1),
        source="human",
        mode="manual_override",
    )

    staged, enforce, why = lifecycle.stage(
        emergency, AdaptiveConfig(), now=NOW + timedelta(seconds=1)
    )

    assert enforce
    assert staged.decision.supersedes_policy_id == active.policy_id
    assert "explicit operator" in why
