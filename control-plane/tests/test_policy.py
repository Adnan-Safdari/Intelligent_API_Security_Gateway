"""The policy ladder, and the rails that stop it doing damage."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone

from iasg.config import Settings
from iasg.models import (
    ACTION_ESCALATE,
    ACTION_MONITOR,
    ACTION_TEMP_BLOCK,
    ACTION_THROTTLE,
    Campaign,
)
from iasg.policy.agent import PolicyAgent
from iasg.policy.writer import PolicyWriter
from iasg.store.memory import MemoryStore


def campaign(confidence, severity="high", ips=None):
    return Campaign(
        campaign_id="7",
        type="Credential Stuffing",
        confidence=confidence,
        ips=ips or ["203.0.113.5"],
        reason="test",
        severity=severity,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )


# --- the ladder ---

def test_low_confidence_only_monitors():
    assert PolicyAgent().decide(campaign(0.3))[0].action == ACTION_MONITOR


def test_medium_confidence_throttles():
    assert PolicyAgent().decide(campaign(0.6))[0].action == ACTION_THROTTLE


def test_high_confidence_and_severity_blocks():
    assert PolicyAgent().decide(campaign(0.8))[0].action == ACTION_TEMP_BLOCK


def test_large_high_confidence_campaign_escalates():
    ips = [f"203.0.113.{n}" for n in range(1, 7)]
    assert PolicyAgent().decide(campaign(0.95, ips=ips))[0].action == ACTION_ESCALATE


def test_high_confidence_but_low_severity_only_throttles():
    assert PolicyAgent().decide(campaign(0.95, severity="low"))[0].action == ACTION_THROTTLE


def test_one_decision_per_ip():
    ips = ["203.0.113.5", "203.0.113.9", "203.0.113.14"]
    assert len(PolicyAgent().decide(campaign(0.8, ips=ips))) == 3


def test_every_action_carries_a_ttl():
    for confidence in (0.3, 0.6, 0.8, 0.95):
        assert PolicyAgent().decide(campaign(confidence))[0].ttl_seconds > 0


# --- the rails ---

def settings(**kwargs):
    return replace(Settings(), **kwargs)


def test_writes_policy_for_public_ip():
    store = MemoryStore()
    decisions = PolicyAgent().decide(campaign(0.8))
    written, _ = PolicyWriter(store, settings()).write(decisions)

    assert written == 1
    stored = json.loads(store.get("policy:203.0.113.5"))
    assert stored["action"] == ACTION_TEMP_BLOCK


def test_never_writes_policy_for_private_or_loopback():
    store = MemoryStore()
    for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1"):
        decisions = PolicyAgent().decide(campaign(0.8, ips=[ip]))
        written, notes = PolicyWriter(store, settings()).write(decisions)
        assert written == 0, f"wrote policy for {ip}"
        assert notes


def test_never_writes_a_decision_without_an_expiry():
    """
    A block ends because Redis drops the key. Nothing renews or clears one, so
    a decision with no expiry would refuse an address until a human deleted the
    key by hand -- and the store reads a falsy ttl as "keep forever", which
    turns a missing number into a permanent sentence.
    """
    store = MemoryStore()
    decision = PolicyAgent().decide(campaign(0.8))[0]

    for ttl in (0, None, -1):
        written, notes = PolicyWriter(store, settings()).write(
            [replace(decision, ttl_seconds=ttl)]
        )
        assert written == 0, f"wrote an unexpiring policy for ttl={ttl!r}"
        assert any("no expiry" in note for note in notes), notes
        assert store.keys("policy:*") == []


def test_an_unexpiring_decision_does_not_consume_the_cycle_budget():
    """A refused decision must not cost a slot a real one could have used."""
    store = MemoryStore()
    good = PolicyAgent().decide(campaign(0.8, ips=["203.0.113.5"]))[0]
    bad = replace(
        PolicyAgent().decide(campaign(0.8, ips=["203.0.113.9"]))[0],
        ttl_seconds=0,
    )

    written, _ = PolicyWriter(store, settings(max_ips_per_cycle=1)).write([bad, good])

    assert written == 1
    assert store.get("policy:203.0.113.5") is not None


def test_monitor_writes_nothing():
    store = MemoryStore()
    decisions = PolicyAgent().decide(campaign(0.3))
    written, _ = PolicyWriter(store, settings()).write(decisions)
    assert written == 0
    assert store.keys("policy:*") == []


def test_dry_run_writes_nothing_but_reports():
    store = MemoryStore()
    decisions = PolicyAgent().decide(campaign(0.8))
    written, notes = PolicyWriter(store, settings(dry_run=True)).write(decisions)

    assert written == 0
    assert store.keys("policy:*") == []
    assert any("dry-run" in n for n in notes)


def test_cycle_cap_limits_how_many_ips_are_actioned():
    store = MemoryStore()
    ips = [f"203.0.113.{n}" for n in range(1, 11)]
    decisions = PolicyAgent().decide(campaign(0.8, ips=ips))
    written, notes = PolicyWriter(store, settings(max_ips_per_cycle=3)).write(decisions)

    assert written == 3
    assert any("cap reached" in n for n in notes)


def test_malformed_ip_is_skipped():
    store = MemoryStore()
    decisions = PolicyAgent().decide(campaign(0.8, ips=["not-an-ip"]))
    written, _ = PolicyWriter(store, settings()).write(decisions)
    assert written == 0


def test_written_policy_carries_a_ttl():
    store = MemoryStore()
    decisions = PolicyAgent().decide(campaign(0.8))
    PolicyWriter(store, settings()).write(decisions)

    _value, expires_at = store._keys["policy:203.0.113.5"]
    assert expires_at is not None


# --- the rate a throttle carries -------------------------------------------
#
# What makes the rate limiting adaptive: the number the gateway enforces comes
# from how bad the campaign is, rather than every throttled caller being slowed
# by the same amount.

def test_throttle_carries_a_rate():
    decision = PolicyAgent().decide(campaign(0.6, severity="medium"))[0]
    assert decision.action == ACTION_THROTTLE
    assert decision.requests_per_minute == 50


def test_a_severe_campaign_is_throttled_harder():
    # Same rung, worse campaign, tighter allowance.
    medium = PolicyAgent().decide(campaign(0.6, severity="medium"))[0]
    high = PolicyAgent().decide(campaign(0.6, severity="high"))[0]
    assert medium.action == high.action == ACTION_THROTTLE
    assert high.requests_per_minute < medium.requests_per_minute
    assert high.requests_per_minute == 20


def test_monitor_names_no_rate():
    # Monitoring changes nothing about what the address may send.
    decision = PolicyAgent().decide(campaign(0.3))[0]
    assert decision.action == ACTION_MONITOR
    assert decision.requests_per_minute == 0


def test_blocking_names_no_rate():
    # Refusing the request outright is the limit; a rate would be unused.
    decision = PolicyAgent().decide(campaign(0.8))[0]
    assert decision.action == ACTION_TEMP_BLOCK
    assert decision.requests_per_minute == 0


def test_the_rate_reaches_the_gateway_contract():
    # The JSON at policy:<ip> is the whole contract with the Go gateway, so the
    # rate is only real if it survives serialisation under that exact name.
    decision = PolicyAgent().decide(campaign(0.6, severity="high"))[0]
    written = json.loads(decision.to_json())
    assert written["requests_per_minute"] == 20
    assert written["action"] == ACTION_THROTTLE


def test_the_rate_is_explained_in_the_reason():
    # An operator reading the policy should see why traffic is being refused.
    decision = PolicyAgent().decide(campaign(0.6, severity="high"))[0]
    assert "20 requests/min" in decision.reason
