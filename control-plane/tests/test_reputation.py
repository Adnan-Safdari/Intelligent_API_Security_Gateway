"""
IP reputation: the one signal that comes from outside this gateway.

The properties worth protecting are all about restraint. Reputation says who an
address is, not what it did, so it must firm up a response without inventing
one, and it must never take credit for a campaign it merely witnessed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from iasg.correlation.agent import CorrelationAgent
from iasg.models import (
    ACTION_LADDER,
    ACTION_MONITOR,
    DETECTOR_BRUTE_FORCE,
    DETECTOR_FLOOD,
    DETECTOR_REPUTATION,
    SIGNAL_TO_DETECTOR,
    STAGE_OF,
    Campaign,
    Evidence,
)
from iasg.policy.agent import PolicyAgent, reputation_bias

NOW = datetime.now(timezone.utc)


def evidence(ip, detector, severity="medium", endpoint="/api/login"):
    return Evidence(
        timestamp=NOW, ip=ip, endpoint=endpoint,
        detector=detector, severity=severity,
    )


def campaign(ips, ctype="API Flooding", confidence=0.8, severity="medium"):
    return Campaign(
        campaign_id="1", type=ctype, confidence=confidence, ips=ips,
        reason="test", severity=severity, first_seen=NOW, last_seen=NOW,
    )


# --- the bias ---

def test_a_listed_address_in_the_campaign_earns_a_rung():
    c = campaign(["203.0.113.66"])
    ev = [evidence("203.0.113.66", DETECTOR_REPUTATION)]
    assert reputation_bias(c, ev) == 1


def test_no_reputation_evidence_earns_nothing():
    c = campaign(["203.0.113.66"])
    ev = [evidence("203.0.113.66", DETECTOR_FLOOD)]
    assert reputation_bias(c, ev) == 0


def test_a_listed_address_outside_the_campaign_earns_nothing():
    # Someone else being listed says nothing about these addresses.
    c = campaign(["203.0.113.10"])
    ev = [evidence("203.0.113.66", DETECTOR_REPUTATION)]
    assert reputation_bias(c, ev) == 0


def test_reputation_firms_the_action_by_one_rung():
    c = campaign(["203.0.113.66"], confidence=0.6, severity="medium")

    plain = PolicyAgent().decide(c, bias=0)[0].action
    listed = PolicyAgent().decide(c, bias=1)[0].action

    assert ACTION_LADDER.index(listed) == ACTION_LADDER.index(plain) + 1


def test_reputation_and_learned_feedback_cannot_compound():
    """
    The clamp in _promote is the point: two independent reasons to be firmer
    are still only worth one rung, so nothing reaches a block by addition.
    """
    c = campaign(["203.0.113.66"], confidence=0.6, severity="medium")

    one = PolicyAgent().decide(c, bias=1)[0].action
    both = PolicyAgent().decide(c, bias=2)[0].action
    assert one == both


def test_reputation_alone_never_invents_enforcement():
    """
    The property that keeps a stale feed from causing an outage.

    A campaign the evidence itself would only monitor stays monitored, so the
    bias has to come back as 0 -- being listed makes an attack answerable more
    firmly, it does not make ordinary traffic into an attack.
    """
    ip = "203.0.113.66"
    quiet = campaign([ip], confidence=0.2, severity="low")
    ev = [evidence(ip, DETECTOR_REPUTATION)]

    assert reputation_bias(quiet, ev) == 0

    action = PolicyAgent().decide(quiet, bias=reputation_bias(quiet, ev))[0].action
    assert action == ACTION_MONITOR


def test_reputation_does_firm_up_a_campaign_that_already_earned_action():
    ip = "203.0.113.66"
    real = campaign([ip], confidence=0.6, severity="medium")
    ev = [evidence(ip, DETECTOR_REPUTATION)]

    # The same address, the same list -- the difference is that this campaign
    # produced enough evidence to be acted on at all.
    assert reputation_bias(real, ev) == 1


# --- staging ---

def test_reputation_is_not_an_intrusion_phase():
    """
    Being on a list is not something the attacker did, so it must not count as
    a stage -- _promote reads len(stages) and would hand every listed address a
    free rung on top of the one the bias already gives it.
    """
    assert DETECTOR_REPUTATION not in STAGE_OF


def test_reputation_evidence_does_not_add_a_stage():
    ip = "203.0.113.66"
    only_flood = CorrelationAgent().analyse([evidence(ip, DETECTOR_FLOOD)] * 3)
    with_listing = CorrelationAgent().analyse(
        [evidence(ip, DETECTOR_FLOOD)] * 3 + [evidence(ip, DETECTOR_REPUTATION)]
    )
    assert len(only_flood[0].stages) == len(with_listing[0].stages)


# --- naming ---

def test_reputation_does_not_rename_a_behavioural_campaign():
    """
    A listed address running a brute force is a brute force. Reputation fires
    on a cooldown so it should not out-count anything, but the classifier does
    not rely on that.
    """
    ip = "203.0.113.66"
    campaigns = CorrelationAgent().analyse(
        [evidence(ip, DETECTOR_BRUTE_FORCE)] * 2 + [evidence(ip, DETECTOR_REPUTATION)] * 20
    )
    assert campaigns[0].type != "Known Bad Address"
    assert "Brute Force" in campaigns[0].type or "Spraying" in campaigns[0].type


def test_reputation_can_name_a_campaign_when_it_is_all_there_is():
    # A lone address needs MIN_SOLO_EVENTS before it counts as a campaign, and
    # reputation fires once per cooldown -- so this is a listed address that
    # kept calling for a quarter of an hour without tripping anything else.
    campaigns = CorrelationAgent().analyse(
        [evidence("203.0.113.66", DETECTOR_REPUTATION, endpoint="/products")] * 3
    )
    assert campaigns[0].type == "Known Bad Address"


# --- the wire ---

def test_the_gateway_signal_name_maps_to_this_detector():
    assert SIGNAL_TO_DETECTOR["ip_reputation"] == DETECTOR_REPUTATION


def test_telemetry_carrying_a_reputation_hit_becomes_evidence():
    import json

    event = {
        "ts": NOW.isoformat(),
        "ip": "203.0.113.66",
        "path": "/products",
        "fired": ["ip_reputation"],
        "signals": [
            {
                "signal": "ip_reputation",
                "score": 80,
                "thresholdCross": True,
                "attackType": "known_bad_address",
                "details": {"listed": True},
            }
        ],
    }
    found = Evidence.from_stream_entry("1-1", {"event": json.dumps(event)})

    assert len(found) == 1
    assert found[0].detector == DETECTOR_REPUTATION
    assert found[0].ip == "203.0.113.66"
