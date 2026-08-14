"""
The Policy Agent (section 13.2).

Sees campaign, severity, confidence and history -- never raw requests. Decides
one action per IP. This is the only part of the control plane that can
influence the gateway, so the ladder is deliberately boring and readable.
"""

from __future__ import annotations

from iasg.models import (
    ACTION_ESCALATE,
    ACTION_LADDER,
    ACTION_MONITOR,
    ACTION_TEMP_BLOCK,
    ACTION_THROTTLE,
    SEVERITY_HIGH,
    Campaign,
    PolicyDecision,
)

# How long each action stands before Redis expires it by itself.
TTL = {
    ACTION_MONITOR: 300,
    ACTION_THROTTLE: 900,
    ACTION_TEMP_BLOCK: 1800,
    # Escalation outlasts an ordinary block: a human has been asked to look,
    # and the block should still be there when they do.
    ACTION_ESCALATE: 3600,
}

LARGE_CAMPAIGN = 5


class PolicyAgent:
    def decide(self, campaign: Campaign, bias: int = 0) -> list[PolicyDecision]:
        """
        One decision per IP in the campaign.

        `bias` is what humans have repeatedly done to this kind of campaign,
        in rungs -- see feedback/memory.py. It moves the starting point and
        nothing else; the collateral checks and address rails run afterwards
        and are not learnable.
        """
        action = self._action(campaign, bias)
        reason = (
            f"{campaign.type} (campaign {campaign.campaign_id}), "
            f"confidence {campaign.confidence:.2f}, severity {campaign.severity}"
        )
        if len(campaign.stages) > 1:
            reason += f", progressed through {' -> '.join(campaign.stages)}"
        if campaign.persistence:
            rounds = "round" if campaign.persistence == 1 else "rounds"
            reason += (
                f", survived {campaign.persistence} enforcement {rounds}"
            )
        return [
            PolicyDecision(
                ip=ip,
                action=action,
                campaign_id=campaign.campaign_id,
                confidence=campaign.confidence,
                ttl_seconds=TTL[action],
                reason=reason,
            )
            for ip in campaign.ips
        ]

    def _action(self, campaign: Campaign, bias: int = 0) -> str:
        """What the evidence asks for, then what our own history argues for."""
        return _promote(self._from_evidence(campaign), campaign, bias)

    def _from_evidence(self, campaign: Campaign) -> str:
        confidence = campaign.confidence
        high = campaign.severity == SEVERITY_HIGH

        if confidence >= 0.9 and high and len(campaign.ips) >= LARGE_CAMPAIGN:
            return ACTION_ESCALATE
        if confidence >= 0.75 and high:
            return ACTION_TEMP_BLOCK
        if confidence >= 0.5:
            return ACTION_THROTTLE
        return ACTION_MONITOR


def _promote(action: str, campaign: Campaign, bias: int = 0) -> str:
    """
    Two reasons to answer more firmly than the evidence alone asked for.

    Enforcement that failed: every round the campaign survived moves it one
    rung up the ladder, so an action that did not work is not simply repeated.

    An attacker that progressed: each phase beyond the first moves it another
    rung. Someone who scanned for secrets, then attacked the login they found,
    then probed the database has shown intent that a single-phase attacker has
    not, and answering the loudest phase alone under-reacts to all of it.

    Promotion lengthens the policy TTL as a side effect, because each rung is
    held for longer than the one below it.

    A learned bias: humans who keep correcting this kind of campaign in the
    same direction move it one rung that way, and only one, ever.

    Escalation stays reserved for high severity by any of these routes. It asks
    a human to look and holds an address for an hour, which is too much to
    reach on a campaign the evidence never called severe.
    """
    earned = (
        campaign.persistence
        + max(0, len(campaign.stages) - 1)
        # Clamped rather than trusted: bias reaches this from stored state, and
        # one rung is the most it is ever allowed to be worth.
        + max(-1, min(1, bias))
    )
    if not earned:
        return action

    ceiling = (
        ACTION_LADDER.index(ACTION_ESCALATE)
        if campaign.severity == SEVERITY_HIGH
        else ACTION_LADDER.index(ACTION_TEMP_BLOCK)
    )
    # A negative bias can pull below monitor, which is not a rung.
    rung = ACTION_LADDER.index(action) + earned
    return ACTION_LADDER[max(0, min(rung, ceiling))]
