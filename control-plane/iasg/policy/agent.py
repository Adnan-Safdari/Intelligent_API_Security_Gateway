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
    def decide(self, campaign: Campaign) -> list[PolicyDecision]:
        """One decision per IP in the campaign."""
        action = self._action(campaign)
        reason = (
            f"{campaign.type} (campaign {campaign.campaign_id}), "
            f"confidence {campaign.confidence:.2f}, severity {campaign.severity}"
        )
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

    def _action(self, campaign: Campaign) -> str:
        """What the evidence asks for, then what our own history argues for."""
        return _promote(self._from_evidence(campaign), campaign)

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


def _promote(action: str, campaign: Campaign) -> str:
    """
    Close the loop: an action that demonstrably failed is not repeated as-is.

    Every enforcement round the campaign survived moves it one rung up the
    ladder, which lengthens the policy TTL as a side effect because each rung
    is held for longer than the one below it.

    Escalation is reserved for high severity even here. It asks a human to
    look and holds an address for an hour, which is too much to reach by
    persistence alone on a campaign the evidence never called severe.
    """
    if not campaign.persistence:
        return action

    ceiling = (
        ACTION_LADDER.index(ACTION_ESCALATE)
        if campaign.severity == SEVERITY_HIGH
        else ACTION_LADDER.index(ACTION_TEMP_BLOCK)
    )
    rung = ACTION_LADDER.index(action) + campaign.persistence
    return ACTION_LADDER[min(rung, ceiling)]
