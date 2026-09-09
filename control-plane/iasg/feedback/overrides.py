"""
What a human decided, which always beats what the agent decided.

An admin writes to the override stream -- from a dashboard, a script, or
redis-cli -- and this reads it once, applies it, and remembers the
disagreement:

    XADD iasg_overrides '*' ip 203.0.113.5 action temp_block \
        actor pranav reason "confirmed attack"

A stream rather than plain keys so each instruction is delivered exactly once
and can be recorded as feedback without being counted again on the next cycle.

The one thing an override cannot do is police an allowlisted range. That is
not the agent overruling a person -- it is one deliberate operator decision
outranking another, and the config is the more considered of the two.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from iasg.config import Settings
from iasg.models import ACTION_ALLOW, ACTION_LADDER, PolicyDecision
from iasg.policy.agent import TTL
from iasg.store.base import Store


@dataclass(frozen=True)
class Override:
    ip: str
    action: str
    actor: str = ""
    reason: str = ""
    method: str = ""
    route_template: str = ""
    emergency: bool = False
    policy_id: str = ""
    ttl_seconds: int = 0

    @classmethod
    def from_fields(cls, fields: dict[str, str]) -> "Override | None":
        ip = (fields.get("ip") or "").strip()
        action = (fields.get("action") or "").strip()
        # An instruction we cannot act on is worse than none, because acting on
        # a misspelled action would silently write nonsense into the gateway.
        if not ip or action not in (*ACTION_LADDER, ACTION_ALLOW):
            return None
        return cls(
            ip=ip,
            action=action,
            actor=(fields.get("actor") or "unknown").strip(),
            reason=(fields.get("reason") or "").strip(),
            method=(fields.get("method") or "").strip().upper(),
            route_template=(fields.get("route_template") or "").strip(),
            emergency=(fields.get("emergency") or "").strip().lower()
            in ("1", "true", "yes"),
            policy_id=(fields.get("policy_id") or "").strip(),
            ttl_seconds=_positive_int(fields.get("ttl_seconds")),
        )


class OverrideChannel:
    def __init__(self, store: Store, settings: Settings) -> None:
        self._store = store
        self._settings = settings
        self._stream = settings.override_stream
        self._group = settings.override_group
        self._store.ensure_group(self._stream, self._group)

    def pending(self) -> list[Override]:
        """Every instruction left since the last cycle, newest winning."""
        entries = self._store.read_group(
            self._stream, self._group, self._settings.consumer_name, 100
        )
        if not entries:
            return []

        ids = [entry_id for entry_id, _ in entries]

        # Two instructions for one address in the same cycle: the later one is
        # what the person currently wants.
        latest: dict[str, Override] = {}
        for _, fields in entries:
            override = Override.from_fields(fields)
            if override:
                latest[override.ip] = override

        # Acked whether or not they parsed, so an unreadable instruction is
        # not retried forever.
        self._store.ack(self._stream, self._group, *ids)
        return list(latest.values())


def apply(
    decisions: list[PolicyDecision], overrides: dict[str, Override]
) -> tuple[list[PolicyDecision], list[tuple[str, str]], list[str]]:
    """
    Replace agent decisions with human ones.

    Returns the decisions to write, the (agent_action, human_action) pairs
    worth learning from, and notes.
    """
    applied: list[PolicyDecision] = []
    lessons: list[tuple[str, str]] = []
    notes: list[str] = []

    for decision in decisions:
        override = overrides.get(decision.ip)
        if override is None:
            applied.append(decision)
            continue

        if override.action == decision.action:
            # Agreement teaches nothing about where the agent is wrong.
            notes.append(
                f"[human] {override.actor} confirmed {decision.action} "
                f"for {decision.ip}"
            )
            applied.append(_as_decision(decision, override))
            continue

        lessons.append((decision.action, override.action))
        notes.append(
            f"[human] {override.actor} set {decision.ip} to "
            f"{override.action} (agent said {decision.action})"
            + (f" -- {override.reason}" if override.reason else "")
        )
        applied.append(_as_decision(decision, override))

    return applied, lessons, notes


def standalone(
    overrides: dict[str, Override], handled: set[str], campaign_id: str = "manual"
) -> list[PolicyDecision]:
    """
    Instructions about addresses no campaign mentioned this cycle.

    An admin blocking an address the agent has never seen is the plainest use
    of this feature, and it must not require a campaign to exist first.
    """
    return [
        PolicyDecision(
            ip=o.ip,
            action=o.action,
            campaign_id=campaign_id,
            confidence=1.0,
            ttl_seconds=o.ttl_seconds or TTL[o.action],
            source="human",
            issued_by=o.actor or "unknown",
            mode="manual_override" if o.emergency else "manual",
            method=o.method,
            route_template=o.route_template,
            scope="client_endpoint" if o.route_template else "client",
            policy_id=o.policy_id or PolicyDecision.__dataclass_fields__["policy_id"].default_factory(),
            reason=(
                f"set by {o.actor}"
                + (f": {o.reason}" if o.reason else "")
            ),
        )
        for ip, o in overrides.items()
        if ip not in handled
    ]


def _as_decision(decision: PolicyDecision, override: Override) -> PolicyDecision:
    standing_policy_id = str(
        ((decision.explanation or {}).get("final") or {}).get("standing_policy_id")
        or ""
    )
    return replace(
        decision,
        action=override.action,
        ttl_seconds=override.ttl_seconds or TTL[override.action],
        confidence=1.0,  # a person looked; that is not a probability
        source="human",
        issued_by=override.actor or "unknown",
        mode="manual_override" if override.emergency else "manual",
        method=override.method or decision.method,
        route_template=override.route_template or decision.route_template,
        scope=("client_endpoint" if (override.route_template or decision.route_template) else "client"),
        policy_id=override.policy_id or decision.policy_id,
        supersedes_policy_id=(
            standing_policy_id
            if standing_policy_id != (override.policy_id or decision.policy_id)
            else decision.supersedes_policy_id
        ),
        reason=(
            f"set by {override.actor}, overriding {decision.action}"
            + (f": {override.reason}" if override.reason else "")
        ),
    )


def _positive_int(value) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0
