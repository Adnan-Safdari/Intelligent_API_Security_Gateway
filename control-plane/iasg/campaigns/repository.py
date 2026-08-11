"""
Campaign memory (section 11 of the proposal).

Campaigns survive between cycles. A cluster that overlaps an existing campaign
is merged into it rather than stored as a new one, so confidence and evidence
accumulate over time. That merge is what makes this an agent continuing an
investigation instead of a script starting over every 30 seconds.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from iasg.models import Campaign
from iasg.store.base import Store

# How much IP overlap counts as "the same campaign".
MERGE_OVERLAP = 0.4


class CampaignRepository:
    def __init__(self, store: Store, prefix: str = "campaign:") -> None:
        self._store = store
        self._prefix = prefix
        self._counter_key = f"{prefix}next_id"

    def all(self) -> list[Campaign]:
        campaigns = []
        for key in self._store.keys(f"{self._prefix}*"):
            if key == self._counter_key:
                continue
            raw = self._store.get(key)
            if raw:
                campaigns.append(_from_json(raw))
        return campaigns

    def save(self, campaign: Campaign, ttl_seconds: int = 86_400) -> None:
        self._store.set(
            f"{self._prefix}{campaign.campaign_id}",
            _to_json(campaign),
            ttl_seconds=ttl_seconds,
        )

    def merge(self, fresh: list[Campaign]) -> list[Campaign]:
        """
        Fold this cycle's clusters into what we already knew.

        Returns the campaigns as they now stand, whether new or updated.
        """
        known = self.all()
        result = []

        for candidate in fresh:
            match = _best_match(candidate, known)
            if match is None:
                candidate.campaign_id = self._next_id()
                known.append(candidate)
                result.append(candidate)
            else:
                _absorb(match, candidate)
                result.append(match)

        for campaign in result:
            self.save(campaign)
        return result

    def _next_id(self) -> str:
        current = self._store.get(self._counter_key)
        nxt = int(current) + 1 if current else 1
        # No TTL: the counter must outlive the campaigns it numbers.
        self._store.set(self._counter_key, str(nxt))
        return str(nxt)


def _best_match(candidate: Campaign, known: list[Campaign]) -> Campaign | None:
    """The stored campaign this cluster most likely continues."""
    best, best_score = None, 0.0
    for existing in known:
        if existing.status != "active":
            continue
        score = _overlap(set(candidate.ips), set(existing.ips))
        if score > best_score:
            best, best_score = existing, score
    return best if best_score >= MERGE_OVERLAP else None


def _overlap(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _absorb(existing: Campaign, fresh: Campaign) -> None:
    """Update a known campaign with a new sighting."""
    existing.ips = sorted(set(existing.ips) | set(fresh.ips))
    existing.event_count += fresh.event_count
    existing.last_seen = max(existing.last_seen, fresh.last_seen)
    existing.severity = _worst(existing.severity, fresh.severity)
    existing.reason = fresh.reason
    existing.signature = fresh.signature or existing.signature

    # Repeated sightings raise confidence, but never past certainty.
    existing.confidence = round(
        min(1.0, max(existing.confidence, fresh.confidence) + 0.05), 3
    )

    if fresh.type != "Unclassified Activity":
        existing.type = fresh.type


def _worst(a: str, b: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def _to_json(c: Campaign) -> str:
    return json.dumps(
        {
            "campaign_id": c.campaign_id,
            "type": c.type,
            "confidence": c.confidence,
            "ips": c.ips,
            "reason": c.reason,
            "severity": c.severity,
            "first_seen": c.first_seen.isoformat(),
            "last_seen": c.last_seen.isoformat(),
            "event_count": c.event_count,
            "status": c.status,
            "explanation": c.explanation,
            "assessment": c.assessment,
            "signature": c.signature,
        }
    )


def _from_json(raw: str) -> Campaign:
    d = json.loads(raw)
    return Campaign(
        campaign_id=d["campaign_id"],
        type=d["type"],
        confidence=d["confidence"],
        ips=d["ips"],
        reason=d["reason"],
        severity=d["severity"],
        first_seen=_parse(d.get("first_seen")),
        last_seen=_parse(d.get("last_seen")),
        event_count=d.get("event_count", 0),
        status=d.get("status", "active"),
        explanation=d.get("explanation", ""),
        assessment=d.get("assessment", ""),
        signature=d.get("signature", {}),
    )


def _parse(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(timezone.utc)
