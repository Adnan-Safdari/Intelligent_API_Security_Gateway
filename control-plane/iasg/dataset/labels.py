"""
Labels, from the run manifest and nothing else.

A dataset labelled by the detectors can only teach a model to reproduce the
detectors, mistakes included -- and it would score well while being worthless,
because the point of this layer is to catch what they miss.

The guarantee is structural rather than a rule to remember: label_for takes an
address, a window and the manifest's attacks, and has no parameter through
which `fired`, `riskScore`, `decision` or a status could reach it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence


@dataclass(frozen=True)
class Attack:
    """One attack interval, written before traffic starts."""

    scenario: str
    ip: str
    start: datetime
    end: datetime

    @classmethod
    def from_json(cls, obj: dict) -> "Attack":
        return cls(
            scenario=obj["scenario"],
            ip=obj["ip"],
            start=_utc(obj["start"]),
            end=_utc(obj["end"]),
        )

    def covers(self, ip: str, window_start: datetime, window_end: datetime) -> bool:
        """
        Any overlap counts. A window in which an attack ran for ten seconds is
        an attack window: the behaviour is in the features either way, and
        requiring full coverage would label the first and last minute of every
        attack as benign.
        """
        return self.ip == ip and self.start < window_end and window_start < self.end


def label_for(
    ip: str,
    window_start: datetime,
    attacks: Sequence[Attack],
    window_seconds: int = 60,
) -> int:
    """1 if a manifest attack overlaps this address's window, else 0."""
    from datetime import timedelta

    window_end = window_start + timedelta(seconds=window_seconds)
    return 1 if any(a.covers(ip, window_start, window_end) for a in attacks) else 0


def scenario_for(
    ip: str, window_start: datetime, attacks: Sequence[Attack], window_seconds: int = 60
) -> str:
    from datetime import timedelta

    window_end = window_start + timedelta(seconds=window_seconds)
    for attack in attacks:
        if attack.covers(ip, window_start, window_end):
            return attack.scenario
    return "benign"


def load_attacks(lines: Iterable[str]) -> list[Attack]:
    import json

    attacks = []
    for line in lines:
        line = line.strip()
        if line:
            attacks.append(Attack.from_json(json.loads(line)))
    return attacks


def _utc(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
