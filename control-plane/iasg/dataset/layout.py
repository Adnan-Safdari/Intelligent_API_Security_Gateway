"""
Where a run's files live, named once.

Capture writes some of these and the traffic generator writes others, so the
names have to be agreed somewhere other than in two argument parsers.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Its own group, deliberately. Redis delivers every entry to every consumer
# group independently, so capture sees clean requests without touching the
# agent's group or Evidence semantics -- campaign formation depends on
# models.py returning no Evidence for a request that fired nothing, and that
# line must not be changed to make capture work.
CAPTURE_GROUP = "iasg-dataset"

STREAM_EVENTS = "iasg:events"
STREAM_ARRIVALS = "iasg:arrivals"
STREAM_HEALTH = "iasg:telemetry:health"


@dataclass(frozen=True)
class RawRun:
    """One capture run's directory."""

    root: Path

    @classmethod
    def at(cls, path: str | Path) -> "RawRun":
        root = Path(path)
        root.mkdir(parents=True, exist_ok=True)
        return cls(root=root)

    # Written by capture, from the three streams.
    @property
    def arrivals(self) -> Path:
        return self.root / "arrivals.jsonl"

    @property
    def completions(self) -> Path:
        return self.root / "completions.jsonl"

    @property
    def health(self) -> Path:
        return self.root / "health.jsonl"

    @property
    def manifest(self) -> Path:
        return self.root / "manifest.json"

    # Written by the traffic generator, before traffic starts. Labels come from
    # here and from nowhere else -- never from detector output.
    @property
    def attacks(self) -> Path:
        return self.root / "attacks.jsonl"

    @property
    def sessions(self) -> Path:
        return self.root / "sessions.jsonl"
