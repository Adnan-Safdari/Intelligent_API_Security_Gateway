"""
Which addresses a run may use.

RFC 5737 documentation ranges, because control-plane/iasg/policy/writer.py
refuses to police private, loopback and reserved addresses -- an attack driven
from localhost correctly produces no policy at all and looks broken.

One address per session per run, so session_id is exactly (run_id, ip) and
grouping rows by address is automatically session-safe. Two sessions sharing an
address would put one person's traffic in another's window and there would be
nothing in the data to separate them again.
"""

from __future__ import annotations

from dataclasses import dataclass

BENIGN = tuple(f"203.0.113.{n}" for n in range(10, 100))

# Never used while tuning. Held apart from the ordinary attacker pool so a
# reserved scenario cannot accidentally share an address with a tunable one --
# that would put the same group key on both sides of the split.
RESERVED = tuple(f"203.0.113.{n}" for n in range(180, 200))

ATTACKERS = tuple(f"203.0.113.{n}" for n in range(200, 251))


class PoolExhausted(RuntimeError):
    """Raised rather than reusing an address. Reuse would silently merge two
    sessions into one, and no later check could tell."""


@dataclass
class Pool:
    """Hands out addresses without repeating one inside a run."""

    addresses: tuple[str, ...]
    _used: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self._used = []

    def take(self) -> str:
        if len(self._used) >= len(self.addresses):
            raise PoolExhausted(f"all {len(self.addresses)} addresses are in use")
        address = self.addresses[len(self._used)]
        self._used.append(address)
        return address

    @property
    def used(self) -> tuple[str, ...]:
        return tuple(self._used)


def session_id(run_id: str, ip: str) -> str:
    """The group key rows are split on. Two runs may reuse an address; two
    sessions in one run may not."""
    return f"{run_id}|{ip}"
