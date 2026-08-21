"""
Writes policy:<ip> keys into Redis.

Everything that could do damage is guarded here rather than in the agent, so
there is one place to audit before trusting this with real traffic.
"""

from __future__ import annotations

import ipaddress

from iasg.config import Settings
from iasg.models import ACTION_MONITOR, PolicyDecision
from iasg.store.base import Store


class PolicyWriter:
    def __init__(self, store: Store, settings: Settings) -> None:
        self._store = store
        self._settings = settings

    def write(self, decisions: list[PolicyDecision]) -> tuple[int, list[str]]:
        """
        Apply decisions. Returns (written, skipped_notes).

        Rails, in order:
          - never touch loopback, private or reserved addresses
          - never write a bare "monitor", which would be a no-op key
          - never write a decision that has no expiry
          - cap how many IPs one cycle may action
          - dry_run writes nothing at all
        """
        written = 0
        notes: list[str] = []
        budget = self._settings.max_ips_per_cycle

        for decision in decisions:
            if decision.action == ACTION_MONITOR:
                continue

            if not _is_public(decision.ip):
                notes.append(f"skipped {decision.ip} (not a public address)")
                continue

            # Enforcement has to release itself. Redis is what ends a block --
            # nothing in the design renews or clears one -- so a decision with
            # no expiry would refuse an address until a human noticed and
            # deleted the key by hand. The store treats a falsy ttl as "keep
            # forever", which turns a missing number into a permanent sentence,
            # so the number is checked here rather than trusted downstream.
            if not decision.ttl_seconds or decision.ttl_seconds <= 0:
                notes.append(
                    f"skipped {decision.ip} ({decision.action} with no expiry)"
                )
                continue

            if budget <= 0:
                notes.append(f"skipped {decision.ip} (cycle cap reached)")
                continue

            key = f"{self._settings.policy_prefix}{decision.ip}"
            if self._settings.dry_run:
                notes.append(f"[dry-run] would set {key} -> {decision.action}")
            else:
                self._store.set(key, decision.to_json(), decision.ttl_seconds)
                written += 1

            budget -= 1

        return written, notes


# RFC 5737 ranges reserved for documentation and examples. Python's
# is_private returns True for these, but they can never belong to a real host,
# so blocking them would only break demos and tests.
DOC_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def _is_public(ip: str) -> bool:
    """Refuse to write policy for anything that isn't safely actionable."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if any(addr in net for net in DOC_RANGES):
        return True

    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )
