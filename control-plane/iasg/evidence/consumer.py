"""
Reads evidence off the attack_events stream.

Uses a consumer group so restarts neither lose nor replay events. Entries are
acked only after a cycle finishes -- acking on read would drop evidence
whenever the agent crashed mid-cycle.
"""

from __future__ import annotations

from iasg.config import Settings
from iasg.models import Evidence
from iasg.store.base import Store


class EvidenceConsumer:
    def __init__(self, store: Store, settings: Settings) -> None:
        self._store = store
        self._settings = settings
        self._stream = settings.evidence_stream
        self._group = settings.consumer_group
        self._consumer = settings.consumer_name
        self._store.ensure_group(self._stream, self._group)
        self._recovered = False

    def fetch(self) -> list[Evidence]:
        """Return this cycle's evidence, oldest first."""
        entries: list[tuple[str, dict[str, str]]] = []

        # On the first run, reclaim anything a previous crash left unacked.
        if not self._recovered:
            entries.extend(
                self._store.read_pending(
                    self._stream, self._group, self._consumer,
                    self._settings.batch_size,
                )
            )
            self._recovered = True

        entries.extend(
            self._store.read_group(
                self._stream, self._group, self._consumer,
                self._settings.batch_size,
            )
        )

        return [Evidence.from_stream_fields(eid, fields) for eid, fields in entries]

    def ack(self, evidence: list[Evidence]) -> int:
        """Mark evidence as processed. Called only after a cycle succeeds."""
        ids = [e.stream_id for e in evidence if e.stream_id]
        if not ids:
            return 0
        return self._store.ack(self._stream, self._group, *ids)
