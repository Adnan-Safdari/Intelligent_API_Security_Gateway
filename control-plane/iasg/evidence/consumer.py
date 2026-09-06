"""
Reads evidence off the iasg:events stream.

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
        self._read_ids: list[str] = []

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

        # Every entry read has to be acked, not just the ones that produced
        # Evidence. The gateway writes one entry per request and most requests
        # are clean, so from_stream_entry returns [] for the majority of them;
        # acking only what became Evidence left every clean request pending
        # forever, growing the PEL without bound and making read_pending replay
        # the whole backlog on each restart.
        self._read_ids.extend(eid for eid, _ in entries)

        out: list[Evidence] = []
        for eid, fields in entries:
            out.extend(Evidence.from_stream_entry(eid, fields))
        return out

    def ack(self, evidence: list[Evidence] | None = None) -> int:
        """Mark this cycle's entries as processed. Called only after a cycle succeeds.

        `evidence` is still accepted so a caller can ack records it obtained
        some other way, but it is no longer the source of truth: what this
        consumer read is.
        """
        ids = list(self._read_ids)
        if evidence:
            ids.extend(e.stream_id for e in evidence if e.stream_id)

        ids = list(dict.fromkeys(i for i in ids if i))
        if not ids:
            return 0

        acked = self._store.ack(self._stream, self._group, *ids)
        # Cleared only on success, so a store that raised is retried rather
        # than silently forgotten.
        self._read_ids.clear()
        return acked
