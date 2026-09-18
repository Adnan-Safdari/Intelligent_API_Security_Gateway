"""
The Store interface -- everything this projects needs redis , in one list.

Two classes will implement it:
    MemoryStore -- a fake , for tests . No Redis needed
    RedisStore  -- the real one.

Everything else in the project accepts a "Store" without caring which it got.
That is what lets the whole pipeline be tested without a database running
"""

from __future__ import annotations

from typing import Protocol

class Store(Protocol):
    def ensure_group(self, stream: str, group: str) -> None:
        """
        Create the consumer group if it doesn't exist yet.

        A "consumer group" is Redis remembering how far we've read. Without it,
        restarting the agent would re-process every attack from the beginning
        of time. Safe to call repeatedly -- doing nothing when it already
        exists is the expected case.
        """
        ...

    def read_group(
            self,
            stream :  str,
            group: str,
            consumer : str,
            count : int,
            block_ms : int = 0,
    ) -> list[tuple[str,dict[str,str]]]:
        pass

    def read_pending(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
    ) -> list[tuple[str, dict[str, str]]]:
        """Re-read entries handed out but never acked. Crash recovery."""
        ...

    def ack(self, stream: str, group: str, *ids: str) -> int:
        pass
    
    def append(self , stream: str, fields: dict[str,str]) -> str:
        pass

    def trim(self, stream: str, maxlen: int) -> int:
        """Remove old entries without deleting the stream's consumer groups."""
        ...

    def get(self, key: str) -> str | None:
        pass

    def set(self,key:str,value:str,ttl_seconds:int | None = None) -> None:
        pass

    def keys(self, pattern: str) -> list[str]:
        pass

    def stream_first_id(self, stream: str) -> str | None:
        """
        The oldest entry still in the stream, or None if it is empty.

        Compared against a group's last-delivered id, this is how a reader
        learns that entries were trimmed away before it got to them. Prevention
        can always be exceeded -- a long enough run outruns any cap -- so the
        adaptive baseline learning marks affected windows untrusted instead of
        pretending the loss cannot happen.
        """
        ...

    def group_last_delivered(self, stream: str, group: str) -> str | None:
        """The last id handed to this group, or None if the group is unknown."""
        ...

    def close(self) -> None:
        pass
