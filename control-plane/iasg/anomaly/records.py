"""
One request, as the two observations that describe it.

The gateway records a request twice: once on arrival, before anything ran, and
once on completion. They are separate observations joined by requestId, and
each keeps when it became available. That is the whole leakage guard -- it lets
one function answer "what was known at instant X" without a second code path
that could quietly answer something else.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Iterable

from iasg.anomaly.spec import (
    LOGIN_METHOD,
    LOGIN_ROUTE,
    ORIGIN_BACKEND,
    OUTCOME_TIMEOUT,
    UNMATCHED_ROUTE,
)


@dataclass(frozen=True)
class RequestRecord:
    """
    What is known about one request.

    Every completion-side field is None until the response settled. There is no
    sentinel and no zero default among them, because zero and unknown are
    different observations throughout this specification and a default would
    quietly pick one.
    """

    request_id: str
    arrival_ts: datetime
    ip: str
    method: str
    path: str
    route_template: str = UNMATCHED_ROUTE

    completed_ts: datetime | None = None
    response_origin: str | None = None
    upstream_outcome: str | None = None
    upstream_status: int | None = None
    upstream_duration_ms: int | None = None
    request_body_bytes: int | None = None
    auth_outcome: str | None = None

    @property
    def is_login(self) -> bool:
        """
        Arrival-derived on purpose. See spec.LOGIN_METHOD for why this does not
        read the completion record's loginAttempt flag.
        """
        return self.method == LOGIN_METHOD and self.route_template == LOGIN_ROUTE

    @property
    def has_backend_status(self) -> bool:
        """
        A status the backend chose, not one the gateway wrote about itself.

        Both halves are required. A 502 from an unreachable backend has
        origin gateway and no upstream status; a 413 from the body cap has a
        status the gateway wrote. Counting either as a backend response would
        mean enforcement changed the features of the address it enforced
        against.
        """
        return self.response_origin == ORIGIN_BACKEND and self.upstream_status is not None

    @property
    def timed_out(self) -> bool:
        return self.upstream_outcome == OUTCOME_TIMEOUT


def parse_ts(value: Any) -> datetime | None:
    """
    Go's RFC 3339 with nanoseconds, which fromisoformat rejects before 3.11 and
    still rejects for a trailing Z on some builds. Returns None rather than
    raising: one unparseable timestamp is a telemetry defect to be counted, not
    a reason to abandon a window.
    """
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Nanosecond precision: trim the fraction to microseconds, which is all a
    # datetime can hold. Truncating rather than rounding keeps a timestamp from
    # ever moving forward across a window boundary.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = ""
        while tail and tail[0].isdigit():
            digits, tail = digits + tail[0], tail[1:]
        text = f"{head}.{digits[:6]}{tail}" if digits else head + tail
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def arrival_from_json(obj: dict[str, Any]) -> RequestRecord | None:
    """Build the arrival half from one iasg:arrivals entry."""
    arrival_ts = parse_ts(obj.get("arrivalTs"))
    request_id = obj.get("requestId") or ""
    if arrival_ts is None or not request_id:
        return None
    return RequestRecord(
        request_id=request_id,
        arrival_ts=arrival_ts,
        ip=obj.get("ip") or "",
        method=obj.get("method") or "",
        # Not cleaned, not case-folded, trailing slash significant. An empty
        # path is a defect the quality metadata counts; it is not repaired
        # here, because a repaired defect is one nobody ever finds.
        path=obj.get("path") or "",
        route_template=obj.get("routeTemplate") or UNMATCHED_ROUTE,
    )


def completion_fields(obj: dict[str, Any]) -> dict[str, Any]:
    """The completion half of one iasg:events entry."""
    return {
        "completed_ts": parse_ts(obj.get("ts")),
        "response_origin": obj.get("responseOrigin"),
        "upstream_outcome": obj.get("upstreamOutcome") or None,
        "upstream_status": obj.get("upstreamStatus"),
        "upstream_duration_ms": obj.get("upstreamDurationMs"),
        "request_body_bytes": obj.get("requestBodyBytes"),
        "auth_outcome": obj.get("authOutcome") or None,
    }


def record_from_event(obj: dict[str, Any]) -> RequestRecord | None:
    """
    Build a whole record from a completion entry alone.

    The event carries arrivalTs too, so a completion whose arrival record was
    dropped is still usable. Without this a queue overflow would delete
    requests from the dataset entirely rather than degrading them, and the
    arrival queue overflows exactly during the traffic worth measuring.
    """
    arrival_ts = parse_ts(obj.get("arrivalTs"))
    request_id = obj.get("requestId") or ""
    if arrival_ts is None or not request_id:
        return None
    base = RequestRecord(
        request_id=request_id,
        arrival_ts=arrival_ts,
        ip=obj.get("ip") or "",
        method=obj.get("method") or "",
        path=obj.get("path") or "",
        route_template=obj.get("routeTemplate") or UNMATCHED_ROUTE,
    )
    return replace(base, **completion_fields(obj))


def join(
    arrivals: Iterable[dict[str, Any]], completions: Iterable[dict[str, Any]]
) -> list[RequestRecord]:
    """
    Join the two streams on requestId.

    A completion with no arrival is kept via record_from_event. An arrival with
    no completion is kept unsettled -- that is the in-flight case the arrival
    stream exists for, and dropping it would erase the request from its window.
    """
    records: dict[str, RequestRecord] = {}
    for obj in arrivals:
        rec = arrival_from_json(obj)
        if rec is not None:
            records[rec.request_id] = rec

    for obj in completions:
        request_id = obj.get("requestId") or ""
        existing = records.get(request_id)
        if existing is None:
            rec = record_from_event(obj)
            if rec is not None:
                records[rec.request_id] = rec
            continue
        # The arrival record wins on arrival-side fields. It was written before
        # anything in the chain could alter them, and it is the only one whose
        # timestamp is the instant the gateway first saw the request.
        records[request_id] = replace(existing, **completion_fields(obj))

    return list(records.values())
