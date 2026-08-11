"""
Reads the gateway's printed SECURITY ALERT blocks into the evidence stream.

The Go gateway is not modified, so its detections only reach stdout. Piping
that output through here puts them in Redis:

    cd gateway && go run ./cmd/server 2>&1 | python -m iasg.evidence.ingest

All four detectors print the same "Key : Value" block, so one parser covers
every one of them.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone

from iasg.config import Settings
from iasg.models import (
    DETECTOR_BRUTE_FORCE,
    DETECTOR_ENUMERATION,
    DETECTOR_FLOOD,
    DETECTOR_SQLI,
    DETECTOR_TRAVERSAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    Evidence,
)
from iasg.store import open_store

ALERT_START = re.compile(r"SECURITY ALERT:\s*(.+?)\s*(?:DETECTED)?\s*$")
FIELD = re.compile(r"^\s*([A-Za-z][A-Za-z ./-]*?)\s*:\s*(.*?)\s*$")
RULE = re.compile(r"^\s*[=-]{5,}\s*$")

# The alert headline -> which detector produced it.
DETECTORS = {
    "BRUTE FORCE": DETECTOR_BRUTE_FORCE,
    "API FLOOD": DETECTOR_FLOOD,
    "SQL INJECTION": DETECTOR_SQLI,
    "PATH TRAVERSAL": DETECTOR_TRAVERSAL,
    "ENUMERATION ATTACK": DETECTOR_ENUMERATION,
}


def detector_for(headline: str) -> str:
    upper = headline.upper()
    for label, detector in DETECTORS.items():
        if label in upper:
            return detector
    return ""


def to_evidence(headline: str, fields: dict[str, str]) -> Evidence | None:
    """Build Evidence from one parsed alert block."""
    detector = detector_for(headline)
    ip = fields.get("IP Address", "")
    if not detector or not ip:
        return None

    severity = fields.get("Severity", "").strip().lower() or SEVERITY_MEDIUM
    if severity not in (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH):
        severity = SEVERITY_MEDIUM

    details: dict[str, object] = {}
    for source, key in (
        ("Failed Logins", "failedLogins"),
        ("Distinct Users", "distinctUsers"),
        ("Requests", "requestCount"),
    ):
        if source in fields:
            try:
                details[key] = int(fields[source])
            except ValueError:
                pass
    for source, key in (
        ("Attack Type", "attackType"),
        ("Details", "matchedPattern"),
        ("Time Window", "window"),
    ):
        if fields.get(source):
            details[key] = fields[source]

    return Evidence(
        timestamp=_parse_time(fields.get("Timestamp", "")),
        ip=ip,
        endpoint=fields.get("Endpoint", ""),
        method=fields.get("Method", ""),
        detector=detector,
        severity=severity,
        user_agent=fields.get("User-Agent", ""),
        details=details,
    )


def parse(lines) -> list[Evidence]:
    """Pull every alert block out of a stream of log lines."""
    found: list[Evidence] = []
    headline: str | None = None
    fields: dict[str, str] = {}

    for raw in lines:
        line = raw.rstrip("\n")

        match = ALERT_START.search(line)
        if match:
            headline, fields = match.group(1), {}
            continue

        if headline is None:
            continue

        if RULE.match(line):
            # A block ends at its closing rule. The opening one leaves fields empty.
            if fields:
                evidence = to_evidence(headline, fields)
                if evidence:
                    found.append(evidence)
                headline, fields = None, {}
            continue

        field_match = FIELD.match(line)
        if field_match:
            fields[field_match.group(1).strip()] = field_match.group(2).strip()

    return found


def _parse_time(raw: str) -> datetime:
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(timezone.utc)


def main() -> None:
    settings = Settings.from_env()
    store = open_store(settings)
    count = 0

    headline: str | None = None
    fields: dict[str, str] = {}

    # Line by line rather than reading everything, so a long-running gateway
    # streams into Redis instead of buffering until it exits.
    for raw in sys.stdin:
        print(raw, end="")  # keep the gateway's own output visible

        line = raw.rstrip("\n")
        match = ALERT_START.search(line)
        if match:
            headline, fields = match.group(1), {}
            continue
        if headline is None:
            continue

        if RULE.match(line):
            if fields:
                evidence = to_evidence(headline, fields)
                if evidence:
                    store.append(settings.evidence_stream, evidence.to_stream_fields())
                    count += 1
                    print(f"[ingest] -> {evidence.detector} {evidence.ip} ({count} total)")
                headline, fields = None, {}
            continue

        field_match = FIELD.match(line)
        if field_match:
            fields[field_match.group(1).strip()] = field_match.group(2).strip()

    store.close()


if __name__ == "__main__":
    main()
