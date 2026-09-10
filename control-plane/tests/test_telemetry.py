"""Gateway iasg:events JSON must become typed Evidence, including split traversal/enum."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from iasg.models import (
    DETECTOR_BRUTE_FORCE,
    DETECTOR_ENUMERATION,
    DETECTOR_FLOOD,
    DETECTOR_TRAVERSAL,
    DETECTOR_UNKNOWN_ROUTE_SCAN,
    Evidence,
)


def test_clean_telemetry_is_ignored():
    event = {
        "ts": "2026-08-14T10:00:00Z",
        "ip": "203.0.113.5",
        "method": "GET",
        "path": "/api/products",
        "fired": [],
        "signals": [],
        "riskScore": 0,
    }
    assert Evidence.from_stream_entry("1-0", {"event": json.dumps(event)}) == []


def test_flood_signal_maps_to_flood_detector():
    event = {
        "ts": "2026-08-14T10:00:00+00:00",
        "ip": "198.51.100.7",
        "method": "GET",
        "path": "/api/products",
        "userAgent": "curl/8.4",
        "fired": ["api_flooding"],
        "riskScore": 80,
        "signals": [
            {
                "signal": "api_flooding",
                "score": 80,
                "thresholdCross": True,
                "attackType": "api_flooding",
                "details": {"requestRate": 120, "threshold": 100},
            }
        ],
    }

    got = Evidence.from_stream_entry("9-0", {"event": json.dumps(event)})

    assert len(got) == 1
    assert got[0].detector == DETECTOR_FLOOD
    assert got[0].ip == "198.51.100.7"
    assert got[0].endpoint == "/api/products"
    assert got[0].details["requestRate"] == 120
    assert got[0].stream_id == "9-0"
    assert got[0].timestamp == datetime(2026, 8, 14, 10, 0, tzinfo=timezone.utc)


def test_enumeration_path_traversal_splits_both_phases():
    event = {
        "ts": "2026-08-14T10:00:00Z",
        "ip": "203.0.113.9",
        "path": "/.git",
        "fired": ["enumeration_path_traversal"],
        "signals": [
            {
                "signal": "enumeration_path_traversal",
                "score": 100,
                "attackType": "path_traversal+enumeration",
                "details": {
                    "pathTraversalDetected": True,
                    "enumerationDetected": True,
                },
            }
        ],
    }

    got = Evidence.from_stream_entry("2-0", {"event": json.dumps(event)})
    assert {e.detector for e in got} == {DETECTOR_TRAVERSAL, DETECTOR_ENUMERATION}
    assert all(e.stream_id == "2-0" for e in got)


def test_seeder_telemetry_round_trips():
    original = Evidence(
        timestamp=datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc),
        ip="203.0.113.5",
        endpoint="/api/login",
        detector=DETECTOR_BRUTE_FORCE,
        severity="high",
        method="POST",
        user_agent="curl/8.4.0",
        details={"failedLogins": 9},
    )

    got = Evidence.from_stream_entry("3-0", original.to_telemetry_fields())
    assert len(got) == 1
    assert got[0].detector == DETECTOR_BRUTE_FORCE
    assert got[0].details["failedLogins"] == 9


def test_unknown_route_scan_maps_to_reconnaissance_evidence():
    event = {
        "ts": "2026-08-14T10:00:00Z",
        "ip": "203.0.113.6",
        "method": "GET",
        "path": "/admin",
        "fired": ["unknown_route_scanning"],
        "signals": [{
            "signal": "unknown_route_scanning",
            "score": 60,
            "thresholdCross": True,
            "attackType": "unknown_route_scanning",
            "details": {"distinctPaths": 8, "window": "5m0s"},
        }],
    }

    got = Evidence.from_stream_entry("4-0", {"event": json.dumps(event)})
    assert len(got) == 1
    assert got[0].detector == DETECTOR_UNKNOWN_ROUTE_SCAN
    assert got[0].details["distinctPaths"] == 8


def test_flat_fields_still_parse():
    got = Evidence.from_stream_entry(
        "4-0",
        {
            "timestamp": "2026-08-14T10:00:00+00:00",
            "ip": "203.0.113.1",
            "endpoint": "/api/login",
            "detector": "bruteforce",
            "severity": "high",
            "method": "POST",
            "userAgent": "curl/8.4",
            "details": '{"failedLogins": 9}',
        },
    )
    assert len(got) == 1
    assert got[0].detector == "bruteforce"
    assert got[0].details["failedLogins"] == 9
