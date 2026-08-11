"""Parsing the gateway's printed SECURITY ALERT blocks."""

from __future__ import annotations

from iasg.evidence.ingest import parse

BRUTE_FORCE = """
------ Incoming Request ------
Method: POST

			========================================
			SECURITY ALERT: BRUTE FORCE DETECTED
			----------------------------------------
			IP Address     : 203.0.113.5
			Endpoint       : /api/login
			Failed Logins  : 12
			Distinct Users : 5
			Attack Type    : PASSWORD SPRAYING (multiple accounts)
			Time Window    : 1m0s
			User-Agent     : curl/8.4.0
			Severity       : HIGH
			Timestamp      : 2026-08-11T12:31:00+05:30
			ACTION         : DETECTED (ALLOWING REQUEST)
			========================================
""".splitlines()

FLOOD = """
			========================================
			SECURITY ALERT: API FLOOD DETECTED
			----------------------------------------
			IP Address     : 198.51.100.7
			Endpoint       : /api/products
			Requests       : 480
			Time Window    : 1m0s
			User-Agent     : python-requests/2.32
			Severity       : HIGH
			Timestamp      : 2026-08-11T12:35:00+05:30
			ACTION         : DETECTED (ALLOWING REQUEST)
			========================================
""".splitlines()


def test_parses_brute_force_alert():
    (ev,) = parse(BRUTE_FORCE)
    assert ev.ip == "203.0.113.5"
    assert ev.detector == "bruteforce"
    assert ev.endpoint == "/api/login"
    assert ev.severity == "high"
    assert ev.user_agent == "curl/8.4.0"
    assert ev.details["failedLogins"] == 12
    assert ev.details["distinctUsers"] == 5


def test_parses_flood_alert():
    (ev,) = parse(FLOOD)
    assert ev.detector == "flood"
    assert ev.details["requestCount"] == 480


def test_parses_multiple_blocks_in_one_stream():
    assert len(parse(BRUTE_FORCE + FLOOD)) == 2


def test_ordinary_log_lines_are_ignored():
    noise = [
        "------ Incoming Request ------",
        "Method: GET",
        "Path: /api/products",
        "IP: 10.0.0.1",
    ]
    assert parse(noise) == []


def test_unknown_alert_type_is_skipped():
    block = [
        "SECURITY ALERT: SOMETHING NEW DETECTED",
        "----------------------------------------",
        "IP Address     : 203.0.113.5",
        "========================================",
    ]
    assert parse(block) == []


def test_alert_without_ip_is_skipped():
    block = [
        "SECURITY ALERT: BRUTE FORCE DETECTED",
        "----------------------------------------",
        "Endpoint       : /api/login",
        "========================================",
    ]
    assert parse(block) == []


def test_round_trips_through_stream_fields():
    """Parsed evidence must survive the trip through Redis."""
    from iasg.models import Evidence

    (ev,) = parse(BRUTE_FORCE)
    back = Evidence.from_stream_fields("1-1", ev.to_stream_fields())
    assert back.ip == ev.ip
    assert back.details["failedLogins"] == 12
