from __future__ import annotations
import json
from dataclasses import dataclass,field
from datetime import datetime,timezone

DETECTOR_BRUTE_FORCE = "bruteforce"
DETECTOR_FLOOD = "flood"
DETECTOR_SQLI = "sqli"
DETECTOR_TRAVERSAL = "traversal"
DETECTOR_ENUMERATION = "enumeration"

# The phase of an intrusion each detector belongs to. Several detectors can
# describe the same phase -- guessing filenames and climbing out of a directory
# are both someone looking around -- so phases are coarser than detectors, and
# a campaign only counts as staged when genuinely different ones appear.
STAGE_RECON = "reconnaissance"
STAGE_CREDENTIAL = "credential attack"
STAGE_INJECTION = "injection"
STAGE_ABUSE = "abuse"

STAGE_OF = {
    DETECTOR_ENUMERATION: STAGE_RECON,
    DETECTOR_TRAVERSAL: STAGE_RECON,
    DETECTOR_BRUTE_FORCE: STAGE_CREDENTIAL,
    DETECTOR_SQLI: STAGE_INJECTION,
    DETECTOR_FLOOD: STAGE_ABUSE,
}

# Go iasg:events signal names -> this agent's detector names.
SIGNAL_TO_DETECTOR = {
    "api_flooding": DETECTOR_FLOOD,
    "sql_injection": DETECTOR_SQLI,
    "brute_force": DETECTOR_BRUTE_FORCE,
    "password_spraying": DETECTOR_BRUTE_FORCE,
    "path_traversal": DETECTOR_TRAVERSAL,
    "enumeration": DETECTOR_ENUMERATION,
}

DETECTOR_TO_SIGNAL = {
    DETECTOR_BRUTE_FORCE: "brute_force",
    DETECTOR_FLOOD: "api_flooding",
    DETECTOR_SQLI: "sql_injection",
    DETECTOR_TRAVERSAL: "enumeration_path_traversal",
    DETECTOR_ENUMERATION: "enumeration_path_traversal",
}

# What a campaign is called once it spans more than one phase.
CAMPAIGN_MULTI_STAGE = "Multi-Stage Intrusion"

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"

ACTION_MONITOR = "monitor"
ACTION_THROTTLE = "throttle"
ACTION_TEMP_BLOCK = "temp_block"
ACTION_ESCALATE = "escalate"

# The ladder, weakest first. The order is meaningful: a campaign that survives
# enforcement is promoted one rung along it.
ACTION_LADDER = (ACTION_MONITOR, ACTION_THROTTLE, ACTION_TEMP_BLOCK, ACTION_ESCALATE)

# Actions that actually restrain traffic. Monitor is deliberately excluded --
# a monitored campaign carrying on says nothing about whether enforcement
# works, because nothing was enforced.
ENFORCEMENT_ACTIONS = frozenset({ACTION_THROTTLE, ACTION_TEMP_BLOCK, ACTION_ESCALATE})

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _parse_timestamp(raw: str) -> datetime:
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return _now()


@dataclass
class Evidence:
    """
    One detector observation. Delibrately carries NO Verdict.
    """
    timestamp :datetime #when it happend
    ip:str              #who did it
    endpoint:str        #what they hit
    detector:str        #which detector saw it
    severity:str        #"low"/"medium"/"high"

    method : str = ""
    user_agent: str = ""

    details : dict = field(default_factory=dict)

    stream_id : str = ""

    @classmethod
    def from_stream_fields(cls,stream_id: str, fields : dict[str,str]) -> "Evidence":
        """
        Build an Evidence from one Redis entry.

        THIS IS THE IMPORTANT METHOD IN THIS FILE.

        Redis has no types -- everything you read back is text. failedLogins
        comes back as the string "12", not the number 12. All that messy
        conversion lives here, once, instead of being repeated inside every
        agent (where each one would get it slightly wrong).
        """
        raw_details = fields.get("details","")
        try:
            details = json.loads(raw_details) if raw_details else {}
        except json.JSONDecodeError:
            details = {}

        return cls(
            timestamp=_parse_timestamp(fields.get("timestamp", "")),
            ip=fields.get("ip", ""),
            endpoint=fields.get("endpoint", ""),
            detector=fields.get("detector", ""),
            severity=fields.get("severity", SEVERITY_LOW),
            method=fields.get("method", ""),
            user_agent=fields.get("userAgent", ""),
            details=details,
            stream_id=stream_id,
        )

    @classmethod
    def from_stream_entry(cls, stream_id: str, fields: dict[str, str]) -> list["Evidence"]:
        """Parse one Redis stream entry into zero or more Evidence records.

        The gateway writes JSON telemetry on iasg:events (field ``event``),
        one request per entry. Fired signals become one Evidence each; clean
        requests are skipped. The seeder and older tests still use the flat
        detector/endpoint fields, which this also accepts.
        """
        raw_event = fields.get("event")
        if raw_event:
            return cls._from_telemetry(stream_id, raw_event)

        if fields.get("detector") and fields.get("ip"):
            return [cls.from_stream_fields(stream_id, fields)]
        return []

    @classmethod
    def _from_telemetry(cls, stream_id: str, raw_event: str | dict) -> list["Evidence"]:
        try:
            event = json.loads(raw_event) if isinstance(raw_event, str) else raw_event
        except json.JSONDecodeError:
            return []
        if not isinstance(event, dict):
            return []

        fired = [name for name in (event.get("fired") or []) if name]
        if not fired:
            return []

        signals = {
            row.get("signal"): row
            for row in (event.get("signals") or [])
            if isinstance(row, dict) and row.get("signal")
        }

        found: list[Evidence] = []
        for name in fired:
            for detector, signal in _detectors_for_signal(name, signals.get(name) or {}):
                details = dict(signal.get("details") or {})
                if signal.get("attackType") and "attackType" not in details:
                    details["attackType"] = signal["attackType"]
                if event.get("riskScore") is not None:
                    details.setdefault("riskScore", event["riskScore"])
                found.append(
                    cls(
                        timestamp=_parse_timestamp(str(event.get("ts", ""))),
                        ip=str(event.get("ip") or ""),
                        endpoint=str(event.get("path") or ""),
                        detector=detector,
                        severity=_severity_from_score(signal.get("score")),
                        method=str(event.get("method") or ""),
                        user_agent=str(event.get("userAgent") or ""),
                        details=details,
                        stream_id=stream_id,
                    )
                )
        return found

    def to_stream_fields(self) -> dict[str,str]:
        """
        The reverse: turn Evidence into text fields Redis can store.
        Used by the fake-attack generator and by the real gateway log reader.
        """
        return {
            "timestamp" : self.timestamp.astimezone(timezone.utc).isoformat(),
            "ip" : self.ip,
            "endpoint" : self.endpoint,
            "detector" : self.detector,
            "severity" : self.severity,
            "method"   : self.method,
            "userAgent": self.user_agent,
            "details" : json.dumps(self.details),
        }

    def to_telemetry_fields(self) -> dict[str, str]:
        """Shape one Evidence as a gateway iasg:events entry so the seeder
        feeds both the agent and the dashboard."""
        signal = DETECTOR_TO_SIGNAL.get(self.detector, self.detector)
        details = dict(self.details)
        attack_type = str(details.get("attackType") or "")
        if self.detector == DETECTOR_TRAVERSAL:
            details.setdefault("pathTraversalDetected", True)
            details.setdefault("enumerationDetected", False)
            attack_type = attack_type or "path_traversal"
        elif self.detector == DETECTOR_ENUMERATION:
            details.setdefault("pathTraversalDetected", False)
            details.setdefault("enumerationDetected", True)
            attack_type = attack_type or "enumeration"

        score = 80 if self.severity == SEVERITY_HIGH else 50 if self.severity == SEVERITY_MEDIUM else 20
        event = {
            "requestId": self.stream_id or "",
            "ts": self.timestamp.astimezone(timezone.utc).isoformat(),
            "ip": self.ip,
            "method": self.method,
            "path": self.endpoint,
            "status": 401 if self.detector == DETECTOR_BRUTE_FORCE else 200,
            "userAgent": self.user_agent,
            "decision": "allow",
            "riskScore": score,
            "fired": [signal],
            "signals": [
                {
                    "signal": signal,
                    "score": score,
                    "thresholdCross": True,
                    "attackType": attack_type or self.detector,
                    "details": details,
                }
            ],
        }
        return {
            "event": json.dumps(event),
            "ip": self.ip,
            "path": self.endpoint,
            "decision": "allow",
            "riskScore": str(score),
            "fired": signal,
        }


def _severity_from_score(score) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return SEVERITY_MEDIUM
    if value >= 70:
        return SEVERITY_HIGH
    if value >= 30:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _detectors_for_signal(name: str, signal: dict) -> list[tuple[str, dict]]:
    if name == "enumeration_path_traversal":
        details = signal.get("details") or {}
        attack = str(signal.get("attackType") or "")
        traversal = bool(details.get("pathTraversalDetected")) or "path_traversal" in attack
        enumeration = bool(details.get("enumerationDetected")) or attack == "enumeration" or attack.endswith("+enumeration")
        rows: list[tuple[str, dict]] = []
        if traversal:
            rows.append((DETECTOR_TRAVERSAL, signal))
        if enumeration:
            rows.append((DETECTOR_ENUMERATION, signal))
        if not rows:
            rows.append((DETECTOR_TRAVERSAL, signal))
        return rows

    detector = SIGNAL_TO_DETECTOR.get(name)
    if not detector:
        return []
    return [(detector, signal)]

@dataclass
class Campaign:
    """
    The Correlation Agent's output. Matches section 13.1 of the proposal.

    This is the whole point of the project: turning six separate "IP X failed
    logins" events into one "these six IPs are running a credential stuffing
    campaign against /api/login".
    """

    campaign_id: str
    type: str
    confidence : float
    ips: list[str]
    reason: str
    severity : str

    first_seen : datetime = field(default_factory=_now)
    last_seen  : datetime = field(default_factory=_now)
    event_count : int = 0

    # How the campaign is going, updated each cycle by the repository's review.
    # "active"    still producing evidence
    # "contained" nothing further since we acted
    status : str = "active"
    quiet_cycles : int = 0
    last_action : str = ""
    outcome : str = ""
    # How many times this campaign was re-identified after the attacker moved
    # to addresses we had never seen. Evidence that tracking survived a rotation.
    rotations : int = 0
    # How many times this campaign came back after we enforced against it, by
    # waiting the policy out or by moving. This is the honest measure of
    # enforcement failing, and it is what pushes the next action up the ladder.
    persistence : int = 0
    # Whether a human has already been told about this one.
    alerted : bool = False

    explanation : str = ""
    assessment : str = ""

    signature : dict = field(default_factory=dict)
    # Intrusion phases seen from this campaign, earliest first. More than one
    # means the actor moved on rather than repeating itself, which is worse
    # than any single phase and is what the policy ladder reacts to.
    stages : list = field(default_factory=list)


@dataclass
class PolicyDecision:
    """
    The Policy Agent's output for a single IP.

    This is the ONLY thing in the whole control plane that can influence the
    gateway. Everything else just produces information.
    """
    ip : str
    action : str
    campaign_id : str
    confidence : float
    ttl_seconds : int
    reason: str = ""
    # Requests per minute this address is allowed while the policy stands.
    # Only meaningful for "throttle": it is what makes the rate limiting
    # adaptive rather than a fixed slowdown applied to everyone alike.
    # Zero means "no rate named", and the gateway falls back to its configured
    # throttle behaviour -- which is also what an older control plane produces,
    # so a policy written before this field existed still enforces.
    requests_per_minute : int = 0
    # "agent" or "human". Decides whose judgement the safety checks defer to:
    # a person outranks the agent's guesses, but not the operator's declared
    # configuration. See policy/simulation.py.
    source : str = "agent"
    issued_at : datetime = field(default_factory=_now)

    def to_json(self) -> str:
        """
        Exactly what gets stored at policy:<ip> in Redis.

        The Go gateway will one day read this key and act on it. Keeping the
        shape here means there's a single definition of that contract.
        """
        return json.dumps(
            {
                "action": self.action,
                "campaign_id": self.campaign_id,
                "confidence": round(self.confidence, 3),
                "reason": self.reason,
                "source": self.source,
                "issued_at": self.issued_at.astimezone(timezone.utc).isoformat(),
                "expires_in": self.ttl_seconds,
                "requests_per_minute": self.requests_per_minute,
            }
        )