from __future__ import annotations
import json
from dataclasses import dataclass,field
from datetime import datetime,timezone

DETECTOR_BRUTE_FORCE = "bruteforce"
DETECTOR_FLOOD = "flood"
DETECTOR_SQLI = "sqli"
DETECTOR_TRAVERSAL = "traversal"
DETECTOR_ENUMERATION = "enumeration"

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"

ACTION_MONITOR = "monitor"
ACTION_THROTTLE = "throttle"
ACTION_TEMP_BLOCK = "temp_block"
ACTION_ESCALATE = "escalate"

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _parse_timestamp(raw: str) -> datetime:
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
    # Whether a human has already been told about this one.
    alerted : bool = False

    explanation : str = ""
    assessment : str = ""

    signature : dict = field(default_factory=dict)


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
                "issued_at": self.issued_at.astimezone(timezone.utc).isoformat(),
                "expires_in": self.ttl_seconds,
            }
        )