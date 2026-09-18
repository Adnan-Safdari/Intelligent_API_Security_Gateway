from __future__ import annotations

import os
from dataclasses import dataclass, field

from iasg.adaptive.config import AdaptiveConfig, load_adaptive_config

def _env_int(name: str,default : int) -> int:
    """read an int from the environment , falling back if unset or unparsable"""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1","true","yes","on")


def _env_tuple(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """A comma-separated list, e.g. IASG_ALLOWLIST=10.0.0.0/8,203.0.113.9"""
    raw = os.getenv(name)
    if raw is None:
        return default
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    redis_url: str = "redis://localhost:6379/0"

    evidence_stream : str = "iasg:events"
    consumer_group :str = "iasg-agent"
    consumer_name : str = "agent-1"
    batch_size: int = 500

    interval_seconds : int = 30
    # Written at the end of every cycle and given a TTL of a few intervals, so
    # a console can tell a stopped agent from a quiet network.
    heartbeat_key : str = "iasg:heartbeat"
    # Epoch-ms of the last "clear campaigns" reset, if any. Evidence stream
    # entries whose own id (Redis stream ids are "<ms>-<seq>", already time-
    # ordered) predates this are acked -- so a crash-recovery replay or a
    # consumer that was behind can't reprocess them -- but never correlated,
    # so they can't recreate a campaign the operator just cleared. Absent or
    # unset means no reset has ever happened, so nothing is filtered.
    reset_watermark_key : str = "iasg:reset_at"
    # policy writing , and the rails that keep it safe
    policy_prefix : str = "policy:"
    max_ips_per_cycle : int = 50
    dry_run : bool = False

    # Addresses and ranges this system will never write policy for, whatever
    # the evidence says. Your own monitoring, health checks and office range.
    allowlist : tuple[str, ...] = ()
    # Ranges known to be shared by many people -- an office NAT, a campus
    # gateway, carrier-grade NAT. Never blocked outright, only slowed.
    shared_ranges : tuple[str, ...] = ()
    # Distinct user agents from one address before it is *suspected* of being
    # shared. Inferred rather than declared, so it only ever softens the
    # ambiguous cases -- see policy/simulation.py.
    shared_address_agents : int = 5

    # Human overrides, and what the agent remembers from them.
    override_stream : str = "iasg_overrides"
    override_group : str = "iasg-overrides"
    feedback_prefix : str = "feedback:"
    # Consistent overrides in one direction before the agent shifts its own
    # recommendation. Two so a single unusual call cannot retrain it.
    feedback_min_samples : int = 2

    llm_provider : str = "null"
    ollama_url : str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # How long one call may block. Narration runs inside the cycle, so a model
    # that hangs must give up well before the cycle is due to end.
    ollama_timeout_seconds : int = 15

    # Total wall-clock one cycle may spend on narration, across every campaign
    # and both agents. Once spent, the remaining campaigns fall back to their
    # templates rather than pushing the cycle past its interval: a late
    # decision is worse than an unnarrated one.
    narration_budget_seconds : int = 12

    postgres_url : str | None = None

    # The adaptive block is replaceable by a JSON value or JSON file through
    # IASG_ADAPTIVE_CONFIG.  A persisted dashboard value supersedes it at the
    # beginning of each cycle; this remains the validated boot/fallback value.
    adaptive: AdaptiveConfig = field(default_factory=AdaptiveConfig)

    # Separate groups let runtime windowing see clean traffic without changing
    # the evidence consumer's contract (which intentionally returns attacks).
    arrival_stream: str = "iasg:arrivals"
    health_stream: str = "iasg:telemetry:health"
    window_consumer_group: str = "iasg-windowing"
    window_consumer_name: str = "window-agent-1"
    window_completion_grace_seconds: int = 5

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            redis_url=os.getenv("IASG_REDIS_URL", cls.redis_url),
            evidence_stream=os.getenv("IASG_EVIDENCE_STREAM", cls.evidence_stream),
            consumer_group=os.getenv("IASG_CONSUMER_GROUP", cls.consumer_group),
            consumer_name=os.getenv("IASG_CONSUMER_NAME", cls.consumer_name),
            batch_size=_env_int("IASG_BATCH_SIZE", cls.batch_size),
            interval_seconds=_env_int("IASG_INTERVAL_SECONDS", cls.interval_seconds),
            heartbeat_key=os.getenv("IASG_HEARTBEAT_KEY", cls.heartbeat_key),
            reset_watermark_key=os.getenv("IASG_RESET_WATERMARK_KEY", cls.reset_watermark_key),
            policy_prefix=os.getenv("IASG_POLICY_PREFIX", cls.policy_prefix),
            max_ips_per_cycle=_env_int("IASG_MAX_IPS_PER_CYCLE", cls.max_ips_per_cycle),
            dry_run=_env_bool("IASG_DRY_RUN", cls.dry_run),
            allowlist=_env_tuple("IASG_ALLOWLIST", cls.allowlist),
            shared_ranges=_env_tuple("IASG_SHARED_RANGES", cls.shared_ranges),
            shared_address_agents=_env_int(
                "IASG_SHARED_ADDRESS_AGENTS", cls.shared_address_agents
            ),
            override_stream=os.getenv("IASG_OVERRIDE_STREAM", cls.override_stream),
            override_group=os.getenv("IASG_OVERRIDE_GROUP", cls.override_group),
            feedback_prefix=os.getenv("IASG_FEEDBACK_PREFIX", cls.feedback_prefix),
            feedback_min_samples=_env_int(
                "IASG_FEEDBACK_MIN_SAMPLES", cls.feedback_min_samples
            ),
            llm_provider=os.getenv("IASG_LLM_PROVIDER", cls.llm_provider),
            ollama_url=os.getenv("IASG_OLLAMA_URL", cls.ollama_url),
            ollama_model=os.getenv("IASG_OLLAMA_MODEL", cls.ollama_model),
            ollama_timeout_seconds=_env_int(
                "IASG_OLLAMA_TIMEOUT_SECONDS", cls.ollama_timeout_seconds
            ),
            narration_budget_seconds=_env_int(
                "IASG_NARRATION_BUDGET_SECONDS", cls.narration_budget_seconds
            ),
            postgres_url=os.getenv("IASG_POSTGRES_URL"),
            adaptive=load_adaptive_config(os.getenv("IASG_ADAPTIVE_CONFIG")),
            arrival_stream=os.getenv("IASG_ARRIVAL_STREAM", cls.arrival_stream),
            health_stream=os.getenv("IASG_HEALTH_STREAM", cls.health_stream),
            window_consumer_group=os.getenv(
                "IASG_WINDOW_CONSUMER_GROUP", cls.window_consumer_group
            ),
            window_consumer_name=os.getenv(
                "IASG_WINDOW_CONSUMER_NAME", cls.window_consumer_name
            ),
            window_completion_grace_seconds=_env_int(
                "IASG_WINDOW_COMPLETION_GRACE_SECONDS",
                cls.window_completion_grace_seconds,
            ),
        )

