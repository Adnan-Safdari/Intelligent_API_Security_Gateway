from __future__ import annotations

import os
from dataclasses import dataclass

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


@dataclass(frozen=True)
class Settings:
    redis_url: str = "redis://localhost:6379/0"

    evidence_stream : str = "attack_events"
    consumer_group :str = "iasg-agent"
    consumer_name : str = "agent-1"
    batch_size: int = 500

    interval_seconds : int = 30
    # policy writing , and the rails that keep it safe
    policy_prefix : str = "policy:"
    max_ips_per_cycle : int = 50
    dry_run : bool = False

    llm_provider : str = "null"
    ollama_url : str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    postgres_url : str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            redis_url=os.getenv("IASG_REDIS_URL", cls.redis_url),
            evidence_stream=os.getenv("IASG_EVIDENCE_STREAM", cls.evidence_stream),
            consumer_group=os.getenv("IASG_CONSUMER_GROUP", cls.consumer_group),
            consumer_name=os.getenv("IASG_CONSUMER_NAME", cls.consumer_name),
            batch_size=_env_int("IASG_BATCH_SIZE", cls.batch_size),
            interval_seconds=_env_int("IASG_INTERVAL_SECONDS", cls.interval_seconds),
            policy_prefix=os.getenv("IASG_POLICY_PREFIX", cls.policy_prefix),
            max_ips_per_cycle=_env_int("IASG_MAX_IPS_PER_CYCLE", cls.max_ips_per_cycle),
            dry_run=_env_bool("IASG_DRY_RUN", cls.dry_run),
            llm_provider=os.getenv("IASG_LLM_PROVIDER", cls.llm_provider),
            ollama_url=os.getenv("IASG_OLLAMA_URL", cls.ollama_url),
            ollama_model=os.getenv("IASG_OLLAMA_MODEL", cls.ollama_model),
            postgres_url=os.getenv("IASG_POSTGRES_URL"),
        )

