"""LLM providers. Text generation only -- never decisions."""

from __future__ import annotations

from iasg.config import Settings
from iasg.reasoning.null import NullProvider
from iasg.reasoning.ollama import OllamaProvider
from iasg.reasoning.provider import LLMProvider

__all__ = ["LLMProvider", "NullProvider", "OllamaProvider", "open_provider"]


def open_provider(settings: Settings) -> LLMProvider:
    if settings.llm_provider == "ollama":
        return OllamaProvider(settings.ollama_url, settings.ollama_model)
    return NullProvider()
