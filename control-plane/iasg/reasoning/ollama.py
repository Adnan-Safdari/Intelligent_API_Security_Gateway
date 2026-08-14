"""
Ollama, over its local HTTP API.

Uses urllib from the standard library so the project gains no dependency for
a feature that is off by default. Enable with IASG_LLM_PROVIDER=ollama once
`ollama serve` is running and a model has been pulled.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 30


class OllamaProvider:
    name = "ollama"

    def __init__(self, url: str, model: str) -> None:
        self._url = url.rstrip("/")
        self._model = model

    def generate(self, system: str, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self._model,
                "system": system,
                "prompt": prompt,
                "stream": False,
                # Low temperature: this is a report, not creative writing.
                "options": {"temperature": 0.2},
            }
        ).encode()

        request = urllib.request.Request(
            f"{self._url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                body = json.loads(response.read())
            return str(body.get("response", "")).strip()
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as err:
            # Never fail a cycle over narration.
            print(f"[llm] ollama unavailable ({err}); falling back to template")
            return ""
