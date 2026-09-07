"""
What a session sends, as data rather than as calls.

A persona is a plan -- a list of (offset, request) -- built before anything is
sent. That makes the traffic reproducible from a seed, lets a plan be checked
against the features it is supposed to teach without a gateway running, and
keeps the timing decisions in one place instead of scattered through sleep
calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Request:
    method: str = "GET"
    path: str = "/api/products"
    body: dict | None = None

    @property
    def route_template(self) -> str:
        """
        What configs/config.yaml's routes: block will match this to.

        Duplicated from the gateway on purpose and only for offline checking of
        a plan -- the dataset always uses the routeTemplate the gateway
        recorded, never this. A copy that drifted would make a test agree with
        itself while the real matcher did something else.
        """
        path = self.path.split("?", 1)[0]
        for template in (
            "/api/health", "/api/login", "/api/products/search-secure",
            "/api/products/search", "/api/products", "/api/demo-files",
            "/backup-demo", "/config-demo", "/.env-demo",
        ):
            if path == template:
                return template
        if path.startswith("/api/products/"):
            return "/api/products/{id}"
        return "<unmatched>"


@dataclass(frozen=True)
class Step:
    """One request, at a fixed offset from the session's start."""

    offset: float
    request: Request


@dataclass
class Plan:
    """One session: an address, a persona name, and what it sends."""

    name: str
    steps: list[Step] = field(default_factory=list)

    def at(self, offset: float, request: Request) -> "Plan":
        self.steps.append(Step(offset, request))
        return self

    @property
    def duration(self) -> float:
        return max((s.offset for s in self.steps), default=0.0)

    def __len__(self) -> int:
        return len(self.steps)
