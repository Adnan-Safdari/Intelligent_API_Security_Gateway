"""
Sending a plan, with the identity the gateway will believe.

Stdlib only. urllib is enough for this and avoids adding a dependency to a
harness whose whole job is to be reproducible.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from testing.traffic.plan import Plan, Request

REQUEST_ID_HEADER = "X-Request-ID"


@dataclass
class Sent:
    """
    What one request turned into.

    request_id comes from the response header, so it is an exact join into
    telemetry that never passes through detector output. Matching on
    (ip, path, approximate time) would be a guess, and a wrong join is a
    mislabelled row nobody can find.
    """

    request_id: str
    method: str
    path: str
    status: int
    at: float


@dataclass
class Session:
    ip: str
    persona: str
    sent: list[Sent] = field(default_factory=list)


class Client:
    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def send(self, ip: str, request: Request) -> Sent:
        data = None
        headers = {
            # The gateway believes this only from a trusted proxy, which is
            # what preflight checks before any of this runs.
            "X-Forwarded-For": ip,
            "User-Agent": "iasg-traffic/1.0",
        }
        if request.body is not None:
            data = json.dumps(request.body).encode()
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            self._base + request.path, data=data, headers=headers, method=request.method
        )
        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as response:
                return Sent(
                    request_id=response.headers.get(REQUEST_ID_HEADER, ""),
                    method=request.method, path=request.path,
                    status=response.status, at=started,
                )
        except urllib.error.HTTPError as err:
            # A 401, 404 or 403 is an outcome, not a failure. Most of this
            # harness's traffic is supposed to be refused by something.
            return Sent(
                request_id=err.headers.get(REQUEST_ID_HEADER, "") if err.headers else "",
                method=request.method, path=request.path, status=err.code, at=started,
            )
        except Exception:
            # A connection that never completed. Recorded with status 0 rather
            # than dropped, so a run that half failed says so.
            return Sent(request_id="", method=request.method, path=request.path,
                        status=0, at=started)


def run_plan(client: Client, ip: str, plan: Plan, start: float | None = None) -> Session:
    """
    Send a plan on its own schedule.

    Offsets are absolute from the session's start, not cumulative sleeps, so a
    slow response does not push every later request back and quietly change the
    timing the persona exists to demonstrate.
    """
    session = Session(ip=ip, persona=plan.name)
    start = start if start is not None else time.time()
    for step in plan.steps:
        delay = start + step.offset - time.time()
        if delay > 0:
            time.sleep(delay)
        session.sent.append(client.send(ip, step.request))
    return session


def run_concurrently(client: Client, assignments: list[tuple[str, Plan]]) -> list[Session]:
    """
    All sessions at once, sharing one clock.

    Concurrency is the point rather than an optimisation: personas overlapping
    in real time is what makes windows contain several clients, which is what
    the gateway will actually see.
    """
    start = time.time()
    sessions: list[Session] = []
    lock = threading.Lock()

    def worker(ip: str, plan: Plan) -> None:
        session = run_plan(client, ip, plan, start)
        with lock:
            sessions.append(session)

    threads = [threading.Thread(target=worker, args=(ip, plan), daemon=True)
               for ip, plan in assignments]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return sessions
