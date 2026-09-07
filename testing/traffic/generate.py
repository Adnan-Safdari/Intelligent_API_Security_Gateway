"""
Drive one run: plan it, prove the identities, send it, and write the labels.

Order matters. attacks.jsonl is written from the plan, before traffic starts,
which is what makes labels independent of anything the detectors decide later.
If it were written afterwards from what was observed, the label would be a
second opinion about the traffic rather than a record of what was launched.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from testing.traffic import attacks as attack_lib
from testing.traffic import personas as persona_lib
from testing.traffic.client import Client, run_concurrently
from testing.traffic.identity import (
    IP_LATEST,
    observed_addresses,
    preflight,
    require_trusted_identity,
)
from testing.traffic.plan import Plan
from testing.traffic.pools import ATTACKERS, BENIGN, RESERVED, Pool, session_id


@dataclass(frozen=True)
class Assignment:
    ip: str
    kind: str  # "benign" or "attack"
    name: str
    plan: Plan


def plan_run(
    seed: int,
    benign_per_persona: int = 2,
    seconds: float = 180.0,
    include_reserved: bool = True,
) -> list[Assignment]:
    """
    Decide every session before anything is sent.

    One address per session, taken from a pool that raises rather than reusing:
    two sessions sharing an address would merge into one group key with nothing
    in the data able to separate them again.
    """
    rng = random.Random(seed)
    benign_pool, attack_pool, reserved_pool = Pool(BENIGN), Pool(ATTACKERS), Pool(RESERVED)
    assignments: list[Assignment] = []

    for name, build in persona_lib.PERSONAS.items():
        for _ in range(benign_per_persona):
            assignments.append(
                Assignment(benign_pool.take(), "benign", name,
                           build(random.Random(rng.random()), seconds))
            )

    for name in attack_lib.TUNABLE:
        assignments.append(
            Assignment(attack_pool.take(), "attack", name,
                       attack_lib.SCENARIOS[name](random.Random(rng.random()), seconds))
        )

    if include_reserved:
        for name in attack_lib.RESERVED:
            # From the reserved address pool, so a held-out scenario can never
            # share a group key with a tunable one -- that would put the same
            # key on both sides of the split.
            assignments.append(
                Assignment(reserved_pool.take(), "attack", name,
                           attack_lib.SCENARIOS[name](random.Random(rng.random()), seconds))
            )

    return assignments


def write_labels(
    out: Path, run_id: str, assignments: list[Assignment], started: datetime
) -> None:
    """
    attacks.jsonl and sessions.jsonl, from the plan.

    Intervals are the plan's own extent, padded by one window on each side.
    An attack's first and last requests land in windows that are only partly
    covered, and labelling those benign would train the model that the start of
    an attack is normal -- which is the moment detection matters most.
    """
    attacks, sessions = [], []
    for item in assignments:
        sessions.append({
            "run_id": run_id,
            "session_id": session_id(run_id, item.ip),
            "ip": item.ip,
            "kind": item.kind,
            "name": item.name,
            "requests": len(item.plan),
        })
        if item.kind != "attack":
            continue
        first = min((s.offset for s in item.plan.steps), default=0.0)
        last = max((s.offset for s in item.plan.steps), default=0.0)
        attacks.append({
            "scenario": item.name,
            "ip": item.ip,
            "start": (started + timedelta(seconds=first)).isoformat(),
            "end": (started + timedelta(seconds=last)).isoformat(),
        })

    out.mkdir(parents=True, exist_ok=True)
    (out / "attacks.jsonl").write_text("".join(json.dumps(a) + "\n" for a in attacks))
    (out / "sessions.jsonl").write_text("".join(json.dumps(s) + "\n" for s in sessions))


def coverage(assignments: list[Assignment]) -> list[str]:
    """
    Which benign persona is missing, and what its absence costs.

    A run without forgetful_user has no benign login failures, so
    login_failure_ratio separates perfectly in training and the model concludes
    one wrong password is an attack. Reported by name rather than left for
    someone to notice in the metrics.
    """
    present = {a.name for a in assignments if a.kind == "benign"}
    return [
        f"{name}: no benign mass for {reason}"
        for name, reason in persona_lib.TEACHES.items()
        if name not in present
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out", required=True, help="datasets/raw/<run_id>")
    parser.add_argument("--gateway", default="http://gateway:8082")
    parser.add_argument("--redis", default="redis://redis:6379/0")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--seconds", type=float, default=180.0)
    parser.add_argument("--per-persona", type=int, default=2)
    parser.add_argument("--no-reserved", action="store_true")
    parser.add_argument(
        "--skip-preflight", action="store_true",
        help="generate without proving identities. Produces a dataset that may "
             "be one client pretending to be forty, undetectably.",
    )
    args = parser.parse_args(argv)

    assignments = plan_run(
        args.seed, args.per_persona, args.seconds, include_reserved=not args.no_reserved
    )
    for gap in coverage(assignments):
        print(f"[traffic] WARNING {gap}")

    client = Client(args.gateway)

    if not args.skip_preflight:
        import redis  # only here: the plan and the personas need no dependency

        conn = redis.Redis.from_url(args.redis, decode_responses=True)
        result = preflight(
            [a.ip for a in assignments],
            send=lambda ip: client.send(ip, persona_lib.HEALTH),
            lookup=conn.get,
            observed=lambda: observed_addresses(
                lambda pattern: conn.scan_iter(match=pattern, count=500)
            ),
        )
        require_trusted_identity(result)
        print(f"[traffic] {len(result.trusted)} addresses confirmed trusted")

    out = Path(args.out)
    started = datetime.now(timezone.utc)
    # Written before the traffic, not after it.
    write_labels(out, args.run_id, assignments, started)

    print(f"[traffic] {len(assignments)} sessions, ~{args.seconds:.0f}s")
    sessions = run_concurrently(client, [(a.ip, a.plan) for a in assignments])

    total = sum(len(s.sent) for s in sessions)
    failed = sum(1 for s in sessions for r in s.sent if r.status == 0)
    joined = sum(1 for s in sessions for r in s.sent if r.request_id)
    print(f"[traffic] sent {total} requests, {failed} failed, {joined} with a request id")
    if joined < total:
        # The request id is the exact join into telemetry. Without it a row has
        # to be matched by address and time, which is a guess.
        print("[traffic] WARNING some responses carried no X-Request-ID")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
