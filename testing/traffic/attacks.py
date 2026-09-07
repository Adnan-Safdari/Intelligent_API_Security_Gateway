"""
Attack scenarios, in Python.

No new .jmx files: .gitignore's `testing/jmeter/*` would silently ignore them,
so an attack driver added there would exist on one machine and nowhere else.

Two of these are reserved. They are deliberately quieter than the Go detectors'
thresholds, which is the whole point -- they are the only honest measure of
whether this layer catches what the detectors miss, and a threshold tuned
against them would measure nothing. The splitter forces them into test.
"""

from __future__ import annotations

import random

from testing.traffic.plan import Plan, Request

# Kept in one place so the splitter, the dataset's held_out_scenarios.txt and
# these definitions cannot drift apart.
RESERVED = ("slow_brute_force", "low_and_slow_enumeration")

PASSWORDS = [
    "123456", "password", "qwerty", "letmein", "admin", "welcome",
    "monkey", "dragon", "football", "iloveyou",
]

PROBE_PATHS = [
    "/.env-demo", "/backup-demo", "/config-demo", "/api/demo-files",
    "/admin", "/api/users", "/api/admin", "/.git/config", "/wp-login.php",
]

SQLI_PAYLOADS = [
    "1' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT null,null--",
    "admin'--", "1' AND SLEEP(5)--",
]


def _login(password: str) -> Request:
    return Request("POST", "/api/login", {"email": "victim@example.com", "password": password})


def credential_stuffing(rng: random.Random, seconds: float = 90.0) -> Plan:
    """Fast, obvious, and inside every detector's threshold. The easy case."""
    plan = Plan("credential_stuffing")
    t = 0.0
    while t < seconds:
        plan.at(t, _login(rng.choice(PASSWORDS)))
        t += rng.uniform(0.2, 0.8)
    return plan


def api_flood(rng: random.Random, seconds: float = 60.0) -> Plan:
    plan = Plan("api_flood")
    t = 0.0
    while t < seconds:
        plan.at(t, Request("GET", "/api/products"))
        t += rng.uniform(0.02, 0.08)
    return plan


def enumeration(rng: random.Random, seconds: float = 90.0) -> Plan:
    plan = Plan("enumeration")
    t = 0.0
    while t < seconds:
        plan.at(t, Request("GET", rng.choice(PROBE_PATHS)))
        t += rng.uniform(0.3, 1.0)
    return plan


def sqli_probe(rng: random.Random, seconds: float = 90.0) -> Plan:
    plan = Plan("sqli_probe")
    t = 0.0
    while t < seconds:
        payload = rng.choice(SQLI_PAYLOADS).replace(" ", "%20").replace("'", "%27")
        plan.at(t, Request("GET", f"/api/products/search?q={payload}"))
        t += rng.uniform(0.5, 2.0)
    return plan


def path_traversal(rng: random.Random, seconds: float = 90.0) -> Plan:
    plan = Plan("path_traversal")
    depths = ["../", "../../", "../../../", "../../../../"]
    targets = ["etc/passwd", "etc/shadow", "proc/self/environ", ".env"]
    t = 0.0
    while t < seconds:
        plan.at(t, Request("GET", f"/api/{rng.choice(depths)}{rng.choice(targets)}"))
        t += rng.uniform(0.4, 1.2)
    return plan


# --- Reserved. Never seen while tuning. ------------------------------------


def slow_brute_force(rng: random.Random, seconds: float = 600.0) -> Plan:
    """
    One login attempt every eight seconds, for ten minutes.

    Deliberately under internal/signals/brute_force.go's threshold, so the
    deterministic detector never fires. Nothing about any single request is
    unusual -- only the shape of the whole window is: a login ratio near 1, a
    failure ratio near 1, and timing far too even for a person. If this layer
    is worth having, this is the case it earns its place on.
    """
    plan = Plan("slow_brute_force")
    t = 0.0
    while t < seconds:
        plan.at(t, _login(rng.choice(PASSWORDS)))
        t += 8.0 + rng.uniform(-0.4, 0.4)
    return plan


def low_and_slow_enumeration(rng: random.Random, seconds: float = 600.0) -> Plan:
    """
    A probe every twelve seconds, spread across many paths.

    Under the enumeration detector's window too. What remains visible is the
    path diversity and the unmatched-route concentration, which is exactly what
    unique_path_ratio and dominant_route_ratio measure.
    """
    plan = Plan("low_and_slow_enumeration")
    t = 0.0
    while t < seconds:
        plan.at(t, Request("GET", rng.choice(PROBE_PATHS)))
        t += 12.0 + rng.uniform(-0.5, 0.5)
    return plan


SCENARIOS = {
    fn.__name__: fn
    for fn in (
        credential_stuffing, api_flood, enumeration, sqli_probe, path_traversal,
        slow_brute_force, low_and_slow_enumeration,
    )
}

TUNABLE = tuple(name for name in SCENARIOS if name not in RESERVED)
