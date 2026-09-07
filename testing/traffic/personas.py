"""
Benign traffic, chosen so every feature has innocent mass.

This is the part that decides whether the model learns behaviour or learns
"any non-zero X is an attack". If no benign session ever fails a login, the
model concludes a single failed login is an attack, and the first real person
who mistypes a password gets throttled. So each persona below exists to put
ordinary traffic somewhere a naive rule would call suspicious.

Every persona is deterministic given a seed, so a run is reproducible.
"""

from __future__ import annotations

import random

from testing.traffic.plan import Plan, Request

PRODUCTS = Request("GET", "/api/products")
HEALTH = Request("GET", "/api/health")


def _login(password: str) -> Request:
    return Request("POST", "/api/login", {"email": "user@example.com", "password": password})


def browser(rng: random.Random, seconds: float = 120.0) -> Plan:
    """Someone reading the catalogue. The baseline everything else is unusual
    relative to."""
    plan = Plan("browser")
    t = 0.0
    while t < seconds:
        plan.at(t, PRODUCTS)
        t += rng.uniform(3.0, 12.0)
        for _ in range(rng.randint(1, 4)):
            if t >= seconds:
                break
            plan.at(t, Request("GET", f"/api/products/{rng.randint(1, 40)}"))
            t += rng.uniform(2.0, 8.0)
    return plan


def shopper(rng: random.Random, seconds: float = 120.0) -> Plan:
    """Browses, then logs in successfully. Supplies logins with zero failures,
    without which any login at all looks like an attack."""
    plan = Plan("shopper")
    t = 0.0
    while t < seconds * 0.4:
        plan.at(t, Request("GET", f"/api/products/{rng.randint(1, 40)}"))
        t += rng.uniform(2.0, 9.0)
    plan.at(t, _login("correct-horse"))
    t += rng.uniform(1.0, 3.0)
    while t < seconds:
        plan.at(t, Request("GET", f"/api/products/{rng.randint(1, 40)}"))
        t += rng.uniform(3.0, 11.0)
    return plan


def forgetful_user(rng: random.Random, seconds: float = 120.0) -> Plan:
    """
    Mistypes a password two or three times, then gets it right.

    Teaches that login_failure_ratio > 0 is benign. Without this persona the
    feature is perfectly separating in training and the model learns that one
    wrong password is an attack.
    """
    plan = Plan("forgetful_user")
    t = rng.uniform(0.0, 5.0)
    for _ in range(rng.randint(2, 3)):
        plan.at(t, _login("wrong-again"))
        # Human hesitation: several seconds, not milliseconds. The gap is what
        # separates this from credential stuffing, and it has to be real.
        t += rng.uniform(4.0, 15.0)
    plan.at(t, _login("correct-horse"))
    t += rng.uniform(2.0, 6.0)
    while t < seconds:
        plan.at(t, Request("GET", f"/api/products/{rng.randint(1, 40)}"))
        t += rng.uniform(4.0, 12.0)
    return plan


def dead_link_visitor(rng: random.Random, seconds: float = 120.0) -> Plan:
    """
    Follows stale bookmarks to products that no longer exist.

    Teaches that backend_404_ratio > 0 is benign -- otherwise every 404 reads
    as enumeration, and a site that deleted some products flags its own users.
    """
    plan = Plan("dead_link_visitor")
    t = 0.0
    while t < seconds:
        if rng.random() < 0.4:
            plan.at(t, Request("GET", f"/api/products/{rng.randint(9000, 9999)}"))
        else:
            plan.at(t, Request("GET", f"/api/products/{rng.randint(1, 40)}"))
        t += rng.uniform(3.0, 14.0)
    return plan


def search_heavy(rng: random.Random, seconds: float = 120.0) -> Plan:
    """
    Many searches, one path.

    unique_path_ratio excludes the query string, so this stays low however many
    distinct searches are run. The persona is here to prove that -- if query
    strings ever leaked into the path, this session would look like a scanner.
    """
    plan = Plan("search_heavy")
    terms = ["laptop", "phone", "desk", "cable", "monitor", "mouse", "chair"]
    t = 0.0
    while t < seconds:
        plan.at(t, Request("GET", f"/api/products/search?q={rng.choice(terms)}"))
        t += rng.uniform(2.0, 7.0)
    return plan


def mobile_poller(rng: random.Random, seconds: float = 120.0) -> Plan:
    """
    A mobile app polling on a fixed interval.

    Teaches that a low interarrival_cv is benign -- exactly what a naive
    "regular timing means bot" rule flags. Real polling is what this looks
    like, and it is the most valuable benign persona in the set.
    """
    plan = Plan("mobile_poller")
    interval = rng.choice([5.0, 10.0, 15.0])
    t = 0.0
    while t < seconds:
        plan.at(t, HEALTH)
        # A little jitter, because a real client has some. Not enough to raise
        # the CV out of the range this persona exists to occupy.
        t += interval + rng.uniform(-0.2, 0.2)
    return plan


def impatient(rng: random.Random, seconds: float = 120.0) -> Plan:
    """
    Someone hitting refresh because a page felt slow.

    Teaches that peak_1s_requests can spike without an attack. A burst of six
    requests in a second is a frustrated person, not a flood.
    """
    plan = Plan("impatient")
    t = 0.0
    while t < seconds:
        plan.at(t, PRODUCTS)
        t += rng.uniform(8.0, 20.0)
        if rng.random() < 0.5:
            for _ in range(rng.randint(3, 6)):
                plan.at(t, PRODUCTS)
                t += rng.uniform(0.1, 0.3)
            t += rng.uniform(5.0, 15.0)
    return plan


def one_shot(rng: random.Random, seconds: float = 120.0) -> Plan:
    """
    A single request and nothing more.

    Produces insufficient_history rows. They are kept and marked rather than
    dropped, and the dataset has to contain them or the abstention rate cannot
    be measured honestly.
    """
    return Plan("one_shot").at(rng.uniform(0.0, 10.0), PRODUCTS)


def idle(rng: random.Random, seconds: float = 120.0) -> Plan:
    """
    Two requests, minutes apart.

    Produces absent windows between them. A window with no requests is not a
    row at all, and a dataset with no such gaps would never exercise that.
    """
    plan = Plan("idle")
    plan.at(rng.uniform(0.0, 5.0), PRODUCTS)
    plan.at(rng.uniform(seconds * 0.75, seconds), HEALTH)
    return plan


PERSONAS = {
    fn.__name__: fn
    for fn in (
        browser, shopper, forgetful_user, dead_link_visitor, search_heavy,
        mobile_poller, impatient, one_shot, idle,
    )
}

# What each persona is in the set to teach. Read by the traffic planner to
# report coverage, so a run that dropped a persona says which feature lost its
# benign mass instead of quietly producing a separable column.
TEACHES = {
    "browser": "dominant_route_ratio baseline",
    "shopper": "logins with zero failures",
    "forgetful_user": "login_failure_ratio > 0 is benign",
    "dead_link_visitor": "backend_404_ratio > 0 is benign",
    "search_heavy": "query strings stay out of unique_path_ratio",
    "mobile_poller": "low interarrival_cv is benign",
    "impatient": "peak_1s_requests without an attack",
    "one_shot": "insufficient_history rows",
    "idle": "absent windows",
}
