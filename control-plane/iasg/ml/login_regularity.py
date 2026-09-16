"""One named transform shared by training, evaluation, and live scoring."""

from __future__ import annotations


LOGIN_REGULARITY_FORMULA = "login_ratio * max(0.0, 1.0 - interarrival_cv)"


def login_regularity(login_ratio: float, interarrival_cv: float) -> float:
    """Return a login cadence signature without promoting polling by itself."""
    return login_ratio * max(0.0, 1.0 - interarrival_cv)
