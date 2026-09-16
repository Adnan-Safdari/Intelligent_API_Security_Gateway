"""One named transform shared by training, evaluation, and live scoring."""

from __future__ import annotations


LOGIN_REGULARITY_FORMULA = "login_ratio * max(0.0, 1.0 - interarrival_cv)"


def login_regularity(login_ratio: float, interarrival_cv: float) -> float:
    """Return a login cadence signature without promoting polling by itself.

    Near zero unless a window both talks to the login endpoint and arrives on a
    near-fixed cadence. Neither half separates the attack alone: a person
    mistyping a password also produces login attempts (and the training set
    carries that case on purpose), while automated polling is often more
    mechanically regular than a slow attack, so timing regularity alone
    promotes legitimate scripted traffic. The product stays small unless both
    hold at once, which no benign persona in this dataset does.
    """
    return login_ratio * max(0.0, 1.0 - interarrival_cv)
