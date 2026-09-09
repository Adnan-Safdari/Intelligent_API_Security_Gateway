"""
Names and constants the v2 feature contract fixes.

`gateway/docs/anomaly-features.md` is the contract; this module is the part of
it the code has to agree with literally. Everything here is frozen for the life
of a spec version: a feature whose meaning changes gets a new version and a new
dataset, because a model trained on v1 has no way to notice that column 9
started meaning something else.
"""

from __future__ import annotations

FEATURE_SPEC_VERSION = "v2"

# Non-overlapping and aligned to :00 UTC.
WINDOW_SECONDS = 60

# Order is part of the contract. A vector is positional, so reordering this
# silently retrains column meanings while every test still passes.
FEATURE_NAMES = (
    "request_count",
    "peak_1s_requests",
    "interarrival_cv",
    "unique_path_ratio",
    "dominant_route_ratio",
    "post_ratio",
    "login_ratio",
    "login_failure_ratio",
    "backend_404_ratio",
    "backend_5xx_ratio",
    "mean_request_body_bytes",
    "p95_upstream_duration_ms",
    "endpoint_method_deviation",
)

# Features 1-7 are computable from arrival alone; 8-12 need a settled response.
# Stated as data rather than left implicit in extract(), because the split is
# what the availability guarantee rests on and it should be readable without
# following the arithmetic.
ARRIVAL_FEATURES = FEATURE_NAMES[:7]
COMPLETION_FEATURES = FEATURE_NAMES[7:12]
BASELINE_FEATURES = FEATURE_NAMES[12:]

QUALITY_NAMES = (
    "known_status_count",
    "login_attempts",
    "login_attempts_known_outcome",
    "complete_body_measurements",
    "complete_duration_measurements",
    "pending_at_scoring",
    "timeouts",
    "telemetry_dropped_in_window",
    "interval_fully_observed",
    "insufficient_history",
    "telemetry_defects",
)

# The reserved template for a path matching nothing. A documented category, not
# a null: a scanner walking paths no template matches produces a large bucket
# here, and that is informative.
UNMATCHED_ROUTE = "<unmatched>"

# internal/telemetry/upstream.go
ORIGIN_BACKEND = "backend"
ORIGIN_GATEWAY = "gateway"
OUTCOME_TIMEOUT = "timeout"

# internal/telemetry/route.go
AUTH_SUCCESS = "success"
AUTH_INVALID_CREDENTIALS = "invalid_credentials"
AUTH_UNKNOWN = "unknown"
KNOWN_AUTH_OUTCOMES = (AUTH_SUCCESS, AUTH_INVALID_CREDENTIALS)

# What counts as a login attempt for features 7 and 8.
#
# Deliberately the method and route template rather than the event's
# loginAttempt flag, even though that flag is the configured, verified notion.
# loginAttempt is written on the completion record, and feature 7 is
# arrival-derived -- reading it would mean a login still in flight did not
# count as a login, so an attacker could shrink their own login_ratio by making
# the backend slow.
LOGIN_METHOD = "POST"
LOGIN_ROUTE = "/api/login"

# A window with 1-2 requests is kept and marked, not dropped: it has no
# meaningful inter-arrival statistics, so it abstains from scoring rather than
# being scored badly. A coverage rule, not an attack threshold.
INSUFFICIENT_HISTORY_MAX = 2

# Feature 12's percentile, one-based after ceil.
P95 = 0.95
