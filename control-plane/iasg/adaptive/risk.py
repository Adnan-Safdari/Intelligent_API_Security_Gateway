"""Explainable 0-100 scoring and guardrail-bounded action selection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from iasg.adaptive.baseline import BaselineSummary, EndpointKey
from iasg.adaptive.config import AdaptiveConfig, AUTO_ACTIONS
from iasg.models import (
    ACTION_MONITOR,
    ACTION_TEMP_BLOCK,
    ACTION_THROTTLE,
    DETECTOR_REPUTATION,
    Campaign,
    Evidence,
)


@dataclass(frozen=True)
class AnomalyObservation:
    available: bool = False
    score: float | None = None
    model_version: str = ""
    feature_schema_version: str = ""


@dataclass(frozen=True)
class RiskResult:
    score: float
    confidence: float
    action: str
    requests_per_minute: int
    explanation: dict


def calculate_risk(
    config: AdaptiveConfig,
    campaign: Campaign | None,
    evidence: Iterable[Evidence],
    *,
    endpoint: EndpointKey | None = None,
    baseline: BaselineSummary | None = None,
    observed_rate: int = 0,
    anomaly: AnomalyObservation | None = None,
) -> RiskResult:
    evidence = list(evidence)
    anomaly = anomaly or AnomalyObservation()
    risk = config.risk
    guard = config.guardrails

    deterministic = [row for row in evidence if row.detector != DETECTOR_REPUTATION]
    deterministic_count = len({
        row.stream_id if row.stream_id else f"unidentified-{index}"
        for index, row in enumerate(deterministic)
    })
    signal_rows = []
    strongest = 0.0
    for row in deterministic:
        base = float(risk.detector_points.get(row.detector, 0.0))
        severity = float(risk.severity_multipliers.get(row.severity, 0.0))
        value = _clamp(base * severity, 0.0, 100.0)
        strongest = max(strongest, value)
        signal_rows.append({
            "detector": row.detector,
            "severity": row.severity,
            "points": round(value, 2),
            "endpoint": row.endpoint,
        })
    deterministic_score = _clamp(
        strongest + max(0, deterministic_count - 1) * risk.repeated_evidence_increment,
        0.0,
        100.0,
    )

    deviation = 0.0
    if baseline is not None and baseline.ready and baseline.derived_threshold > 0:
        deviation = max(
            0.0,
            (observed_rate - baseline.derived_threshold) / baseline.derived_threshold,
        )
    behavioural_score = _clamp(deviation * 100.0, 0.0, 100.0)

    campaign_confidence = _clamp(campaign.confidence if campaign else 0.0, 0.0, 1.0)
    campaign_severity = risk.severity_multipliers.get(
        campaign.severity if campaign else "low", 0.0
    )
    campaign_score = _clamp(campaign_confidence * campaign_severity * 100.0, 0.0, 100.0)

    ml_score = (
        _clamp(float(anomaly.score), 0.0, 1.0) * 100.0
        if anomaly.available and anomaly.score is not None else 0.0
    )
    contributions = {
        "deterministic": deterministic_score * risk.deterministic_weight,
        "behavioural": behavioural_score * risk.behavioural_weight,
        "campaign": campaign_score * risk.campaign_weight,
        "ml": ml_score * risk.ml_weight,
    }
    total = _clamp(sum(contributions.values()), 0.0, 100.0)

    confidence = _clamp(
        (deterministic_score / 100.0) * risk.confidence_deterministic_weight
        + campaign_confidence * risk.confidence_campaign_weight,
        0.0,
        1.0,
    )
    candidate = _candidate(total, config)
    action, guardrail_reasons = _guard(
        candidate,
        total,
        confidence,
        deterministic_score,
        deterministic_count,
        anomaly,
        config,
    )
    rpm = _throttle_rate(action, baseline, config)

    explanation = {
        "deterministic_evidence": signal_rows,
        "deterministic_evidence_count": deterministic_count,
        "baseline": {
            "method": endpoint.method if endpoint else "",
            "route_template": endpoint.route_template if endpoint else "",
            "value": baseline.statistic if baseline else None,
            "threshold": baseline.derived_threshold if baseline else None,
            "observed": observed_rate,
            "deviation": round(deviation, 4),
            "baseline_ready": bool(baseline and baseline.ready),
            "version": baseline.version if baseline else 0,
        },
        "campaign": {
            "campaign_id": campaign.campaign_id if campaign else "",
            "severity": campaign.severity if campaign else "",
            "confidence": campaign_confidence,
            "facts": campaign.reason if campaign else "",
            "stages": list(campaign.stages) if campaign else [],
        },
        "ml": {
            "model_available": anomaly.available,
            "anomaly_score": anomaly.score,
            "model_version": anomaly.model_version,
            "feature_schema_version": anomaly.feature_schema_version,
            "note": "anomaly score is advisory and is not policy confidence",
        },
        "components": {
            name: {
                "weighted_points": round(value, 2),
                "weight": getattr(risk, f"{name}_weight"),
            }
            for name, value in contributions.items()
        },
        "final": {
            "risk_score": round(total, 2),
            "confidence": round(confidence, 3),
            "candidate_action": candidate,
            "selected_action": action,
            "guardrails": guardrail_reasons,
            "configuration_version": config.version,
        },
    }
    return RiskResult(
        score=round(total, 2), confidence=round(confidence, 3), action=action,
        requests_per_minute=rpm, explanation=explanation,
    )


def _candidate(score: float, config: AdaptiveConfig) -> str:
    if score >= config.risk.temporary_block_score:
        return ACTION_TEMP_BLOCK
    if score >= config.risk.throttle_score:
        return ACTION_THROTTLE
    return ACTION_MONITOR


def _guard(
    candidate: str,
    score: float,
    confidence: float,
    deterministic_score: float,
    deterministic_count: int,
    anomaly: AnomalyObservation,
    config: AdaptiveConfig,
) -> tuple[str, list[str]]:
    guard = config.guardrails
    reasons: list[str] = []
    action = candidate

    # A statistical surprise is a reason to investigate, never authority to
    # police a client.  Reputation is excluded above for the same reason.
    if deterministic_count == 0:
        return ACTION_MONITOR, ["no deterministic gateway evidence; monitor only"]

    ceiling = AUTO_ACTIONS.index(guard.maximum_automatic_action)
    if AUTO_ACTIONS.index(action) > ceiling:
        action = AUTO_ACTIONS[ceiling]
        reasons.append(f"automatic action capped at {guard.maximum_automatic_action}")

    if action == ACTION_TEMP_BLOCK:
        if deterministic_count < guard.minimum_deterministic_evidence_temporary_block:
            action = ACTION_THROTTLE
            reasons.append("temporary-block evidence minimum was not met")
        elif confidence < guard.minimum_confidence_temporary_block:
            action = ACTION_THROTTLE
            reasons.append("temporary-block confidence minimum was not met")
        else:
            # If ML was necessary to cross the block line it must itself be
            # strong.  A deterministic/campaign score already over the line is
            # allowed without a deployed model.
            without_ml = score - (
                (_clamp(float(anomaly.score or 0), 0.0, 1.0) * 100.0)
                * config.risk.ml_weight
            )
            if without_ml < config.risk.temporary_block_score and (
                not anomaly.available or (anomaly.score or 0.0) < guard.strong_ml_anomaly
            ):
                action = ACTION_THROTTLE
                reasons.append("ML-assisted block requires a strong anomaly")

    if action == ACTION_THROTTLE:
        if deterministic_count < guard.minimum_deterministic_evidence_throttle:
            action = ACTION_MONITOR
            reasons.append("throttle evidence minimum was not met")
        elif confidence < guard.minimum_confidence_throttle:
            action = ACTION_MONITOR
            reasons.append("throttle confidence minimum was not met")

    if deterministic_score <= 0:
        action = ACTION_MONITOR
        reasons.append("configured deterministic evidence carried no weight")
    if not reasons:
        reasons.append("configured score, confidence, and evidence guardrails were met")
    return action, reasons


def _throttle_rate(
    action: str, baseline: BaselineSummary | None, config: AdaptiveConfig
) -> int:
    if action != ACTION_THROTTLE:
        return 0
    guard = config.guardrails
    proposed = guard.default_throttle_rpm
    if baseline is not None and baseline.ready and baseline.derived_threshold > 0:
        proposed = round(
            baseline.derived_threshold * guard.throttle_baseline_fraction
        )
    return max(guard.minimum_throttle_rpm, min(guard.maximum_throttle_rpm, proposed))


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
