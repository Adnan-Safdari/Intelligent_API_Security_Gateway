"""Connect completed windows, baselines, ML advice, risk, and lifecycle."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace

from iasg.adaptive.baseline import BaselineLearner, BaselineRepository, BaselineSummary, EndpointKey
from iasg.adaptive.config import AdaptiveConfig
from iasg.adaptive.lifecycle import Lifecycle, LifecycleRepository
from iasg.adaptive.risk import AnomalyObservation, RiskResult, calculate_risk
from iasg.adaptive.windows import CompletedWindow
from iasg.ml.scorer import ModelScorer
from iasg.models import (
    ACTION_ALLOW,
    ACTION_MONITOR,
    ACTION_TEMP_BLOCK,
    ACTION_THROTTLE,
    Campaign,
    Evidence,
    PolicyDecision,
)


@dataclass(frozen=True)
class EndpointObservation:
    key: EndpointKey
    observed: int
    baseline: BaselineSummary | None
    deviation: float


@dataclass(frozen=True)
class WindowAssessment:
    ip: str
    endpoints: tuple[EndpointObservation, ...]
    anomaly: AnomalyObservation

    @property
    def most_deviant(self) -> EndpointObservation | None:
        return max(
            self.endpoints,
            key=lambda item: (item.deviation, item.observed),
            default=None,
        )


class AdaptiveController:
    def __init__(
        self,
        baselines: BaselineRepository,
        lifecycle: LifecycleRepository,
        scorer: ModelScorer,
        config: AdaptiveConfig,
    ) -> None:
        self.baselines = baselines
        self.lifecycle = Lifecycle(lifecycle)
        self.scorer = scorer
        self.config = config.validate()
        self._windows: dict[str, WindowAssessment] = {}

    def apply_config(self, config: AdaptiveConfig) -> None:
        self.config = config.validate()

    def observe(
        self, windows: list[CompletedWindow]
    ) -> list[tuple[PolicyDecision, bool, str]]:
        """Learn safe windows and save ML-only observations as monitor advice."""
        learner = BaselineLearner(self.baselines, self.config.baseline)
        recommendations: list[tuple[PolicyDecision, bool, str]] = []
        for window in windows:
            endpoint_rows: list[EndpointObservation] = []
            for (method, route), observed in window.route_counts.items():
                key = EndpointKey.of(method, route)
                before = self.baselines.get_baseline(key)
                deviation = learner.deviation(before, observed)
                endpoint_rows.append(EndpointObservation(key, observed, before, deviation))

            features = dict(window.row.features)
            features["endpoint_method_deviation"] = max(
                (item.deviation for item in endpoint_rows), default=0.0
            )
            scored_row = replace(window.row, features=features)
            anomaly = self.scorer.score(scored_row)
            assessment = WindowAssessment(
                ip=window.row.ip,
                endpoints=tuple(endpoint_rows),
                anomaly=anomaly,
            )
            self._windows[window.row.ip] = assessment

            # Score before this observation is admitted, so a burst cannot
            # raise its own comparison point and then look ordinary.
            configured = _configured_action(
                window.row.ip,
                self.config.guardrails.allowlist,
                self.config.guardrails.blocklist,
            )
            if configured or (anomaly.available and anomaly.score is not None and anomaly.score > 0):
                context = assessment.most_deviant
                result = calculate_risk(
                    self.config, None, [],
                    endpoint=context.key if context else None,
                    baseline=context.baseline if context else None,
                    observed_rate=context.observed if context else 0,
                    anomaly=anomaly,
                )
                decision = self._decision(
                    window.row.ip, None, result, context, anomaly,
                    action=ACTION_MONITOR,
                )
                recommendation, enforce, why = self.lifecycle.stage(
                    decision, self.config
                )
                recommendations.append((recommendation.decision, enforce, why))

            for (method, route), observed in window.route_counts.items():
                learner.observe(
                    EndpointKey.of(method, route), observed,
                    trusted=window.safe_to_learn and configured != ACTION_TEMP_BLOCK,
                    now=window.row.window_start,
                )
        return recommendations

    def decisions(
        self, campaign: Campaign, evidence: list[Evidence]
    ) -> list[tuple[PolicyDecision, bool, str]]:
        staged: list[tuple[PolicyDecision, bool, str]] = []
        for ip in campaign.ips:
            assessment = self._windows.get(ip)
            context = assessment.most_deviant if assessment else None
            # Distinct from the scorer's own "model_unavailable"/
            # "insufficient_history" -- this ip has no completed rate window
            # at all yet (e.g. its first-ever request just tripped a
            # signature detector), so the model was never even asked.
            anomaly = assessment.anomaly if assessment else AnomalyObservation(reason="no_window_observed")
            relevant = [row for row in evidence if row.ip == ip]
            result = calculate_risk(
                self.config,
                campaign,
                relevant,
                endpoint=context.key if context else None,
                baseline=context.baseline if context else None,
                observed_rate=context.observed if context else 0,
                anomaly=anomaly,
            )
            decision = self._decision(ip, campaign, result, context, anomaly)
            recommendation, enforce, why = self.lifecycle.stage(decision, self.config)
            staged.append((recommendation.decision, enforce, why))
        return staged

    def _decision(
        self,
        ip: str,
        campaign: Campaign | None,
        result: RiskResult,
        endpoint: EndpointObservation | None,
        anomaly: AnomalyObservation,
        *,
        action: str | None = None,
    ) -> PolicyDecision:
        selected = action or result.action
        guard = self.config.guardrails
        configured = _configured_action(ip, guard.allowlist, guard.blocklist)
        source = "adaptive"
        mode = self.config.mode
        issued_by = "control-plane"
        if configured:
            selected = configured
            source = "human"
            mode = "manual_override"
            issued_by = "adaptive-config"
            result.explanation["final"]["selected_action"] = selected
            result.explanation["final"]["guardrails"].append(
                f"emergency {('allowlist' if configured == ACTION_ALLOW else 'blocklist')} has operator precedence"
            )
        duration = {
            ACTION_MONITOR: guard.monitor_duration_seconds,
            ACTION_ALLOW: guard.maximum_policy_duration_seconds,
            ACTION_THROTTLE: guard.throttle_duration_seconds,
            ACTION_TEMP_BLOCK: guard.temporary_block_duration_seconds,
        }.get(selected, guard.monitor_duration_seconds)
        duration = min(duration, guard.maximum_policy_duration_seconds)
        route = endpoint.key.route_template if endpoint and not configured else ""
        method = endpoint.key.method if endpoint and not configured else ""
        baseline_version = (
            f"{method} {route}@{endpoint.baseline.version}"
            if endpoint and endpoint.baseline else ""
        )
        reason = (
            f"risk {result.score:.2f}/100, confidence {result.confidence:.3f}; "
            + "; ".join(result.explanation["final"]["guardrails"])
        )
        return PolicyDecision(
            ip=ip,
            action=selected,
            campaign_id=campaign.campaign_id if campaign else "",
            confidence=result.confidence,
            ttl_seconds=duration,
            reason=reason,
            requests_per_minute=result.requests_per_minute if selected == ACTION_THROTTLE else 0,
            source=source,
            scope="client_endpoint" if route else "client",
            target_identity=ip,
            method=method,
            route_template=route,
            risk_score=result.score,
            explanation=result.explanation,
            mode=mode,
            issued_by=issued_by,
            baseline_version=baseline_version,
            config_version=self.config.version,
            model_version=anomaly.model_version,
            model_score=anomaly.score,
            model_status=anomaly.reason,
        )


def _configured_action(
    ip: str, allowlist: tuple[str, ...], blocklist: tuple[str, ...]
) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    # A safety allow always wins if an operator accidentally overlaps ranges.
    if any(address in ipaddress.ip_network(value, strict=False) for value in allowlist):
        return ACTION_ALLOW
    if any(address in ipaddress.ip_network(value, strict=False) for value in blocklist):
        return ACTION_TEMP_BLOCK
    return ""
