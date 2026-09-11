"""Load and score a deployed model without making it an enforcement authority."""

from __future__ import annotations

import json
from pathlib import Path

from iasg.adaptive.risk import AnomalyObservation
from iasg.anomaly.extract import WindowRow
from iasg.anomaly.spec import FEATURE_NAMES, FEATURE_SPEC_VERSION
from iasg.ml.login_regularity import LOGIN_REGULARITY_FORMULA, login_regularity


class ModelScorer:
    def __init__(self, model_path: str, metadata_path: str) -> None:
        self._model_path = Path(model_path)
        self._metadata_path = Path(metadata_path)
        self._bundle = None
        self._metadata: dict = {}
        self._load_error = ""
        self.reload()

    def reload(self) -> None:
        self._bundle = None
        self._metadata = {}
        self._load_error = ""
        if not self._model_path.exists() or not self._metadata_path.exists():
            return
        try:
            import joblib

            metadata = json.loads(self._metadata_path.read_text())
            if metadata.get("feature_schema_version") != FEATURE_SPEC_VERSION:
                raise ValueError("deployed model feature schema does not match runtime")
            if tuple(metadata.get("feature_names") or ()) != FEATURE_NAMES:
                raise ValueError("deployed model feature order does not match runtime")
            self._validate_engineered_features(metadata)
            self._bundle = joblib.load(self._model_path)
            self._metadata = metadata
        except Exception as err:  # noqa: BLE001 - absence/mismatch is fail-safe
            self._load_error = str(err)

    @staticmethod
    def _validate_engineered_features(metadata: dict) -> None:
        engineered = metadata.get("engineered_features") or {}
        unknown = set(engineered) - {"login_regularity"}
        if unknown:
            raise ValueError("deployed model has unsupported engineered features")
        regularity = engineered.get("login_regularity")
        if not regularity:
            return
        if regularity.get("formula") != LOGIN_REGULARITY_FORMULA:
            raise ValueError("deployed login regularity formula does not match runtime")
        repeated = regularity.get("repeated")
        if not isinstance(repeated, int) or repeated < 1:
            raise ValueError("deployed login regularity repeat count is invalid")
        gate = regularity.get("benign_validation_max")
        if gate is not None and not 0.0 <= float(gate) <= 1.0:
            raise ValueError("deployed login regularity gate is invalid")

    @property
    def available(self) -> bool:
        return self._bundle is not None

    @property
    def error(self) -> str:
        return self._load_error

    def score(self, row: WindowRow) -> AnomalyObservation:
        if self._bundle is None:
            return AnomalyObservation(available=False, reason="model_unavailable")
        if row.quality.insufficient_history:
            return AnomalyObservation(
                available=True,
                score=None,
                model_version=str(self._metadata.get("model_version") or ""),
                feature_schema_version=FEATURE_SPEC_VERSION,
                reason="insufficient_history",
            )
        medians = self._bundle["medians"]
        vector = [
            float(medians[name] if row.features.get(name) is None else row.features[name])
            for name in FEATURE_NAMES
        ]
        regularity = (self._metadata.get("engineered_features") or {}).get(
            "login_regularity"
        )
        login_signature = None
        if regularity:
            login_signature = login_regularity(
                vector[FEATURE_NAMES.index("login_ratio")],
                vector[FEATURE_NAMES.index("interarrival_cv")],
            )
            vector += [login_signature] * int(regularity["repeated"])
        raw = float(self._bundle["model"].score_samples([vector])[0])
        low = float(self._metadata["score_scale"]["anomalous"])
        high = float(self._metadata["score_scale"]["normal"])
        score = 1.0 if high <= low else (high - raw) / (high - low)
        score = max(0.0, min(1.0, score))
        # This is calibrated only against benign validation observations.  It
        # lifts a recognisably hostile login cadence into advisory context but
        # leaves risk confidence and the no-ML-alone guardrail untouched.
        if regularity and login_signature is not None:
            gate = regularity.get("benign_validation_max")
            if gate is not None and login_signature > float(gate):
                score = max(score, float(regularity.get("gate_score") or 1.0))
        return AnomalyObservation(
            available=True,
            score=round(score, 6),
            model_version=str(self._metadata.get("model_version") or ""),
            feature_schema_version=FEATURE_SPEC_VERSION,
            reason="scored",
        )
