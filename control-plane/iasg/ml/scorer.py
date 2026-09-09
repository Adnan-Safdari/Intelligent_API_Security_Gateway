"""Load and score a deployed model without making it an enforcement authority."""

from __future__ import annotations

import json
from pathlib import Path

from iasg.adaptive.risk import AnomalyObservation
from iasg.anomaly.extract import WindowRow
from iasg.anomaly.spec import FEATURE_NAMES, FEATURE_SPEC_VERSION


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
            self._bundle = joblib.load(self._model_path)
            self._metadata = metadata
        except Exception as err:  # noqa: BLE001 - absence/mismatch is fail-safe
            self._load_error = str(err)

    @property
    def available(self) -> bool:
        return self._bundle is not None

    @property
    def error(self) -> str:
        return self._load_error

    def score(self, row: WindowRow) -> AnomalyObservation:
        if self._bundle is None:
            return AnomalyObservation(available=False)
        if row.quality.insufficient_history:
            return AnomalyObservation(
                available=True,
                score=None,
                model_version=str(self._metadata.get("model_version") or ""),
                feature_schema_version=FEATURE_SPEC_VERSION,
            )
        medians = self._bundle["medians"]
        vector = [
            float(medians[name] if row.features.get(name) is None else row.features[name])
            for name in FEATURE_NAMES
        ]
        raw = float(self._bundle["model"].score_samples([vector])[0])
        low = float(self._metadata["score_scale"]["anomalous"])
        high = float(self._metadata["score_scale"]["normal"])
        score = 1.0 if high <= low else (high - raw) / (high - low)
        score = max(0.0, min(1.0, score))
        return AnomalyObservation(
            available=True,
            score=round(score, 6),
            model_version=str(self._metadata.get("model_version") or ""),
            feature_schema_version=FEATURE_SPEC_VERSION,
        )
