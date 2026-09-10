import csv
import json

import numpy as np
import pytest

from iasg.anomaly.spec import FEATURE_NAMES
from iasg.ml.validate import validate


pytest.importorskip("sklearn")


def test_fresh_validation_compares_rules_ml_and_true_gateway_misses(tmp_path):
    from sklearn.ensemble import IsolationForest
    import joblib

    dataset = tmp_path / "fresh"
    artifact = tmp_path / "model"
    dataset.mkdir()
    artifact.mkdir()
    ids = [str(value) for value in range(1, 7)]
    _write(dataset / "features.csv", ["row_id", *FEATURE_NAMES], [
        {"row_id": row_id, **{name: float(index) for name in FEATURE_NAMES}}
        for index, row_id in enumerate(ids, start=1)
    ])
    _write(dataset / "metadata.csv", [
        "row_id", "label", "scenario", "persona", "detector_fired", "gateway_blocked",
    ], [
        {"row_id": "1", "label": "0", "scenario": "benign", "persona": "dead_link_visitor", "detector_fired": "0", "gateway_blocked": "0"},
        {"row_id": "2", "label": "0", "scenario": "benign", "persona": "forgetful_user", "detector_fired": "1", "gateway_blocked": "0"},
        {"row_id": "3", "label": "1", "scenario": "scan", "persona": "", "detector_fired": "1", "gateway_blocked": "0"},
        {"row_id": "4", "label": "1", "scenario": "slow", "persona": "", "detector_fired": "0", "gateway_blocked": "0"},
        {"row_id": "5", "label": "1", "scenario": "blocked", "persona": "", "detector_fired": "0", "gateway_blocked": "1"},
        {"row_id": "6", "label": "1", "scenario": "slow", "persona": "", "detector_fired": "0", "gateway_blocked": "0"},
    ])
    _write(dataset / "quality.csv", ["row_id", "insufficient_history"], [
        {"row_id": "1", "insufficient_history": "False"},
        {"row_id": "2", "insufficient_history": "False"},
        {"row_id": "3", "insufficient_history": "False"},
        {"row_id": "4", "insufficient_history": "False"},
        {"row_id": "5", "insufficient_history": "False"},
        {"row_id": "6", "insufficient_history": "True"},
    ])
    model = IsolationForest(random_state=1).fit(np.asarray([
        [float(index)] * len(FEATURE_NAMES) for index in range(1, 7)
    ]))
    joblib.dump({"model": model, "medians": {name: 1.0 for name in FEATURE_NAMES}}, artifact / "model.joblib")
    (artifact / "metadata.json").write_text(json.dumps({
        "model_version": "fixed-model",
        "feature_names": list(FEATURE_NAMES),
        "evaluation": {"threshold_score_samples": 1.0},
    }))

    report = validate(dataset, artifact)

    assert report["threshold_source"] == "artifact validation data; not selected on this fresh run"
    assert report["rules_only"]["personas"]["forgetful_user"]["false_positives"] == 1
    assert report["advisory_ml_only"]["personas"]["dead_link_visitor"]["false_positives"] == 1
    assert report["rules_only"]["scenarios"]["slow"]["operational_recall"] == 0
    missed = report["gateway_missed_attack_minute_coverage"]
    assert missed["slow"]["gateway_missed_attack_minutes"] == 2
    assert missed["slow"]["advisory_ml"]["detected"] == 1
    assert "blocked" not in missed


def _write(path, fields, rows):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
