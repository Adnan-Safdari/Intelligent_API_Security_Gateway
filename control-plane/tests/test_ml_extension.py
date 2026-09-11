"""The offline model artifact and asynchronous scorer share one schema."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone

import pytest

from iasg.anomaly.extract import WindowRow
from iasg.anomaly.quality import WindowQuality
from iasg.anomaly.spec import FEATURE_NAMES, FEATURE_SPEC_VERSION
from iasg.ml.scorer import ModelScorer
from iasg.ml.train import train


pytest.importorskip("sklearn")


def test_training_writes_versioned_metadata_and_runtime_can_score(tmp_path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    rows = []
    metadata = []
    splits = []
    for index in range(1, 31):
        attack = index in (20, 21, 29)
        values = {
            name: (1000.0 if attack else float(index % 5 + 1))
            for name in FEATURE_NAMES
        }
        rows.append({"row_id": str(index), **values})
        metadata.append({
            "row_id": str(index), "run_id": f"run-{index // 10}",
            "client_id": f"client-{index}", "window_start": "2026-09-08T00:00:00+00:00",
            "label": "1" if attack else "0", "scenario": "flood" if attack else "benign",
        })
        split = "train" if index <= 15 else "val" if index <= 24 else "test"
        splits.append({"row_id": str(index), "split": split, "group_key": f"run|{index}"})
    _write(dataset / "features.csv", ["row_id", *FEATURE_NAMES], rows)
    _write(dataset / "metadata.csv", ["row_id", "run_id", "client_id", "window_start", "label", "scenario"], metadata)
    _write(dataset / "splits.csv", ["row_id", "split", "group_key"], splits)
    (dataset / "manifest.json").write_text(json.dumps({"runs": ["run-0", "run-1", "run-2"]}))

    artifact = train(dataset, tmp_path / "model", version="iforest-test")
    details = json.loads((artifact / "metadata.json").read_text())
    assert details["model_version"] == "iforest-test"
    assert details["feature_schema_version"] == FEATURE_SPEC_VERSION
    assert details["training_run_ids"] == ["run-0", "run-1", "run-2"]
    assert details["evaluation"]["test"]["rows"] == 6

    scorer = ModelScorer(str(artifact / "model.joblib"), str(artifact / "metadata.json"))
    row = WindowRow(
        ip="203.0.113.99",
        window_start=datetime(2026, 9, 8, tzinfo=timezone.utc),
        features={name: 2.0 for name in FEATURE_NAMES},
        quality=WindowQuality(insufficient_history=False),
    )
    score = scorer.score(row)
    assert scorer.available
    assert score.available and score.model_version == "iforest-test"
    assert 0 <= score.score <= 1


def test_no_deployed_model_is_safe_and_explicit(tmp_path):
    scorer = ModelScorer(str(tmp_path / "missing.joblib"), str(tmp_path / "missing.json"))
    assert not scorer.available


def test_runtime_rebuilds_a_calibrated_login_regularity_feature(tmp_path):
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    rows, metadata, splits = [], [], []
    for index in range(1, 31):
        attack = index in (20, 21, 29)
        values = {name: float(index % 5 + 1) for name in FEATURE_NAMES}
        values["login_ratio"] = 1.0 if attack else 0.0
        values["interarrival_cv"] = 0.01 if attack else 0.8
        rows.append({"row_id": str(index), **values})
        metadata.append({
            "row_id": str(index), "run_id": f"run-{index // 10}",
            "client_id": f"client-{index}", "window_start": "2026-09-08T00:00:00+00:00",
            "label": "1" if attack else "0", "scenario": "flood" if attack else "benign",
        })
        split = "train" if index <= 15 else "val" if index <= 24 else "test"
        splits.append({"row_id": str(index), "split": split, "group_key": f"run|{index}"})
    _write(dataset / "features.csv", ["row_id", *FEATURE_NAMES], rows)
    _write(dataset / "metadata.csv", ["row_id", "run_id", "client_id", "window_start", "label", "scenario"], metadata)
    _write(dataset / "splits.csv", ["row_id", "split", "group_key"], splits)
    (dataset / "manifest.json").write_text(json.dumps({"runs": ["run-0", "run-1", "run-2"]}))

    artifact = train(
        dataset, tmp_path / "model", version="iforest-regularity",
        login_regularity_feature=True, login_regularity_gate=True,
    )
    scorer = ModelScorer(str(artifact / "model.joblib"), str(artifact / "metadata.json"))
    row = WindowRow(
        ip="203.0.113.98", window_start=datetime(2026, 9, 8, tzinfo=timezone.utc),
        features={
            **{name: 2.0 for name in FEATURE_NAMES},
            "login_ratio": 1.0, "interarrival_cv": 0.01,
        },
        quality=WindowQuality(insufficient_history=False),
    )
    observation = scorer.score(row)
    assert scorer.available
    assert observation.score == 1.0


def _write(path, fields, rows):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
