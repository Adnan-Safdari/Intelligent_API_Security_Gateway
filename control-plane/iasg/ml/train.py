"""Train and evaluate the advisory Isolation Forest on a frozen dataset."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from iasg.anomaly.spec import FEATURE_NAMES, FEATURE_SPEC_VERSION


def train(dataset: str | Path, out: str | Path, *, version: str = "", false_positive_budget: float = 0.02) -> Path:
    try:
        import joblib
        import numpy as np
        import sklearn
        from sklearn.ensemble import IsolationForest
    except ImportError as err:
        raise RuntimeError('install the ML extra with: pip install -e ".[ml]"') from err

    dataset, out = Path(dataset), Path(out)
    features = _csv_by_id(dataset / "features.csv")
    metadata = _csv_by_id(dataset / "metadata.csv")
    splits = _csv_by_id(dataset / "splits.csv")
    header = tuple(next(csv.reader((dataset / "features.csv").open()))[1:])
    if header != FEATURE_NAMES:
        raise ValueError(f"feature header is {header!r}, expected schema {FEATURE_SPEC_VERSION}")

    train_ids = [
        row_id for row_id, meta in metadata.items()
        if splits.get(row_id, {}).get("split") == "train" and int(meta.get("label") or 0) == 0
    ]
    if len(train_ids) < 3:
        raise ValueError("at least three independently captured clean training windows are required")
    medians = {
        name: float(np.median([
            float(features[row_id][name]) for row_id in train_ids if features[row_id].get(name) not in (None, "")
        ] or [0.0]))
        for name in FEATURE_NAMES
    }

    def vector(row_id):
        return [
            medians[name] if features[row_id].get(name) in (None, "")
            else float(features[row_id][name])
            for name in FEATURE_NAMES
        ]

    x_train = np.asarray([vector(row_id) for row_id in train_ids], dtype=float)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=1)
    model.fit(x_train)
    train_scores = model.score_samples(x_train)
    anomalous = float(np.percentile(train_scores, 1))
    normal = float(np.percentile(train_scores, 99))

    val_ids = [row_id for row_id in features if splits.get(row_id, {}).get("split") == "val"]
    test_ids = [row_id for row_id in features if splits.get(row_id, {}).get("split") == "test"]
    threshold = _threshold(model, vector, val_ids, metadata, false_positive_budget, np)
    evaluation = {
        "validation": _evaluate(model, vector, val_ids, metadata, threshold),
        "test": _evaluate(model, vector, test_ids, metadata, threshold),
        "threshold_score_samples": threshold,
        "false_positive_budget": false_positive_budget,
    }
    trained_at = datetime.now(timezone.utc)
    model_version = version or trained_at.strftime("iforest-%Y%m%dT%H%M%SZ")
    dataset_manifest = _json(dataset / "manifest.json")
    metadata_out = {
        "model_version": model_version,
        "trained_at": trained_at.isoformat(),
        "feature_schema_version": FEATURE_SPEC_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "training_run_ids": dataset_manifest.get("runs", []),
        # An absolute path can itself contain a person's account name. The
        # run IDs identify the source while this keeps the artifact portable.
        "data_source": dataset.name,
        "library": "scikit-learn IsolationForest",
        "library_version": sklearn.__version__,
        "missing_value_handling": "training-partition median by feature",
        "score_scale": {"anomalous": anomalous, "normal": normal},
        "evaluation": evaluation,
    }
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "medians": medians}, out / "model.joblib")
    (out / "metadata.json").write_text(json.dumps(metadata_out, indent=2, sort_keys=True) + "\n")
    return out


def _threshold(model, vector, ids, metadata, budget, np):
    benign = [row_id for row_id in ids if int(metadata[row_id].get("label") or 0) == 0]
    if not benign:
        return float("-inf")
    scores = model.score_samples(np.asarray([vector(row_id) for row_id in benign], dtype=float))
    return float(np.quantile(scores, max(0.0, min(1.0, budget))))


def _evaluate(model, vector, ids, metadata, threshold):
    if not ids:
        return {"rows": 0, "false_positive_rate": None, "attack_detection_rate": None}
    scores = model.score_samples([vector(row_id) for row_id in ids])
    labels = [int(metadata[row_id].get("label") or 0) for row_id in ids]
    predictions = [score <= threshold for score in scores]
    benign = [pred for pred, label in zip(predictions, labels) if label == 0]
    attacks = [pred for pred, label in zip(predictions, labels) if label == 1]
    return {
        "rows": len(ids),
        "false_positive_rate": sum(benign) / len(benign) if benign else None,
        "attack_detection_rate": sum(attacks) / len(attacks) if attacks else None,
        "attack_rows": len(attacks),
        "benign_rows": len(benign),
    }


def _csv_by_id(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="") as handle:
        return {row["row_id"]: row for row in csv.DictReader(handle)}


def _json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--version", default="")
    parser.add_argument("--false-positive-budget", type=float, default=0.02)
    args = parser.parse_args(argv)
    output = train(args.dataset, args.out, version=args.version,
                   false_positive_budget=args.false_positive_budget)
    print(f"[train] wrote model and metadata to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
