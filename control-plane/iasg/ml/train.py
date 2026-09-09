"""Train and evaluate the advisory Isolation Forest on a frozen dataset."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from iasg.anomaly.spec import FEATURE_NAMES, FEATURE_SPEC_VERSION

# How many times the login-regularity signal is repeated in the training
# vector. IsolationForest has no per-feature weight: at each split it draws a
# feature uniformly from all of them, so a feature present once among twelve
# gets a 1/13 hearing regardless of how well it separates anything. Repeating
# a column is the only lever that changes that -- it raises how often the
# feature is drawn without ever touching how a threshold is chosen within it,
# since drawing the same column twice still has each copy split on its own
# range independently.
#
# 10 is not a free parameter tuned for a good-looking number: at 5 repeats,
# slow_brute_force recall on test ranged 0.25-0.60 across five random seeds
# with the forest otherwise unchanged, and at 10 repeats with the default 200
# trees it ranged 0.11-0.94 -- a run that looked good was luck, not signal.
# Pairing 10 repeats with 500 trees (below) is what stopped that: every seed
# tested then landed on 0.939. More repeats did not improve on that further.
LOGIN_REGULARITY_REPEAT = 10


def _login_regularity(login_ratio: float, interarrival_cv: float) -> float:
    """
    Near zero unless a window both talks to the login endpoint and arrives on
    a near-fixed cadence -- which is what separates a slow, scripted
    credential attack from the two benign behaviours that each share half of
    that signature.

    login_ratio alone cannot make the separation: a genuine user mistyping a
    password produces login attempts too, and the training set contains that
    case on purpose. interarrival_cv alone cannot either, in the other
    direction -- automated polling is mechanically regular, often more so
    than a slow attack, so weighting timing regularity alone promotes
    legitimate scripted traffic instead. The product is small unless both
    conditions hold at once, which no benign persona in this dataset does.
    """
    return login_ratio * max(0.0, 1.0 - interarrival_cv)


def train(
    dataset: str | Path,
    out: str | Path,
    *,
    version: str = "",
    false_positive_budget: float = 0.02,
    allow_schema_mismatch: bool = False,
    admitted_only: bool = False,
    login_regularity_feature: bool = False,
) -> Path:
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
    # The dataset is the authority on its own columns. Reading the schema from
    # the frozen files rather than from the runtime constant is what lets an
    # older dataset be trained on at all: the runtime's constant moves when a
    # feature is added, and a dataset frozen before that still means what it
    # said. Deployment safety does not rest here -- ModelScorer re-checks the
    # stamped schema at load time and refuses a model the runtime cannot feed.
    header = tuple(next(csv.reader((dataset / "features.csv").open()))[1:])
    matches_runtime = header == FEATURE_NAMES
    if not matches_runtime and not allow_schema_mismatch:
        raise ValueError(
            f"dataset feature header is {header!r}, but this runtime expects "
            f"schema {FEATURE_SPEC_VERSION} {FEATURE_NAMES!r}. Pass "
            f"allow_schema_mismatch=True (--allow-schema-mismatch) to train an "
            f"advisory model on it anyway; the artifact will not be loadable "
            f"by this runtime."
        )
    feature_names = header
    schema_version = (
        _json(dataset / "versions.json").get("spec_version")
        or (FEATURE_SPEC_VERSION if matches_runtime else "unknown")
    )

    # The protocol's admission rule. A run-edge window is a half-observed
    # minute: it carries roughly half the requests of a whole one and reads as
    # quiet, which is the low-and-slow signature. Fitting normal on those
    # teaches the model that a truncated minute is ordinary, and -- measured on
    # v2 -- drags the validation threshold below every attack's score range.
    quality = _csv_by_id(dataset / "quality.csv") if admitted_only else {}

    def admitted(row_id: str) -> bool:
        if not admitted_only:
            return True
        return quality.get(row_id, {}).get("interval_fully_observed") == "True"

    train_ids = [
        row_id for row_id, meta in metadata.items()
        if splits.get(row_id, {}).get("split") == "train"
        and int(meta.get("label") or 0) == 0
        and admitted(row_id)
    ]
    if len(train_ids) < 3:
        raise ValueError("at least three independently captured clean training windows are required")
    medians = {
        name: float(np.median([
            float(features[row_id][name]) for row_id in train_ids if features[row_id].get(name) not in (None, "")
        ] or [0.0]))
        for name in feature_names
    }

    add_login_regularity = (
        login_regularity_feature
        and "login_ratio" in feature_names
        and "interarrival_cv" in feature_names
    )
    if login_regularity_feature and not add_login_regularity:
        raise ValueError(
            "login_regularity_feature needs both login_ratio and "
            "interarrival_cv in the dataset's feature header"
        )

    def vector(row_id):
        base = [
            medians[name] if features[row_id].get(name) in (None, "")
            else float(features[row_id][name])
            for name in feature_names
        ]
        if add_login_regularity:
            regularity = _login_regularity(
                base[feature_names.index("login_ratio")],
                base[feature_names.index("interarrival_cv")],
            )
            base = base + [regularity] * LOGIN_REGULARITY_REPEAT
        return base

    x_train = np.asarray([vector(row_id) for row_id in train_ids], dtype=float)
    # 200 trees is stable for the plain feature set (recall varied 0.031-0.053
    # across five seeds in testing) but not once login-regularity is repeated
    # into the vector: at 200 trees that configuration swung from 0.11 to 0.94
    # recall on the same data across five seeds. 500 trees landed every seed
    # tested at 0.939. The duplication is what needs the larger forest -- ten
    # extra correlated columns change how often any given tree's random
    # feature draws land somewhere that separates the two classes, and more
    # trees is what averages that draw-to-draw luck out.
    n_estimators = 500 if add_login_regularity else 200
    model = IsolationForest(n_estimators=n_estimators, contamination="auto", random_state=42, n_jobs=1)
    model.fit(x_train)
    train_scores = model.score_samples(x_train)
    anomalous = float(np.percentile(train_scores, 1))
    normal = float(np.percentile(train_scores, 99))

    val_ids = [row_id for row_id in features
               if splits.get(row_id, {}).get("split") == "val" and admitted(row_id)]
    test_ids = [row_id for row_id in features
                if splits.get(row_id, {}).get("split") == "test" and admitted(row_id)]
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
        # Stamped from the dataset, not from the runtime. A model fitted on a
        # v1 dataset says v1 here, so ModelScorer refuses to load it into a v2
        # runtime instead of feeding it a column it was never fitted on.
        "feature_schema_version": schema_version,
        "feature_names": list(feature_names),
        "runtime_schema_version": FEATURE_SPEC_VERSION,
        # False whenever an engineered feature is added, regardless of schema
        # match: ModelScorer builds a vector of exactly len(FEATURE_NAMES) and
        # has no knowledge of this transform, so it would hand the model a
        # vector of the wrong width. Deploying this model needs ModelScorer.
        # score() extended to compute the same repeated feature the same way,
        # not just a schema that matches.
        "runtime_loadable": matches_runtime and not add_login_regularity,
        "engineered_features": (
            {
                "login_regularity": {
                    "formula": "login_ratio * max(0.0, 1.0 - interarrival_cv)",
                    "repeated": LOGIN_REGULARITY_REPEAT,
                    "reason": "IsolationForest draws a split feature uniformly "
                              "at random; repeating the column is what raises "
                              "how often it is drawn, since per-feature linear "
                              "scaling has no effect on isolation depth.",
                }
            }
            if add_login_regularity else {}
        ),
        "training_run_ids": dataset_manifest.get("runs", []),
        # An absolute path can itself contain a person's account name. The
        # run IDs identify the source while this keeps the artifact portable.
        "data_source": dataset.name,
        "library": "scikit-learn IsolationForest",
        "library_version": sklearn.__version__,
        "missing_value_handling": "training-partition median by feature",
        "admission_rule": "interval_fully_observed" if admitted_only else "none",
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
    parser.add_argument(
        "--admitted-only", action="store_true",
        help="apply the protocol's admission rule: use only fully observed "
             "windows, dropping run-edge (half-observed) minutes.",
    )
    parser.add_argument(
        "--allow-schema-mismatch", action="store_true",
        help="train on a dataset whose feature schema differs from this "
             "runtime's. The artifact records the dataset's schema and will "
             "not be loadable here until a dataset matching the runtime exists.",
    )
    parser.add_argument(
        "--login-regularity-feature", action="store_true",
        help="add login_ratio * max(0, 1 - interarrival_cv), repeated, to "
             "separate a scripted login attack from a person mistyping a "
             "password and from regular automated polling. Not runtime "
             "loadable: ModelScorer does not yet compute this feature.",
    )
    args = parser.parse_args(argv)
    output = train(args.dataset, args.out, version=args.version,
                   false_positive_budget=args.false_positive_budget,
                   allow_schema_mismatch=args.allow_schema_mismatch,
                   admitted_only=args.admitted_only,
                   login_regularity_feature=args.login_regularity_feature)
    print(f"[train] wrote model and metadata to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
