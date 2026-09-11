"""Compare gateway rules and a fixed advisory model on a fresh capture.

This intentionally does not call ``train`` or select a score threshold.  A
fresh run is the final hold-out: the model artifact supplies the threshold that
was selected on its earlier validation data, and this command only measures
what happened on new traffic.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from iasg.ml.evaluate import _by_id, _false_positives, _recall
from iasg.ml.login_regularity import login_regularity


def validate(dataset: str | Path, artifact: str | Path) -> dict:
    """Return three detection views for an independently collected dataset.

    ``detector_fired`` is evidence from deterministic gateway detectors, not a
    policy write.  A gateway miss also excludes windows where the gateway
    already refused traffic: detectors cannot observe requests that never
    reach them, and counting those as misses would misrepresent their reach.
    """
    import joblib
    import numpy as np

    dataset, artifact = Path(dataset), Path(artifact)
    features = _by_id(dataset / "features.csv")
    metadata = _by_id(dataset / "metadata.csv")
    quality = _by_id(dataset / "quality.csv")
    details = json.loads((artifact / "metadata.json").read_text())
    try:
        threshold = float(details["evaluation"]["threshold_score_samples"])
    except (KeyError, TypeError, ValueError) as err:
        raise ValueError("artifact has no fixed validation threshold") from err

    bundle = joblib.load(artifact / "model.joblib")
    model, medians = bundle["model"], bundle["medians"]
    names = tuple(details["feature_names"])
    regularity = (details.get("engineered_features") or {}).get("login_regularity")

    def vector(row_id: str) -> list[float]:
        row = features[row_id]
        base = [
            medians[name] if row.get(name) in (None, "") else float(row[name])
            for name in names
        ]
        if regularity:
            value = login_regularity(
                base[names.index("login_ratio")],
                base[names.index("interarrival_cv")],
            )
            base += [value] * int(regularity["repeated"])
        return base

    ids = sorted(features, key=lambda row_id: int(row_id))
    scored = {
        row_id: quality.get(row_id, {}).get("insufficient_history") != "True"
        for row_id in ids
    }
    scorable = [row_id for row_id in ids if scored[row_id]]
    raw = model.score_samples(np.asarray([vector(row_id) for row_id in scorable], dtype=float))
    ml_detected = dict.fromkeys(ids, False)
    ml_detected.update({
        row_id: (
            float(score) <= threshold
            or (
                regularity is not None
                and regularity.get("benign_validation_max") is not None
                and login_regularity(
                    float(features[row_id].get("login_ratio") or 0.0),
                    float(features[row_id].get("interarrival_cv") or 0.0),
                ) > float(regularity["benign_validation_max"])
            )
        )
        for row_id, score in zip(scorable, raw)
    })
    rules_detected = {
        row_id: metadata[row_id].get("detector_fired") in ("1", "true", "True")
        for row_id in ids
    }
    combined_detected = {
        row_id: rules_detected[row_id] or ml_detected[row_id] for row_id in ids
    }

    def label_of(row_id: str) -> int:
        return int(metadata[row_id].get("label") or 0)

    def by_mode(detected: dict[str, bool], mode_scored: dict[str, bool]) -> dict:
        attack = [row_id for row_id in ids if label_of(row_id) == 1]
        benign = [row_id for row_id in ids if label_of(row_id) == 0]
        result = {
            "personas": {},
            "scenarios": {},
            "pooled": {
                "benign": _false_positives(benign, mode_scored, detected, 100),
                "attack": _recall(attack, mode_scored, detected),
            },
        }
        for persona in sorted({metadata[row_id].get("persona") or "<unknown>" for row_id in benign}):
            member_ids = [
                row_id for row_id in benign
                if (metadata[row_id].get("persona") or "<unknown>") == persona
            ]
            result["personas"][persona] = _false_positives(member_ids, mode_scored, detected, 100)
        for scenario in sorted({metadata[row_id].get("scenario") or "<unknown>" for row_id in attack}):
            member_ids = [
                row_id for row_id in attack
                if (metadata[row_id].get("scenario") or "<unknown>") == scenario
            ]
            result["scenarios"][scenario] = _recall(member_ids, mode_scored, detected)
        return result

    all_scored = dict.fromkeys(ids, True)
    gateway_missed = [
        row_id for row_id in ids
        if label_of(row_id) == 1
        and not rules_detected[row_id]
        and metadata[row_id].get("gateway_blocked") not in ("1", "true", "True")
    ]
    missed_by_scenario = {}
    for scenario in sorted({metadata[row_id].get("scenario") or "<unknown>" for row_id in gateway_missed}):
        member_ids = [
            row_id for row_id in gateway_missed
            if (metadata[row_id].get("scenario") or "<unknown>") == scenario
        ]
        missed_by_scenario[scenario] = {
            "gateway_missed_attack_minutes": len(member_ids),
            "advisory_ml": _recall(member_ids, scored, ml_detected),
            "rules_plus_advisory_ml": _recall(member_ids, scored, combined_detected),
        }

    return {
        "dataset": dataset.name,
        "artifact": details.get("model_version"),
        "threshold_score_samples": threshold,
        "threshold_source": "artifact validation data; not selected on this fresh run",
        "rules_only": by_mode(rules_detected, all_scored),
        "advisory_ml_only": by_mode(ml_detected, scored),
        "rules_plus_advisory_ml": by_mode(combined_detected, all_scored),
        "gateway_missed_attack_minute_coverage": missed_by_scenario,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--out", default="", help="write report JSON here")
    args = parser.parse_args(argv)

    report = validate(args.dataset, args.artifact)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n")
        print(f"[validate] wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
