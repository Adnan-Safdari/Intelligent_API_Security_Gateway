"""
Score a trained model against the evaluation protocol, not against itself.

`train.py` reports a pooled false-positive rate and a pooled detection rate.
Both are the numbers the protocol says not to report on their own:
`gateway/docs/anomaly-evaluation.md` fixes a per-persona budget, and requires
coverage, conditional recall and operational recall together, because
abstentions are not spread evenly across scenarios and a pooled figure hides
where they sit.

Nothing here selects a threshold after seeing test. The threshold comes from
validation alone; test is read once, at the end, with the threshold already
fixed.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

# Imported, not reimplemented: a duplicated transform could silently score an
# artifact against a vector with different semantics than training used.
from iasg.ml.login_regularity import login_regularity

# Below this many rows a false-positive rate is not a measurement. The protocol
# reports these personas as a count with an interval instead of gating on them:
# zero failures in fifty rows is consistent with a true rate near six percent.
GATE_MIN_ROWS = 100
DEFAULT_BUDGET = 0.01


def evaluate(
    dataset: str | Path,
    artifact: str | Path,
    *,
    budget: float = DEFAULT_BUDGET,
    gate_min_rows: int = GATE_MIN_ROWS,
    admitted_only: bool = False,
) -> dict:
    import joblib
    import numpy as np

    dataset, artifact = Path(dataset), Path(artifact)
    features = _by_id(dataset / "features.csv")
    metadata = _by_id(dataset / "metadata.csv")
    splits = _by_id(dataset / "splits.csv")
    quality = _by_id(dataset / "quality.csv")

    details = json.loads((artifact / "metadata.json").read_text())
    bundle = joblib.load(artifact / "model.joblib")
    model, medians = bundle["model"], bundle["medians"]
    names = tuple(details["feature_names"])
    engineered = details.get("engineered_features") or {}
    regularity = engineered.get("login_regularity")

    def vector(row_id):
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
            base = base + [value] * int(regularity["repeated"])
        return base

    def abstains(row_id) -> bool:
        # The runtime declines to score a window of one or two requests: it has
        # no meaningful inter-arrival statistics. ModelScorer.score returns a
        # null score for exactly this, so an evaluation that scored these rows
        # anyway would be measuring something the runtime never does.
        return quality.get(row_id, {}).get("insufficient_history") == "True"

    def split_of(row_id) -> str:
        return splits.get(row_id, {}).get("split", "")

    def label_of(row_id) -> int:
        return int(metadata[row_id].get("label") or 0)

    def admitted(row_id: str) -> bool:
        # The protocol's admission rule, applied identically here and in
        # training. A half-observed minute is not a quiet one, and measuring
        # against it compares the model to traffic that was never fully seen.
        if not admitted_only:
            return True
        return quality.get(row_id, {}).get("interval_fully_observed") == "True"

    features = {r: v for r, v in features.items() if admitted(r)}
    scored = {row_id: not abstains(row_id) for row_id in features}
    scorable = [row_id for row_id in features if scored[row_id]]
    raw = model.score_samples(np.asarray([vector(r) for r in scorable], dtype=float))
    score = dict(zip(scorable, (float(v) for v in raw)))

    threshold, selection = _select_threshold(
        score, metadata, splits, scored, budget, gate_min_rows, np
    )

    # Lower score_samples means more anomalous, so detection is <= threshold.
    detected = {row_id: value <= threshold for row_id, value in score.items()}

    report = {
        "dataset": dataset.name,
        "model_version": details.get("model_version"),
        "feature_schema_version": details.get("feature_schema_version"),
        "runtime_loadable": details.get("runtime_loadable"),
        "budget": budget,
        "admission_rule": "interval_fully_observed" if admitted_only else "none",
        "gate_min_rows": gate_min_rows,
        "threshold_score_samples": threshold,
        "threshold_selection": selection,
        "coverage": {},
        "scenarios": {},
        "personas": {},
        "pooled": {},
    }

    for split in ("train", "val", "test"):
        ids = [r for r in features if split_of(r) == split]
        report["coverage"][split] = _coverage(ids, scored, label_of)

    test_ids = [r for r in features if split_of(r) == "test"]
    for scenario in sorted({metadata[r]["scenario"] for r in test_ids}):
        ids = [r for r in test_ids if metadata[r]["scenario"] == scenario]
        if not ids or label_of(ids[0]) == 0:
            continue
        report["scenarios"][scenario] = _recall(ids, scored, detected)

    benign_test = [r for r in test_ids if label_of(r) == 0]
    for persona in sorted({metadata[r].get("persona") or "<unknown>" for r in benign_test}):
        ids = [r for r in benign_test if (metadata[r].get("persona") or "<unknown>") == persona]
        report["personas"][persona] = _false_positives(ids, scored, detected, gate_min_rows)

    report["pooled"] = {
        "benign": _false_positives(benign_test, scored, detected, gate_min_rows),
        "attack": _recall([r for r in test_ids if label_of(r) == 1], scored, detected),
    }
    return report


def _select_threshold(score, metadata, splits, scored, budget, gate_min_rows, np):
    """
    The largest threshold that keeps every gated persona and the pooled rate
    inside the budget.

    A pooled quantile alone would satisfy the budget on average while letting
    one persona sit far above it, which is the failure the per-persona rule
    exists to make visible.
    """
    benign_val = [
        row_id for row_id in score
        if splits.get(row_id, {}).get("split") == "val"
        and int(metadata[row_id].get("label") or 0) == 0
    ]
    if not benign_val:
        return float("-inf"), {"reason": "no scorable benign validation rows"}

    values = np.asarray([score[r] for r in benign_val], dtype=float)
    limits = {"pooled": float(np.quantile(values, budget))}

    by_persona: dict[str, list[float]] = {}
    for row_id in benign_val:
        persona = metadata[row_id].get("persona") or "<unknown>"
        by_persona.setdefault(persona, []).append(score[row_id])

    for persona, scores in sorted(by_persona.items()):
        if len(scores) >= gate_min_rows:
            limits[persona] = float(np.quantile(np.asarray(scores, dtype=float), budget))

    binding = min(limits, key=limits.get)
    return limits[binding], {
        "binding_constraint": binding,
        "limits": limits,
        "gated_personas": sorted(p for p in limits if p != "pooled"),
        "ungated_personas": sorted(
            p for p, s in by_persona.items() if len(s) < gate_min_rows
        ),
        "validation_benign_rows": len(benign_val),
    }


def _coverage(ids, scored, label_of) -> dict:
    out = {}
    for name, subset in (
        ("all", ids),
        ("benign", [r for r in ids if label_of(r) == 0]),
        ("attack", [r for r in ids if label_of(r) == 1]),
    ):
        total = len(subset)
        got = sum(1 for r in subset if scored[r])
        out[name] = {
            "rows": total,
            "scored": got,
            "abstained": total - got,
            "coverage": got / total if total else None,
        }
    return out


def _recall(ids, scored, detected) -> dict:
    """
    Three numbers, never one.

    Conditional recall alone would publish a blind spot as perfect detection:
    a window that abstained was not detected by this layer, whatever the
    conditional figure says about the ones that were scored.
    """
    total = len(ids)
    scored_ids = [r for r in ids if scored[r]]
    hits = sum(1 for r in scored_ids if detected[r])
    return {
        "rows": total,
        "scored": len(scored_ids),
        "abstained": total - len(scored_ids),
        "detected": hits,
        "coverage": len(scored_ids) / total if total else None,
        "conditional_recall": hits / len(scored_ids) if scored_ids else None,
        "operational_recall": hits / total if total else None,
    }


def _false_positives(ids, scored, detected, gate_min_rows) -> dict:
    total = len(ids)
    scored_ids = [r for r in ids if scored[r]]
    hits = sum(1 for r in scored_ids if detected[r])
    low, high = _interval(hits, len(scored_ids))
    return {
        "rows": total,
        "scored": len(scored_ids),
        "abstained": total - len(scored_ids),
        "false_positives": hits,
        "false_positive_rate": hits / len(scored_ids) if scored_ids else None,
        "ci95": [low, high],
        "gated": len(ids) >= gate_min_rows,
    }


def _interval(successes: int, total: int) -> tuple[float | None, float | None]:
    """
    Clopper-Pearson. Zero failures in a small sample is not evidence of a low
    rate -- with fifty rows the upper bound is near six percent -- and a bare
    0.0% would claim otherwise.
    """
    if not total:
        return None, None
    try:
        from scipy.stats import beta
    except ImportError:
        return None, None
    low = float(beta.ppf(0.025, successes, total - successes + 1)) if successes else 0.0
    high = (
        float(beta.ppf(0.975, successes + 1, total - successes))
        if successes < total else 1.0
    )
    return low, high


def _by_id(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="") as handle:
        return {row["row_id"]: row for row in csv.DictReader(handle)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--budget", type=float, default=DEFAULT_BUDGET)
    parser.add_argument("--gate-min-rows", type=int, default=GATE_MIN_ROWS)
    parser.add_argument(
        "--admitted-only", action="store_true",
        help="apply the protocol's admission rule: fully observed windows only.",
    )
    parser.add_argument("--out", default="", help="write the report JSON here")
    args = parser.parse_args(argv)

    report = evaluate(
        args.dataset, args.artifact,
        budget=args.budget, gate_min_rows=args.gate_min_rows,
        admitted_only=args.admitted_only,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n")
        print(f"[evaluate] wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
