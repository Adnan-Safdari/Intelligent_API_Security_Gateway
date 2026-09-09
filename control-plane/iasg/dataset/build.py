"""
Turn raw capture into a frozen dataset.

The output is deliberately several files rather than one table, because the
split between them is the leakage guard. features.csv physically cannot contain
an address, a label or a timestamp; metadata carries an opaque per-export
client id, never the raw address. A check asserts its header is exactly row_id
plus the versioned features. A guarantee that depends
on nobody adding the wrong column is not a guarantee.

FROZEN marks a directory as finished. A frozen dataset is not rebuilt in place:
a model trained on it has no way to notice that its inputs changed underneath.
"""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import secrets
import sys
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from iasg.anomaly.checks import check_feature_header, check_no_identifying_columns
from iasg.anomaly.extract import WindowRow, build_as_of, extract
from iasg.anomaly.health import health_by_window
from iasg.anomaly.impute import Medians
from iasg.anomaly.records import join
from iasg.anomaly.spec import FEATURE_NAMES, FEATURE_SPEC_VERSION, QUALITY_NAMES
from iasg.anomaly.windows import assign, window_start
from iasg.adaptive.baseline import BaselineLearner, EndpointKey, MemoryBaselineRepository
from iasg.adaptive.config import AdaptiveConfig
from iasg.dataset.labels import Attack, label_for, load_attacks, scenario_for
from iasg.dataset.layout import RawRun
from iasg.dataset.splits import RESERVED_SCENARIOS, Split, TRAIN, check_reserved


class LeakageCheckFailed(RuntimeError):
    """
    Raised instead of freezing a dataset whose feature matrix carries an
    identity.

    checks.py has stated this guarantee since it was written, but only pytest
    ever asked. A guarantee nothing enforces at the moment it could be broken
    is a comment: the build would have written the column, printed success and
    stamped FROZEN.
    """


class DatasetFrozen(RuntimeError):
    """Raised rather than overwriting. Rebuilding a frozen directory in place
    changes what a trained model's inputs meant, silently."""


@dataclass
class BuiltRow:
    row_id: int
    run_id: str
    row: WindowRow
    label: int
    scenario: str
    split: str = ""
    client_id: str = ""
    endpoint_counts: dict[tuple[str, str], int] = None
    safe_to_learn: bool = False


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            # One unparseable line does not abandon a run. It is a defect, and
            # the quality columns are where defects are reported.
            continue
    return out


def rows_for_run(run: RawRun, run_id: str) -> list[BuiltRow]:
    arrivals = read_jsonl(run.arrivals)
    completions = read_jsonl(run.completions)
    completions_by_id = {
        value.get("requestId"): value for value in completions if value.get("requestId")
    }
    attacks = load_attacks(run.attacks.read_text().splitlines() if run.attacks.exists() else [])

    manifest = json.loads(run.manifest.read_text()) if run.manifest.exists() else {}
    streams = (manifest.get("capture") or {}).get("streams") or {}
    trim_losses = any(s.get("entries_lost") for s in streams.values())

    health = health_by_window(read_jsonl(run.health), trim_losses)
    grouped = assign(join(arrivals, completions))

    built: list[BuiltRow] = []
    for (ip, start), records in sorted(grouped.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        # build_as_of, never now. Passing now is the single mistake that would
        # undo the availability guarantee, so the build never writes it.
        row = extract(records, start, build_as_of(start), health.get(start))
        label = label_for(ip, start, attacks)
        ids = {record.request_id for record in records}
        observed = [completions_by_id.get(request_id) for request_id in ids]
        safe_to_learn = (
            label == 0
            and all(value is not None for value in observed)
            and all((value.get("decision") or "allow") == "allow" for value in observed)
            and not any(value.get("fired") for value in observed)
            and row.quality.interval_fully_observed
        )
        built.append(
            BuiltRow(
                row_id=0,
                run_id=run_id,
                row=row,
                label=label,
                scenario=scenario_for(ip, start, attacks),
                endpoint_counts=dict(Counter(
                    (record.method, record.route_template) for record in records
                )),
                safe_to_learn=safe_to_learn,
            )
        )
    return built


def build(
    raw_dirs: Sequence[str | Path],
    out_dir: str | Path,
    split: Split | None = None,
    force: bool = False,
) -> Path:
    out = Path(out_dir)
    if (out / "FROZEN").exists() and not force:
        raise DatasetFrozen(f"{out} is frozen; build a new version instead")
    out.mkdir(parents=True, exist_ok=True)
    split = split or Split()

    built: list[BuiltRow] = []
    run_ids: list[str] = []
    for raw in raw_dirs:
        run = RawRun.at(raw)
        manifest = json.loads(run.manifest.read_text()) if run.manifest.exists() else {}
        run_id = manifest.get("run_id") or Path(raw).name
        run_ids.append(run_id)
        built.extend(rows_for_run(run, run_id))

    built.sort(key=lambda b: (b.row.window_start, b.run_id, b.row.ip))
    privacy_key = secrets.token_bytes(32)
    for index, item in enumerate(built, start=1):
        item.row_id = index
        item.split = split.assign(
            split.group_key(item.run_id, item.row.ip), item.label, item.scenario
        )
        # Grouping uses the resolved client identity in memory, but exported
        # datasets never retain the address. A per-export keyed digest keeps
        # one client's windows together without creating a reversible IP hash.
        item.client_id = hashlib.blake2b(
            f"{item.run_id}\0{item.row.ip}".encode(),
            key=privacy_key,
            digest_size=12,
        ).hexdigest()

    check_reserved(
        [{"scenario": b.scenario, "split": b.split} for b in built]
    )

    _derive_endpoint_deviation(built)

    # Medians from the training partition only. A median over the whole dataset
    # would leak the test partition into the model through the back door.
    training = [b.row for b in built if b.split == TRAIN]
    medians = Medians.fit(training) if training else None

    _write_features(out / "features.csv", built)
    # Checked on the file, not on the code that wrote it. The physical split is
    # the leakage guard, so it is the file that has to be right.
    failures = (
        check_feature_header(out / "features.csv")
        + check_no_identifying_columns(out / "features.csv")
    )
    if failures:
        raise LeakageCheckFailed("; ".join(str(f) for f in failures))

    _write_metadata(out / "metadata.csv", built)
    _write_quality(out / "quality.csv", built)
    _write_rows(out / "rows.jsonl", built)
    _write_splits(out / "splits.csv", built)
    if medians is not None:
        medians.save(out / "medians.json")
    (out / "held_out_scenarios.txt").write_text("\n".join(RESERVED_SCENARIOS) + "\n")
    _write_versions(out / "versions.json", run_ids)
    _write_evaluation(out / "evaluation.md", built)
    _write_manifest(out / "manifest.json", out, run_ids, built)
    (out / "FROZEN").write_text(datetime.now(timezone.utc).isoformat() + "\n")
    return out


def _derive_endpoint_deviation(built: Sequence[BuiltRow]) -> None:
    """Fit only on earlier clean training rows, then fill schema-v2 column."""
    repository = MemoryBaselineRepository()
    learner = BaselineLearner(repository, AdaptiveConfig().baseline)
    for item in built:
        deviations = []
        for (method, route), observed in (item.endpoint_counts or {}).items():
            key = EndpointKey.of(method, route)
            deviations.append(learner.deviation(repository.get_baseline(key), observed))
        features = dict(item.row.features)
        features["endpoint_method_deviation"] = max(deviations, default=0.0)
        item.row = replace(item.row, features=features)

        trusted = item.split == TRAIN and item.safe_to_learn
        for (method, route), observed in (item.endpoint_counts or {}).items():
            learner.observe(
                EndpointKey.of(method, route), observed,
                trusted=trusted,
                now=item.row.window_start,
            )


def _write_features(path: Path, built: Sequence[BuiltRow]) -> None:
    """
    row_id plus the versioned feature set, and nothing else, ever.

    Unknowns are written empty rather than imputed. Imputation belongs at
    vectorisation time using training medians, and baking it in here would make
    the file unable to say what was never measured.
    """
    with open(path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["row_id", *FEATURE_NAMES])
        for item in built:
            values = ["" if v is None else v for v in item.row.feature_tuple()]
            writer.writerow([item.row_id, *values])


def _write_metadata(path: Path, built: Sequence[BuiltRow]) -> None:
    """Everything that identifies a row, kept out of the feature matrix by
    living in a different file."""
    with open(path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["row_id", "run_id", "client_id", "window_start", "label", "scenario"])
        for item in built:
            writer.writerow([
                item.row_id, item.run_id, item.client_id,
                item.row.window_start.isoformat(), item.label, item.scenario,
            ])


def _write_quality(path: Path, built: Sequence[BuiltRow]) -> None:
    with open(path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["row_id", *QUALITY_NAMES])
        for item in built:
            quality = item.row.quality.as_dict()
            writer.writerow([item.row_id, *[quality[name] for name in QUALITY_NAMES]])


def _write_rows(path: Path, built: Sequence[BuiltRow]) -> None:
    """One line per row, everything together. For inspection and for
    recomputing a row by hand -- not for training."""
    with open(path, "w") as handle:
        for item in built:
            handle.write(json.dumps({
                "row_id": item.row_id,
                "run_id": item.run_id,
                "client_id": item.client_id,
                "window_start": item.row.window_start.isoformat(),
                "label": item.label,
                "scenario": item.scenario,
                "split": item.split,
                "features": item.row.features,
                "quality": item.row.quality.as_dict(),
            }, sort_keys=True) + "\n")


def _write_splits(path: Path, built: Sequence[BuiltRow]) -> None:
    with open(path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["row_id", "split", "group_key"])
        for item in built:
            writer.writerow([item.row_id, item.split, f"{item.run_id}|{item.client_id}"])


def _write_versions(path: Path, run_ids: Sequence[str]) -> None:
    path.write_text(json.dumps({
        "spec_version": FEATURE_SPEC_VERSION,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "runs": list(run_ids),
    }, indent=2, sort_keys=True) + "\n")


def _write_evaluation(path: Path, built: Sequence[BuiltRow]) -> None:
    """
    Written before any model is fit, on purpose.

    Deciding what counts as success after seeing the scores is how a result
    gets talked into existing. Per-persona false positives are reported
    separately so "the mobile poller is always flagged" is visible rather than
    averaged away, and abstentions are counted as abstentions rather than
    misses.
    """
    from collections import Counter

    by_split = Counter(b.split for b in built)
    by_scenario = Counter(b.scenario for b in built)
    abstained = sum(1 for b in built if b.row.quality.insufficient_history)
    unobserved = sum(1 for b in built if not b.row.quality.interval_fully_observed)

    lines = [
        "# Evaluation plan",
        "",
        "Written by the build, before any model is fit. Deciding what counts as",
        "success after seeing the scores is how a result gets talked into existing.",
        "",
        "## What this dataset contains",
        "",
        f"- Rows: {len(built)}",
        f"- Split: " + ", ".join(f"{k}={v}" for k, v in sorted(by_split.items())),
        f"- Attack rows: {sum(1 for b in built if b.label == 1)}",
        f"- Abstaining rows (1-2 requests): {abstained}",
        f"- Rows in an incompletely observed minute: {unobserved}",
        "",
        "### Scenarios",
        "",
        *[f"- `{name}`: {count} rows" for name, count in sorted(by_scenario.items())],
        "",
        "## How it will be measured",
        "",
        "1. **False positives on benign test traffic, per persona.** Reported",
        "   separately, never averaged: one persona always being flagged is a",
        "   different failure from a uniform low rate, and the average hides it.",
        "2. **Detection per attack scenario**, per scenario and not pooled.",
        "3. **Coverage**, with abstentions counted as abstentions. A window that",
        "   declined to score is not a miss -- the Go detectors inspected those",
        "   requests regardless.",
        "4. **Detection delay**, in windows.",
        "",
        "The threshold is chosen against a fixed false-positive budget on",
        "**validation**. Test is looked at once.",
        "",
        "## Held out",
        "",
        *[f"- `{name}`" for name in RESERVED_SCENARIOS],
        "",
        "These never appear outside test. They stay deliberately under the Go",
        "detectors' thresholds, so they are the only honest measure of whether",
        "this layer catches what the detectors miss.",
        "",
    ]
    path.write_text("\n".join(lines))


def _write_manifest(path: Path, out: Path, run_ids: Sequence[str], built: Sequence[BuiltRow]) -> None:
    """
    A sha256 per file. What makes a frozen dataset checkable rather than just
    labelled frozen.
    """
    digests = {}
    for file in sorted(out.iterdir()):
        if file.is_file() and file.name not in ("manifest.json", "FROZEN"):
            digests[file.name] = hashlib.sha256(file.read_bytes()).hexdigest()

    path.write_text(json.dumps({
        "spec_version": FEATURE_SPEC_VERSION,
        "runs": list(run_ids),
        "rows": len(built),
        "files": digests,
    }, indent=2, sort_keys=True) + "\n")


def verify(out_dir: str | Path) -> list[str]:
    """Re-hash every file against the manifest. A frozen dataset that has been
    edited is worse than one that was never frozen."""
    out = Path(out_dir)
    manifest = json.loads((out / "manifest.json").read_text())
    problems = []
    for name, digest in manifest["files"].items():
        file = out / name
        if not file.exists():
            problems.append(f"{name} is missing")
        elif hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            problems.append(f"{name} does not match its manifest digest")
    return problems


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", nargs="+", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--force", action="store_true", help="rebuild a frozen directory")
    args = parser.parse_args(argv)

    out = build(args.runs, args.out, force=args.force)
    problems = verify(out)
    if problems:
        for problem in problems:
            print(f"[build] {problem}")
        return 1
    print(f"[build] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
