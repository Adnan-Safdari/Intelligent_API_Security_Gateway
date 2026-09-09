"""
Turn raw capture into a frozen dataset.

The output is deliberately several files rather than one table, because the
split between them is the leakage guard. features.csv physically cannot contain
an address, a label or a timestamp -- those live in metadata.csv -- and a check
asserts its header is exactly row_id plus the twelve. A guarantee that depends
on nobody adding the wrong column is not a guarantee.

FROZEN marks a directory as finished. A frozen dataset is not rebuilt in place:
a model trained on it has no way to notice that its inputs changed underneath.
"""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from iasg.anomaly.checks import check_feature_header, check_no_identifying_columns
from iasg.anomaly.extract import WindowRow, build_as_of, extract
from iasg.anomaly.impute import Medians
from iasg.anomaly.quality import WindowHealth
from iasg.anomaly.records import join
from iasg.anomaly.spec import FEATURE_NAMES, FEATURE_SPEC_VERSION, QUALITY_NAMES
from iasg.anomaly.windows import assign, window_start
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


class UnplannedTrafficTooHigh(RuntimeError):
    """
    Raised rather than filtering, when a run is mostly traffic nobody planned.

    A handful of stray windows is something to drop and count. A run where a
    large share of the traffic came from addresses the plan never assigned is a
    run that was collected while something else was talking to the gateway, and
    filtering it would leave a dataset shaped by whatever that was.
    """


# Above this share of a run's windows, the run is wrong rather than dirty.
UNPLANNED_ROW_LIMIT = 0.05


@dataclass
class BuiltRow:
    row_id: int
    run_id: str
    row: WindowRow
    label: int
    scenario: str
    persona: str = ""
    split: str = ""


@dataclass
class RunRows:
    """One run's rows, plus what was thrown away getting them."""

    rows: list[BuiltRow]
    unplanned_rows: int = 0
    unplanned_ips: tuple[str, ...] = ()


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


def health_by_window(entries: Iterable[dict], trim_losses: bool) -> dict[datetime, WindowHealth]:
    """
    Fold the heartbeat into one verdict per minute.

    A window is fully observed only if sixty consecutive sequence numbers cover
    it. A gap means the gateway was not running for part of the minute, which
    otherwise reads as a quiet one.
    """
    from iasg.anomaly.records import parse_ts

    seen: dict[datetime, list[dict]] = {}
    for entry in entries:
        at = parse_ts(entry.get("at"))
        if at is None:
            continue
        seen.setdefault(window_start(at), []).append(entry)

    verdicts: dict[datetime, WindowHealth] = {}
    for start, beats in seen.items():
        beats.sort(key=lambda b: b.get("seq", 0))
        seqs = [b.get("seq", 0) for b in beats]
        contiguous = len(seqs) == 60 and seqs == list(range(seqs[0], seqs[0] + 60))

        dropped = 0
        if beats:
            first, last = beats[0], beats[-1]
            # A delta, because the counter is cumulative for the process's
            # whole life. Negative means a restart, and a restart is a gap.
            dropped = max(
                0,
                (last.get("droppedTotal", 0) + last.get("arrivalsDroppedTotal", 0))
                - (first.get("droppedTotal", 0) + first.get("arrivalsDroppedTotal", 0)),
            )
        verdicts[start] = WindowHealth(
            dropped=dropped,
            fully_observed=contiguous and dropped == 0 and not trim_losses,
        )
    return verdicts


def load_sessions(run: RawRun) -> dict[str, str] | None:
    """
    Which address the plan gave to which persona or scenario.

    Returns None when the run has no sessions.jsonl at all, which means the run
    predates the file rather than that every address in it was unplanned --
    those two have to be distinguishable, because treating the first as the
    second would silently produce an empty dataset.
    """
    if not run.sessions.exists():
        return None
    planned: dict[str, str] = {}
    for line in run.sessions.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            session = json.loads(line)
        except json.JSONDecodeError:
            continue
        if session.get("ip"):
            planned[session["ip"]] = session.get("name", "")
    return planned


def rows_for_run(run: RawRun, run_id: str) -> RunRows:
    """
    Windows for the addresses this run planned, and only those.

    An address the plan never assigned is *unlabelled*, not benign: nothing in
    attacks.jsonl covers it, so label_for answers 0 and it would join the class
    the anomaly model is fitted on. That is how a stray browser tab teaches the
    model what normal looks like.
    """
    arrivals = read_jsonl(run.arrivals)
    completions = read_jsonl(run.completions)
    attacks = load_attacks(run.attacks.read_text().splitlines() if run.attacks.exists() else [])
    planned = load_sessions(run)

    manifest = json.loads(run.manifest.read_text()) if run.manifest.exists() else {}
    streams = (manifest.get("capture") or {}).get("streams") or {}
    trim_losses = any(s.get("entries_lost") for s in streams.values())

    health = health_by_window(read_jsonl(run.health), trim_losses)
    grouped = assign(join(arrivals, completions))

    built: list[BuiltRow] = []
    unplanned_rows = 0
    unplanned_ips: set[str] = set()
    for (ip, start), records in sorted(grouped.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        if planned is not None and ip not in planned:
            unplanned_rows += 1
            unplanned_ips.add(ip)
            continue
        # build_as_of, never now. Passing now is the single mistake that would
        # undo the availability guarantee, so the build never writes it.
        row = extract(records, start, build_as_of(start), health.get(start))
        built.append(
            BuiltRow(
                row_id=0,
                run_id=run_id,
                row=row,
                label=label_for(ip, start, attacks),
                scenario=scenario_for(ip, start, attacks),
                # Straight from the plan, so an attack session's quiet minute
                # reads persona=api_flood, scenario=benign -- the session was an
                # attack, that particular minute was outside its interval.
                persona=(planned or {}).get(ip, ""),
            )
        )

    total = len(built) + unplanned_rows
    if planned is not None and total and unplanned_rows / total > UNPLANNED_ROW_LIMIT:
        raise UnplannedTrafficTooHigh(
            f"{run_id}: {unplanned_rows} of {total} windows came from addresses the "
            f"plan never assigned ({', '.join(sorted(unplanned_ips))}). Discard the "
            f"run rather than filtering it."
        )
    return RunRows(built, unplanned_rows, tuple(sorted(unplanned_ips)))


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
    unplanned: list[tuple[str, int, tuple[str, ...]]] = []
    for raw in raw_dirs:
        run = RawRun.at(raw)
        manifest = json.loads(run.manifest.read_text()) if run.manifest.exists() else {}
        run_id = manifest.get("run_id") or Path(raw).name
        run_ids.append(run_id)
        result = rows_for_run(run, run_id)
        built.extend(result.rows)
        if result.unplanned_rows:
            unplanned.append((run_id, result.unplanned_rows, result.unplanned_ips))
            print(
                f"[build] {run_id}: dropped {result.unplanned_rows} window(s) from "
                f"unplanned addresses: {', '.join(result.unplanned_ips)}"
            )

    built.sort(key=lambda b: (b.row.window_start, b.run_id, b.row.ip))
    for index, item in enumerate(built, start=1):
        item.row_id = index
        item.split = split.assign(
            split.group_key(item.run_id, item.row.ip), item.label, item.scenario
        )

    check_reserved(
        [{"scenario": b.scenario, "split": b.split} for b in built]
    )

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
    _write_evaluation(out / "evaluation.md", built, unplanned)
    _write_manifest(out / "manifest.json", out, run_ids, built)
    (out / "FROZEN").write_text(datetime.now(timezone.utc).isoformat() + "\n")
    return out


def _write_features(path: Path, built: Sequence[BuiltRow]) -> None:
    """
    row_id plus the twelve, and nothing else, ever.

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
        writer.writerow(
            ["row_id", "run_id", "ip", "window_start", "label", "scenario", "persona"]
        )
        for item in built:
            writer.writerow([
                item.row_id, item.run_id, item.row.ip,
                item.row.window_start.isoformat(), item.label, item.scenario,
                item.persona,
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
                "ip": item.row.ip,
                "window_start": item.row.window_start.isoformat(),
                "label": item.label,
                "scenario": item.scenario,
                "persona": item.persona,
                "split": item.split,
                "features": item.row.features,
                "quality": item.row.quality.as_dict(),
            }, sort_keys=True) + "\n")


def _write_splits(path: Path, built: Sequence[BuiltRow]) -> None:
    with open(path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["row_id", "split", "group_key"])
        for item in built:
            writer.writerow([item.row_id, item.split, f"{item.run_id}|{item.row.ip}"])


def _write_versions(path: Path, run_ids: Sequence[str]) -> None:
    path.write_text(json.dumps({
        "spec_version": FEATURE_SPEC_VERSION,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "runs": list(run_ids),
    }, indent=2, sort_keys=True) + "\n")


def _unplanned_section(
    unplanned: Sequence[tuple[str, int, tuple[str, ...]]],
) -> list[str]:
    """
    What was dropped, named. Recorded in the dataset rather than only printed,
    because the build log is gone by the time anyone asks why a run looks thin.
    """
    if not unplanned:
        return []
    lines = [
        "### Dropped as unplanned",
        "",
        "Windows from addresses the run's plan never assigned. Unlabelled rather",
        "than benign -- nothing in attacks.jsonl covers them, so keeping them",
        "would have put unknown traffic in the class the model is fitted on.",
        "",
    ]
    for run_id, count, ips in unplanned:
        lines.append(f"- `{run_id}`: {count} rows from {', '.join(ips)}")
    lines.append("")
    return lines


def _write_evaluation(
    path: Path,
    built: Sequence[BuiltRow],
    unplanned: Sequence[tuple[str, int, tuple[str, ...]]] = (),
) -> None:
    """
    Written before any model is fit, on purpose.

    Deciding what counts as success after seeing the scores is how a result
    gets talked into existing. Per-persona false positives are reported
    separately so "the mobile poller is always flagged" is visible rather than
    averaged away, and abstentions are counted as abstentions rather than
    misses.

    The benign persona counts are listed because metric 1 is only meaningful if
    every persona actually has test mass. A persona with two rows cannot have a
    false-positive rate worth reporting, and that has to be visible here rather
    than discovered afterwards.
    """
    from collections import Counter

    by_split = Counter(b.split for b in built)
    by_scenario = Counter(b.scenario for b in built)
    by_persona = Counter(b.persona or "<unknown>" for b in built if b.label == 0)
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
        "### Benign rows per persona",
        "",
        *[f"- `{name}`: {count} rows" for name, count in sorted(by_persona.items())],
        "",
        *_unplanned_section(unplanned),
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
