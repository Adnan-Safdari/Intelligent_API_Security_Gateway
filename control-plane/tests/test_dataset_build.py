"""
The build: labels from the manifest, groups placed whole, and a feature matrix
that physically cannot carry an identity.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone

import pytest

from iasg.anomaly.checks import check_feature_header, check_no_identifying_columns
from iasg.anomaly.spec import FEATURE_NAMES
from iasg.dataset.build import DatasetFrozen, build, health_by_window, verify
from iasg.dataset.labels import Attack, label_for, scenario_for
from iasg.dataset.layout import RawRun
from iasg.dataset.splits import RESERVED_SCENARIOS, ReservedScenarioMisplaced, Split, check_reserved

W = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def write_run(tmp_path, name, requests, attacks=(), health=()):
    run = RawRun.at(tmp_path / name)
    with open(run.arrivals, "w") as a, open(run.completions, "w") as c:
        for rec in requests:
            a.write(json.dumps({
                "requestId": rec["id"], "arrivalTs": iso(rec["at"]), "ip": rec["ip"],
                "method": rec.get("method", "GET"), "path": rec.get("path", "/api/products"),
                "routeTemplate": rec.get("route", "/api/products"),
            }) + "\n")
            if rec.get("done") is not None:
                c.write(json.dumps({
                    "requestId": rec["id"], "arrivalTs": iso(rec["at"]),
                    "ts": iso(rec["done"]), "ip": rec["ip"],
                    "method": rec.get("method", "GET"), "path": rec.get("path", "/api/products"),
                    "routeTemplate": rec.get("route", "/api/products"),
                    "responseOrigin": "backend", "upstreamStatus": rec.get("status", 200),
                    "upstreamDurationMs": 10, "requestBodyBytes": 0,
                }) + "\n")
    with open(run.attacks, "w") as f:
        for attack in attacks:
            f.write(json.dumps(attack) + "\n")
    with open(run.health, "w") as f:
        for beat in health:
            f.write(json.dumps(beat) + "\n")
    run.manifest.write_text(json.dumps({"run_id": name}))
    return run


def busy(ip, start, count=10, **kw):
    return [
        {"id": f"{ip}-{start.timestamp()}-{i}", "at": start + timedelta(seconds=i * 2),
         "ip": ip, "done": start + timedelta(seconds=i * 2, milliseconds=20), **kw}
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


def test_a_window_that_fired_signals_but_is_not_in_the_manifest_labels_zero(tmp_path):
    """
    The property the whole label design exists for. label_for takes an address,
    a window and the manifest's attacks -- it has no parameter through which
    detector output could reach it, so this cannot be got wrong by accident.
    """
    attacks = [Attack("credential_stuffing", "203.0.113.200", W, W + timedelta(minutes=5))]
    assert label_for("203.0.113.200", W, attacks) == 1
    # Same window, different address: benign whatever the detectors thought.
    assert label_for("203.0.113.10", W, attacks) == 0
    assert scenario_for("203.0.113.10", W, attacks) == "benign"


def test_label_for_cannot_see_detector_output():
    import inspect

    params = set(inspect.signature(label_for).parameters)
    assert params == {"ip", "window_start", "attacks", "window_seconds"}
    forbidden = {"fired", "risk_score", "decision", "status", "signals", "row"}
    assert not (params & forbidden)


def test_a_partly_covered_window_is_an_attack_window():
    """Requiring full coverage would label the first and last minute of every
    attack as benign, which is exactly where detection matters."""
    attacks = [Attack("burst", "203.0.113.200", W + timedelta(seconds=50), W + timedelta(seconds=70))]
    assert label_for("203.0.113.200", W, attacks) == 1
    assert label_for("203.0.113.200", W + timedelta(seconds=60), attacks) == 1
    assert label_for("203.0.113.200", W + timedelta(seconds=120), attacks) == 0


# ---------------------------------------------------------------------------
# Splits
# ---------------------------------------------------------------------------


def test_one_address_never_lands_in_two_partitions():
    split = Split()
    key = split.group_key("run1", "203.0.113.10")
    assignments = {split.assign(key, 0, "benign") for _ in range(20)}
    assert len(assignments) == 1


def test_splits_are_deterministic_so_two_builds_are_comparable():
    a, b = Split(), Split()
    key = ("run1", "203.0.113.42", "")
    assert a.assign(key, 0, "benign") == b.assign(key, 0, "benign")


def test_attacks_never_enter_the_training_partition():
    """Train is benign only: an anomaly model fitted on attacks is a classifier
    with two examples of each."""
    split = Split()
    for i in range(50):
        assert split.assign(("run1", f"203.0.113.{i}", ""), 1, "credential_stuffing") != "train"


def test_reserved_scenarios_are_forced_to_test():
    split = Split()
    for scenario in RESERVED_SCENARIOS:
        for i in range(20):
            assert split.assign(("run1", f"203.0.113.{i}", ""), 1, scenario) == "test"


def test_a_misplaced_reserved_scenario_raises_rather_than_being_corrected():
    """Quietly moving it would hide that the splitter was asked to do the wrong
    thing; the evaluation would be invalid and look fine."""
    with pytest.raises(ReservedScenarioMisplaced):
        check_reserved([{"scenario": "slow_brute_force", "split": "val"}])


# ---------------------------------------------------------------------------
# Health folding
# ---------------------------------------------------------------------------


def test_a_full_minute_of_heartbeats_is_fully_observed():
    beats = [{"at": iso(W + timedelta(seconds=s)), "seq": s + 1, "droppedTotal": 0} for s in range(60)]
    verdict = health_by_window(beats, trim_losses=False)[W]
    assert verdict.fully_observed is True
    assert verdict.dropped == 0


def test_a_gap_in_the_sequence_means_the_minute_was_not_fully_observed():
    """A gap says the window is short for reasons unrelated to the traffic in
    it, which otherwise reads as a quiet minute."""
    beats = [
        {"at": iso(W + timedelta(seconds=s)), "seq": s + 1, "droppedTotal": 0}
        for s in range(60) if s != 30
    ]
    assert health_by_window(beats, trim_losses=False)[W].fully_observed is False


def test_dropped_telemetry_is_a_delta_not_the_lifetime_counter():
    """The counter is cumulative for the process's whole life, so the absolute
    value says nothing about this minute."""
    beats = [
        {"at": iso(W), "seq": 1, "droppedTotal": 1000, "arrivalsDroppedTotal": 0},
        {"at": iso(W + timedelta(seconds=59)), "seq": 60, "droppedTotal": 1012,
         "arrivalsDroppedTotal": 3},
    ]
    verdict = health_by_window(beats, trim_losses=False)[W]
    assert verdict.dropped == 15
    assert verdict.fully_observed is False


def test_a_trim_loss_makes_every_window_in_the_run_untrusted():
    beats = [{"at": iso(W + timedelta(seconds=s)), "seq": s + 1, "droppedTotal": 0} for s in range(60)]
    assert health_by_window(beats, trim_losses=True)[W].fully_observed is False


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


def test_build_produces_a_frozen_checkable_dataset(tmp_path):
    # count=25 at two-second spacing keeps the attacker inside one window;
    # 40 would spill into the next minute and quietly make this a three-row test.
    requests = busy("203.0.113.10", W) + busy("203.0.113.200", W, count=25)
    write_run(tmp_path, "run1", requests, attacks=[
        {"scenario": "credential_stuffing", "ip": "203.0.113.200",
         "start": iso(W), "end": iso(W + timedelta(minutes=1))}
    ])
    out = build([tmp_path / "run1"], tmp_path / "v1")

    assert (out / "FROZEN").exists()
    assert verify(out) == []

    for name in ("features.csv", "metadata.csv", "quality.csv", "rows.jsonl",
                 "splits.csv", "held_out_scenarios.txt", "versions.json",
                 "evaluation.md", "manifest.json"):
        assert (out / name).exists(), name

    rows = [json.loads(line) for line in (out / "rows.jsonl").read_text().splitlines()]
    assert len(rows) == 2
    labels = {r["ip"]: r["label"] for r in rows}
    assert labels == {"203.0.113.10": 0, "203.0.113.200": 1}


def test_the_feature_matrix_carries_no_identity(tmp_path):
    """The leakage guarantee, checked on the file that a model is trained
    from rather than on the code that wrote it."""
    write_run(tmp_path, "run1", busy("203.0.113.10", W))
    out = build([tmp_path / "run1"], tmp_path / "v1")

    assert check_feature_header(out / "features.csv") == []
    assert check_no_identifying_columns(out / "features.csv") == []

    header = next(csv.reader(open(out / "features.csv")))
    assert header == ["row_id", *FEATURE_NAMES]

    # The identity is in the other file, joined by row_id.
    meta = next(csv.DictReader(open(out / "metadata.csv")))
    assert meta["ip"] == "203.0.113.10"


def test_unknowns_are_written_empty_rather_than_imputed(tmp_path):
    """Imputation belongs at vectorisation time using training medians. Baking
    it in here would make the file unable to say what was never measured."""
    pending = [{"id": f"p{i}", "at": W + timedelta(seconds=i), "ip": "203.0.113.10", "done": None}
               for i in range(5)]
    write_run(tmp_path, "run1", pending)
    out = build([tmp_path / "run1"], tmp_path / "v1")

    row = next(csv.DictReader(open(out / "features.csv")))
    assert row["backend_404_ratio"] == ""
    assert row["request_count"] == "5.0"


def test_a_frozen_dataset_is_not_rebuilt_in_place(tmp_path):
    """A model trained on it has no way to notice that its inputs changed."""
    write_run(tmp_path, "run1", busy("203.0.113.10", W))
    build([tmp_path / "run1"], tmp_path / "v1")
    with pytest.raises(DatasetFrozen):
        build([tmp_path / "run1"], tmp_path / "v1")


def test_verify_catches_a_dataset_edited_after_freezing(tmp_path):
    write_run(tmp_path, "run1", busy("203.0.113.10", W))
    out = build([tmp_path / "run1"], tmp_path / "v1")
    (out / "features.csv").write_text("row_id\n1\n")
    assert verify(out) == ["features.csv does not match its manifest digest"]


def test_the_build_uses_window_end_not_now(tmp_path):
    """
    A request that arrived at 12:00:59 and completed at 12:01:02 contributes
    its arrival and none of its response, however long after the run the build
    happens to be executed.
    """
    straddler = [
        {"id": f"a{i}", "at": W + timedelta(seconds=i), "ip": "203.0.113.10",
         "done": W + timedelta(seconds=i, milliseconds=20)} for i in range(3)
    ] + [
        {"id": "late", "at": W + timedelta(seconds=59), "ip": "203.0.113.10",
         "done": W + timedelta(seconds=62), "status": 404}
    ]
    write_run(tmp_path, "run1", straddler)
    out = build([tmp_path / "run1"], tmp_path / "v1")

    rows = [json.loads(line) for line in (out / "rows.jsonl").read_text().splitlines()]
    first = [r for r in rows if r["window_start"].startswith("2026-09-07T12:00")][0]
    assert first["features"]["request_count"] == 4
    assert first["quality"]["pending_at_scoring"] == 1
    # The 404 landed after the window closed, so it is in no backend ratio.
    assert first["features"]["backend_404_ratio"] == 0.0
    assert first["quality"]["known_status_count"] == 3


def test_evaluation_md_is_written_before_any_model_is_fit(tmp_path):
    """Deciding what counts as success after seeing the scores is how a result
    gets talked into existing."""
    write_run(tmp_path, "run1", busy("203.0.113.10", W))
    out = build([tmp_path / "run1"], tmp_path / "v1")

    text = (out / "evaluation.md").read_text()
    assert "per persona" in text
    assert "abstentions" in text
    assert "validation" in text
    for scenario in RESERVED_SCENARIOS:
        assert scenario in text
