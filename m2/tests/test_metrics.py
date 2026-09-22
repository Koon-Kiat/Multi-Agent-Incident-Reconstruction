"""T4.1: precision/recall/F1 arithmetic over synthetic detection runs and labels.

Nothing here reads a corpus, an EVTX file or a real label file. Every expectation is hand-computed
from the fixture below, so the tests state the metric definitions rather than reproduce the code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from m2.detection.schema import Detection, DetectionRun
from m2.metrics import (
    SCORE_REPORT_FILENAME,
    LabelRow,
    ScoreError,
    load_detection_runs,
    load_labels,
    report_to_json,
    score,
    write_report,
)

SCENARIO = "SYN-B"
OTHER_SCENARIO = "SYN-C"
SHA = "D396CE599723189331D440EDD55CC055C28EB4B6AD45A421D07A8E83A2F0EBA7"
WINDOW = "2026-09-21T02:05:30.0000000Z"


def _json(run: DetectionRun) -> str:
    return json.dumps(run.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, indent=2)


def _detection(scenario_id: str, rule_id: str, record_ids: tuple[int, ...], *, version: str = "1") -> Detection:
    triggers = tuple(f"{scenario_id}-SEC-{record}" for record in record_ids)
    return Detection(
        detection_id=f"{scenario_id}-{rule_id}-{triggers[-1]}",
        rule_id=rule_id,
        rule_version=version,
        scenario_id=scenario_id,
        trigger_evidence_ids=triggers,
        window_start_utc=WINDOW,
        window_end_utc=WINDOW,
        severity="high",
        rationale="synthetic",
    )


def _run(scenario_id: str, *detections: Detection) -> DetectionRun:
    return DetectionRun(
        scenario_id=scenario_id,
        corpus_manifest_sha256=SHA,
        rules=(),
        detections=detections,
    )


def _runs() -> tuple[DetectionRun, ...]:
    """Two rules overlap on one event; a second scenario flags an excluded event."""
    return (
        _run(
            SCENARIO,
            _detection(SCENARIO, "R-A", (1, 2)),
            _detection(SCENARIO, "R-B", (2, 3)),
        ),
        _run(OTHER_SCENARIO, _detection(OTHER_SCENARIO, "R-A", (9,))),
    )


def _labels() -> tuple[LabelRow, ...]:
    """positives {1, 2, 5}, negative {3}, excluded {4, 9}; 5 is never flagged (a false negative)."""
    return (
        LabelRow(evidence_id="SYN-B-SEC-1", label="positive", reason="stage"),
        LabelRow(evidence_id="SYN-B-SEC-2", label="positive"),
        LabelRow(evidence_id="SYN-B-SEC-5", label="positive"),
        LabelRow(evidence_id="SYN-B-SEC-3", label="negative", reason="benign lookalike"),
        LabelRow(evidence_id="SYN-B-SEC-4", label="excluded"),
        LabelRow(evidence_id="SYN-C-SEC-9", label="excluded"),
    )


def test_the_overall_metrics_are_the_hand_computed_ratios():
    report = score(_runs(), _labels())
    counts = report.overall
    # flagged = {1, 2, 3, 9}: 2 is flagged by two rules and counted once.
    assert counts.flagged == 4
    assert (counts.positives, counts.negatives, counts.excluded) == (3, 1, 2)
    assert (counts.tp, counts.fp, counts.fn) == (2, 1, 1)
    assert (counts.flagged_excluded, counts.unflagged_excluded) == (1, 1)
    assert counts.precision_denominator == 3 and counts.recall_denominator == 3
    assert counts.precision == counts.recall == counts.f1 == pytest.approx(2 / 3)
    assert report.unit == "evidence_id"


def test_excluded_events_never_enter_precision_or_recall():
    # SYN-C-SEC-9 is flagged and excluded: it is neither a TP nor an FP.
    report = score(_runs(), _labels())
    assert report.overall.flagged == report.overall.tp + report.overall.fp + 1
    without_exclusion = score(
        _runs(),
        tuple(row for row in _labels() if row.evidence_id != "SYN-C-SEC-9"),
    )
    assert without_exclusion.overall.tp == 2  # unchanged
    assert without_exclusion.overall.fp == 2  # the previously excluded flag is now a false positive


def test_every_scope_is_reported_with_its_own_counts():
    report = score(_runs(), _labels())
    assert [scenario.scenario_id for scenario in report.scenarios] == [SCENARIO, OTHER_SCENARIO]
    assert [rule.rule_id for rule in report.rules] == ["R-A", "R-B"]
    by_scenario = {scenario.scenario_id: scenario.counts for scenario in report.scenarios}
    # SYN-B: flagged {1, 2, 3}, positives {1, 2, 5}, negative {3}, excluded {4}
    assert (by_scenario[SCENARIO].tp, by_scenario[SCENARIO].fp, by_scenario[SCENARIO].fn) == (2, 1, 1)
    assert by_scenario[SCENARIO].precision == pytest.approx(2 / 3)
    # SYN-C: the only flagged event is excluded, so both metrics have a zero denominator.
    assert (by_scenario[OTHER_SCENARIO].tp, by_scenario[OTHER_SCENARIO].fp) == (0, 0)
    assert (by_scenario[OTHER_SCENARIO].flagged_excluded, by_scenario[OTHER_SCENARIO].unflagged_excluded) == (1, 0)
    assert by_scenario[OTHER_SCENARIO].precision is None
    assert by_scenario[OTHER_SCENARIO].recall is None
    assert by_scenario[OTHER_SCENARIO].f1 is None


def test_per_rule_attribution_double_counts_a_shared_flag_but_the_overall_figure_does_not():
    report = score(_runs(), _labels())
    by_rule = {rule.rule_id: rule.counts for rule in report.rules}
    # R-A flags {1, 2}: both positives. R-B flags {2, 3}: one positive, one negative.
    assert (by_rule["R-A"].tp, by_rule["R-A"].fp, by_rule["R-A"].fn) == (2, 0, 1)
    assert by_rule["R-A"].precision == 1.0
    assert by_rule["R-A"].recall == pytest.approx(2 / 3)
    assert by_rule["R-A"].f1 == pytest.approx(0.8)
    assert (by_rule["R-B"].tp, by_rule["R-B"].fp, by_rule["R-B"].fn) == (1, 1, 2)
    assert by_rule["R-B"].precision == pytest.approx(0.5)
    assert by_rule["R-B"].recall == pytest.approx(1 / 3)
    # The per-rule TPs sum to more than the overall TP, which is deduplicated.
    assert sum(rule.counts.tp for rule in report.rules) == 3 > report.overall.tp == 2


def test_an_empty_flag_set_leaves_precision_undefined_and_recall_defined():
    labels = (LabelRow(evidence_id="SYN-B-SEC-1", label="positive"),)
    report = score((_run(SCENARIO),), labels)
    counts = report.overall
    assert (counts.flagged, counts.tp, counts.fp) == (0, 0, 0)
    assert counts.precision is None
    assert counts.f1 is None
    assert counts.recall == 0.0  # one positive, none flagged: a defined zero, not "undefined"


def test_no_positives_leaves_recall_undefined():
    labels = (LabelRow(evidence_id="SYN-B-SEC-3", label="negative"),)
    report = score(_runs(), labels)
    assert report.overall.positives == 0
    assert report.overall.recall is None
    assert report.overall.f1 is None
    # Every flagged event is a false positive (unlisted ones are negative by definition), so
    # precision is a defined zero rather than "undefined".
    assert (report.overall.tp, report.overall.fp) == (0, 4)
    assert report.overall.precision == 0.0


def test_no_labels_at_all_still_reports_the_flagged_set_as_false_positives():
    report = score(_runs(), ())
    counts = report.overall
    assert counts.flagged == 4
    assert (counts.tp, counts.fp, counts.fn) == (0, 4, 0)
    assert counts.precision == 0.0
    assert counts.recall is None  # no positives to find
    assert counts.f1 is None


def test_scores_are_deterministic_and_read_only():
    runs = _runs()
    labels = _labels()
    first = score(runs, labels)
    second = score(tuple(reversed(runs)), tuple(reversed(labels)))
    assert first == second
    assert report_to_json(first) == report_to_json(second)
    assert [detection.detection_id for run in runs for detection in run.detections] == [
        "SYN-B-R-A-SYN-B-SEC-2",
        "SYN-B-R-B-SYN-B-SEC-3",
        "SYN-C-R-A-SYN-C-SEC-9",
    ]


def test_a_shared_flag_is_not_attributed_to_a_rule_that_did_not_emit_it():
    report = score(
        (
            _run(SCENARIO, _detection(SCENARIO, "R-A", (1,))),
            _run(SCENARIO, _detection(SCENARIO, "R-C", (2,))),
        ),
        (LabelRow(evidence_id="SYN-B-SEC-1", label="positive"),),
    )
    by_rule = {rule.rule_id: rule.counts for rule in report.rules}
    assert (by_rule["R-A"].tp, by_rule["R-A"].fp) == (1, 0)
    assert (by_rule["R-C"].tp, by_rule["R-C"].fp) == (0, 1)


def test_a_label_naming_an_evidence_id_outside_the_scored_corpus_raises():
    runs = _runs()
    labels = (LabelRow(evidence_id="SYN-B-SEC-99", label="negative"),)
    with pytest.raises(ScoreError, match="not in the corpus"):
        score(runs, labels, known_evidence_ids={"SYN-B-SEC-1", "SYN-B-SEC-2"})


def test_a_label_that_is_not_an_evidence_id_at_all_raises_when_it_is_loaded(tmp_path: Path):
    labels = tmp_path / "labels.csv"
    labels.write_text("evidence_id,label\nS02-SEC-0,positive\nnot-an-id,negative\n", encoding="utf-8")
    with pytest.raises(ScoreError, match="not a valid label row"):
        load_labels(labels)


def test_a_duplicate_evidence_id_in_the_labels_raises():
    labels = (
        LabelRow(evidence_id="SYN-B-SEC-1", label="positive"),
        LabelRow(evidence_id="SYN-B-SEC-1", label="negative"),
    )
    with pytest.raises(ScoreError, match="labelled more than once"):
        score(_runs(), labels)


def test_an_unsupported_unit_is_rejected():
    with pytest.raises(ScoreError, match="unit"):
        score(_runs(), _labels(), unit="window")


# --- the label file formats --------------------------------------------------------


def _write_csv(path: Path) -> None:
    path.write_text(
        "evidence_id,label,reason\n"
        "SYN-B-SEC-1,positive,stage one\n"
        "SYN-B-SEC-2,positive,\n"
        "SYN-B-SEC-3,negative,benign lookalike\n"
        "SYN-B-SEC-4,excluded,\n",
        encoding="utf-8",
    )


def test_the_csv_label_shape_round_trips_into_rows(tmp_path: Path):
    path = tmp_path / "labels.csv"
    _write_csv(path)
    rows = load_labels(path)
    assert [row.model_dump() for row in rows] == [
        {"evidence_id": "SYN-B-SEC-1", "label": "positive", "reason": "stage one"},
        {"evidence_id": "SYN-B-SEC-2", "label": "positive", "reason": None},
        {"evidence_id": "SYN-B-SEC-3", "label": "negative", "reason": "benign lookalike"},
        {"evidence_id": "SYN-B-SEC-4", "label": "excluded", "reason": None},
    ]


def test_the_json_label_shape_round_trips_into_rows(tmp_path: Path):
    path = tmp_path / "labels.json"
    path.write_text(
        json.dumps(
            {
                "labels": [
                    {"evidence_id": "SYN-B-SEC-1", "label": "positive", "reason": "stage one"},
                    {"evidence_id": "SYN-B-SEC-4", "label": "excluded"},
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = load_labels(path)
    assert [row.evidence_id for row in rows] == ["SYN-B-SEC-1", "SYN-B-SEC-4"]
    assert rows[1].reason is None


def test_a_label_file_that_is_not_csv_or_json_is_rejected(tmp_path: Path):
    path = tmp_path / "labels.txt"
    path.write_text("SYN-B-SEC-1,positive\n", encoding="utf-8")
    with pytest.raises(ScoreError, match="must be .csv or .json"):
        load_labels(path)


def test_a_missing_label_file_is_rejected(tmp_path: Path):
    with pytest.raises(ScoreError, match="does not exist"):
        load_labels(tmp_path / "absent.csv")


@pytest.mark.parametrize(
    "payload",
    (
        "evidence_id,label\nS02-SEC-1,maybe\n",
        "evidence_id\nS02-SEC-1\n",
        "evidence_id,label,reason,extra\nS02-SEC-1,positive,,x\n",
        "evidence_id,label\nS02-SEC-1\n",
    ),
)
def test_a_malformed_csv_label_file_is_rejected(tmp_path: Path, payload: str):
    path = tmp_path / "labels.csv"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ScoreError):
        load_labels(path)


def test_a_malformed_json_label_document_is_rejected(tmp_path: Path):
    path = tmp_path / "labels.json"
    path.write_text(json.dumps({"rows": []}), encoding="utf-8")
    with pytest.raises(ScoreError, match="list of label rows"):
        load_labels(path)


# --- reading a written detections directory ----------------------------------------


def test_a_written_detections_directory_is_read_back(tmp_path: Path):
    directory = tmp_path / "detections"
    directory.mkdir()
    run = _run(SCENARIO, _detection(SCENARIO, "R-A", (1, 2)))
    (directory / f"{SCENARIO}.json").write_text(f"{_json(run)}\n", encoding="utf-8")
    (directory / "summary.json").write_text('{"schema_version": "m2-detect-v1"}', encoding="utf-8")
    (runs,) = load_detection_runs(directory)
    assert runs.scenario_id == SCENARIO
    assert runs.detections[0].trigger_evidence_ids == ("SYN-B-SEC-1", "SYN-B-SEC-2")


def test_a_directory_without_runs_or_a_missing_directory_is_rejected(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ScoreError, match="no run files"):
        load_detection_runs(empty)
    with pytest.raises(ScoreError, match="does not exist"):
        load_detection_runs(tmp_path / "absent")


def test_a_file_that_is_not_a_detection_run_is_rejected(tmp_path: Path):
    directory = tmp_path / "detections"
    directory.mkdir()
    (directory / "SYN-B.json").write_text('{"scenario_id": "SYN-B"}', encoding="utf-8")
    with pytest.raises(ScoreError, match="not a valid detection run"):
        load_detection_runs(directory)


def test_the_report_is_written_as_deterministic_sorted_key_json(tmp_path: Path):
    report = score(_runs(), _labels())
    first = write_report(report, tmp_path / "first")
    second = write_report(report, tmp_path / "second")
    assert first.name == SCORE_REPORT_FILENAME
    payload = first.read_bytes()
    assert payload == second.read_bytes()
    assert payload.endswith(b"\n") and b"\r\n" not in payload
    document = json.loads(payload)
    assert list(document) == sorted(document)
    assert document["schema_version"] == "m2-score-v1"
    assert document["unit"] == "evidence_id"
    assert document["overall"]["tp"] == 2
