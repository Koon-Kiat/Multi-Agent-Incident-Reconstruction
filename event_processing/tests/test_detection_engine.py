"""T3.3: the detection engine over a written corpus.

The corpus here is synthetic and written the way ``python -m event_processing normalise`` writes it, so the
engine's manifest and digest checks are exercised in CI. ``test_detection_real.py`` runs the
same engine over the real exports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from event_processing.corpus import CORPUS_MANIFEST_FILENAME, write_manifest, write_scenario
from event_processing.detection.engine import (
    SUMMARY_FILENAME,
    DetectionEngine,
    DetectionError,
    DetectionOutputError,
    corpus_manifest_digest,
    write_detections,
)
from event_processing.detection.rules import RULES
from event_processing.detection.schema import DetectionRun, DetectionSummary, run_to_json
from event_processing.manifest import load_scenario, sha256_file
from event_processing.query import EventStore, QueryError
from event_processing.schema import NormalisedEvent
from event_processing.tests.synthetic import build_scenario_dir, make_event
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks, ticks_to_iso

SHA = "D396CE599723189331D440EDD55CC055C28EB4B6AD45A421D07A8E83A2F0EBA7"
SCENARIO = "SYN-B"
BASE = iso_to_ticks("2026-09-21T02:05:30.0000000Z")


def at(seconds: int) -> str:
    return ticks_to_iso(BASE + seconds * TICKS_PER_SECOND)


def synthetic_events() -> tuple[NormalisedEvent, ...]:
    """Three failed logons then a success, plus one encoded PowerShell command line."""
    return (
        make_event(
            record_id=1,
            event_id=4625,
            timestamp_ticks=BASE,
            user="alice",
            host="LAB-A",
            event_data={"TargetUserName": "alice"},
        ),
        make_event(
            record_id=2,
            event_id=4625,
            timestamp_ticks=BASE + 5 * TICKS_PER_SECOND,
            user="alice",
            host="LAB-A",
            event_data={"TargetUserName": "alice"},
        ),
        make_event(
            record_id=3,
            event_id=4625,
            timestamp_ticks=BASE + 10 * TICKS_PER_SECOND,
            user="alice",
            host="LAB-A",
            event_data={"TargetUserName": "alice"},
        ),
        make_event(
            record_id=4,
            event_id=4624,
            timestamp_ticks=BASE + 15 * TICKS_PER_SECOND,
            user="alice",
            host="LAB-A",
            event_data={"TargetUserName": "alice"},
        ),
        make_event(
            record_id=5,
            event_id=4688,
            timestamp_ticks=BASE + 20 * TICKS_PER_SECOND,
            user="alice",
            host="LAB-A",
            event_data={
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -enc SQBFAFgA",
            },
        ),
    )


@pytest.fixture
def corpus_dir(tmp_path: Path) -> Path:
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    out = tmp_path / "corpus"
    write_manifest(out, [write_scenario(out, info, synthetic_events())])
    return out


def test_detection_writes_a_run_per_scenario_plus_a_summary(corpus_dir: Path, tmp_path: Path):
    out = tmp_path / "detections"
    summary = write_detections(corpus_dir, out)

    assert (out / f"{SCENARIO}.json").is_file()
    assert (out / SUMMARY_FILENAME).is_file()
    run = DetectionRun.model_validate_json((out / f"{SCENARIO}.json").read_text(encoding="utf-8"))
    assert run.scenario_id == SCENARIO
    assert run.corpus_manifest_sha256 == sha256_file(corpus_dir / CORPUS_MANIFEST_FILENAME)
    assert [rule.rule_id for rule in run.rules] == [rule.spec.rule_id for rule in RULES]
    assert [detection.rule_id for detection in run.detections] == ["R-AUTH-01", "R-EXEC-02"]
    assert run.detections[0].trigger_evidence_ids == (
        "SYN-B-SEC-1",
        "SYN-B-SEC-2",
        "SYN-B-SEC-3",
        "SYN-B-SEC-4",
    )
    assert [scenario.total for scenario in summary.scenarios] == [2]
    assert summary.scenarios[0].scenario_id == SCENARIO
    assert summary.scenarios[0].counts_by_rule == {"R-AUTH-01": 1, "R-EXEC-02": 1}


def test_the_summary_matches_the_engine(corpus_dir: Path):
    engine = DetectionEngine(EventStore.load(corpus_dir), corpus_manifest_sha256=corpus_manifest_digest(corpus_dir))
    assert engine.corpus_manifest_sha256 == sha256_file(corpus_dir / CORPUS_MANIFEST_FILENAME)
    assert engine.summary().scenarios[0].total == len(engine.triggers_for(SCENARIO))


def test_two_runs_are_byte_identical(corpus_dir: Path, tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_detections(corpus_dir, first)
    write_detections(corpus_dir, second)
    for name in (f"{SCENARIO}.json", SUMMARY_FILENAME):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert b"\r\n" not in (first / f"{SCENARIO}.json").read_bytes()


def test_the_written_documents_are_sorted_key_json(corpus_dir: Path, tmp_path: Path):
    out = tmp_path / "detections"
    write_detections(corpus_dir, out)
    for name in (f"{SCENARIO}.json", SUMMARY_FILENAME):
        document = json.loads((out / name).read_text(encoding="utf-8"))
        assert list(document) == sorted(document)


def test_triggers_for_orders_by_window_start_and_ignores_unknown_scenarios(corpus_dir: Path):
    engine = DetectionEngine(EventStore.load(corpus_dir), corpus_manifest_sha256=corpus_manifest_digest(corpus_dir))
    detections = engine.triggers_for(SCENARIO)
    assert [detection.window_start_utc for detection in detections] == sorted(
        detection.window_start_utc for detection in detections
    )
    assert engine.triggers_for("SYN-Z") == ()
    assert engine.run("SYN-Z").detections == ()


def test_an_empty_store_produces_an_empty_run_and_summary():
    engine = DetectionEngine(EventStore(()), corpus_manifest_sha256=SHA)
    assert engine.scenario_ids == ()
    assert engine.runs() == ()
    assert engine.summary().scenarios == ()
    empty = engine.run(SCENARIO)
    assert empty.detections == ()
    assert empty.rules and len(empty.rules) == len(RULES)


def test_detect_fails_closed_without_a_corpus_manifest(tmp_path: Path):
    with pytest.raises(DetectionError, match="corpus manifest"):
        corpus_manifest_digest(tmp_path / "absent")
    with pytest.raises(DetectionError, match="corpus manifest"):
        write_detections(tmp_path / "absent", tmp_path / "out")


def test_detect_refuses_a_tampered_corpus(corpus_dir: Path, tmp_path: Path):
    jsonl = corpus_dir / f"{SCENARIO}.jsonl"
    lines = jsonl.read_text(encoding="utf-8").splitlines()
    jsonl.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8", newline="\n")
    with pytest.raises(QueryError, match="sha256"):
        write_detections(corpus_dir, tmp_path / "out")


def test_the_run_declares_the_thresholds_it_used(corpus_dir: Path):
    run = DetectionEngine(EventStore.load(corpus_dir), corpus_manifest_sha256=SHA).run(SCENARIO)
    params = {rule.rule_id: rule.params for rule in run.rules}
    assert params["R-AUTH-01"] == {"min_failures": 3, "window_seconds": 300, "variant": "burst_then_success"}
    assert params["R-EXEC-01"]["min_distinct_binaries"] == 3
    assert params["R-EXEC-01"]["window_seconds"] == 120
    assert "0x001410" in str(params["R-CRED-01"]["masks"])


def test_the_summary_is_a_valid_model_and_round_trips(corpus_dir: Path, tmp_path: Path):
    summary = write_detections(corpus_dir, tmp_path / "out")
    payload = (tmp_path / "out" / SUMMARY_FILENAME).read_text(encoding="utf-8")
    assert DetectionSummary.model_validate_json(payload) == summary


def test_a_scenario_with_no_detections_still_gets_a_run_file(corpus_dir: Path, tmp_path: Path):
    quiet = tuple(
        make_event(record_id=record, event_id=4624, timestamp_ticks=BASE + record * TICKS_PER_SECOND)
        for record in (1, 2)
    )
    info = load_scenario(build_scenario_dir(tmp_path / "other-datasets", "lab"))
    other = tmp_path / "other-corpus"
    write_manifest(other, [write_scenario(other, info, quiet)])
    out = tmp_path / "quiet-detections"
    summary = write_detections(other, out)
    run = DetectionRun.model_validate_json((out / f"{SCENARIO}.json").read_text(encoding="utf-8"))
    assert run.detections == ()
    assert run.scenario_id == SCENARIO
    assert summary.scenarios[0].total == 0
    assert summary.scenarios[0].counts_by_rule == {}


def test_at_is_the_canonical_rendering_used_by_the_detections(corpus_dir: Path):
    # Guards the fixture helper itself: a detection window is made of these exact strings.
    assert DetectionEngine(EventStore.load(corpus_dir), corpus_manifest_sha256=SHA).run(SCENARIO).detections[
        0
    ].window_start_utc == at(0)


def test_detect_removes_stale_run_files_from_its_own_output_directory(corpus_dir: Path, tmp_path: Path):
    # T5.0/amendment A2: a run file for a scenario the corpus no longer holds must not survive,
    # because `score` and any consumer that globs the directory would read it as current.
    out = tmp_path / "detections"
    out.mkdir()
    stale = out / "SYN-GONE.json"
    stale.write_text(_stale_run_payload("SYN-GONE"), encoding="utf-8", newline="\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    untouched = elsewhere / "SYN-GONE.json"
    untouched.write_text(_stale_run_payload("SYN-GONE"), encoding="utf-8", newline="\n")

    write_detections(corpus_dir, out)

    assert not stale.exists()
    assert sorted(path.name for path in out.iterdir()) == sorted([f"{SCENARIO}.json", SUMMARY_FILENAME])
    assert untouched.read_text(encoding="utf-8") == _stale_run_payload("SYN-GONE")  # only --out is touched
    # The written run parses, so the removal left a usable directory rather than a hole.
    assert DetectionRun.model_validate_json((out / f"{SCENARIO}.json").read_text(encoding="utf-8")).scenario_id == SCENARIO


def _stale_run_payload(scenario_id: str) -> str:
    """A genuine Event Processing & Detection Engine run document for a scenario the corpus no longer holds."""
    return (
        run_to_json(
            DetectionRun(
                scenario_id=scenario_id,
                corpus_manifest_sha256=SHA,
                rules=(),
                detections=(),
            )
        )
        + "\n"
    )


def test_detect_leaves_every_file_it_did_not_write_untouched(corpus_dir: Path, tmp_path: Path):
    # F1: the removal is narrowed to a file that carries both an Event Processing & Detection Engine detection name and the Event Processing & Detection Engine
    # schema marker. `manifest.json` and `package.json` also match the scenario-id name pattern,
    # so only the marker can tell them apart from a real run.
    out = tmp_path / "detections"
    out.mkdir()
    survivors = {
        "manifest.json": '{"important": true}\n',
        "package.json": '{"name": "not-a-detection", "version": "1.0.0"}\n',
        "S02.json": '{"caller": "a foreign file, not an event_processing run"}\n',
        "SYN-MISMATCH.json": json.dumps({"schema_version": "detection-run-v1", "scenario_id": "SYN-GONE"}) + "\n",
        "SYN-BROKEN.json": "{not json at all\n",
    }
    for name, payload in survivors.items():
        (out / name).write_text(payload, encoding="utf-8", newline="\n")

    write_detections(corpus_dir, out)

    for name, payload in survivors.items():
        assert (out / name).read_text(encoding="utf-8") == payload, name
    assert (out / SUMMARY_FILENAME).is_file()


def test_a_run_file_that_carries_the_marker_is_removed(corpus_dir: Path, tmp_path: Path):
    # The complement of the test above: a real stale artefact, however minimal, still goes.
    out = tmp_path / "detections"
    out.mkdir()
    stale = out / "SYN-GONE.json"
    stale.write_text(_stale_run_payload("SYN-GONE"), encoding="utf-8", newline="\n")

    write_detections(corpus_dir, out)

    assert not stale.exists()


@pytest.mark.parametrize("tree", ["datasets", "ground_truth", "DataSets", "GROUND_TRUTH"])
def test_detect_refuses_an_out_directory_inside_a_protected_tree(corpus_dir: Path, tmp_path: Path, tree: str):
    out = tmp_path / tree / "results"
    with pytest.raises(DetectionOutputError, match="read-only"):
        write_detections(corpus_dir, out)
    assert not out.exists()


def test_a_directory_whose_name_merely_contains_a_protected_word_is_allowed(corpus_dir: Path, tmp_path: Path):
    out = tmp_path / "datasets-out"
    summary = write_detections(corpus_dir, out)
    assert summary.scenarios[0].scenario_id == SCENARIO
    assert (out / SUMMARY_FILENAME).is_file()


def test_detect_refuses_to_write_into_the_corpus_directory(corpus_dir: Path):
    # `--out` is a directory detect owns: it deletes stale run files there, and the corpus's own
    # corpus_manifest.json is not a run file.
    with pytest.raises(DetectionError, match="is the corpus directory"):
        write_detections(corpus_dir, corpus_dir)
    assert (corpus_dir / CORPUS_MANIFEST_FILENAME).is_file()
