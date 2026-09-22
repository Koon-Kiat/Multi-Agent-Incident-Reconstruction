"""T3.3: the detection engine over a written corpus.

The corpus here is synthetic and written the way ``python -m m2 normalise`` writes it, so the
engine's manifest and digest checks are exercised in CI. ``test_detection_real.py`` runs the
same engine over the real exports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from m2.corpus import CORPUS_MANIFEST_FILENAME, write_manifest, write_scenario
from m2.detection import engine
from m2.detection.engine import (
    SUMMARY_FILENAME,
    DetectionEngine,
    DetectionError,
    DetectionOutputError,
    corpus_manifest_digest,
    write_detections,
)
from m2.detection.rules import RULES
from m2.detection.schema import DetectionRun, DetectionSummary, run_to_json
from m2.manifest import load_scenario, sha256_file
from m2.query import EventStore, QueryError
from m2.schema import NormalisedEvent
from m2.tests.synthetic import build_scenario_dir, make_event
from m2.timeutil import TICKS_PER_SECOND, iso_to_ticks, ticks_to_iso

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
    """A genuine M2 run document for a scenario the corpus no longer holds."""
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
    # F1: the removal is narrowed to a file that carries both an M2 detection name and the M2
    # schema marker. `manifest.json` and `package.json` also match the scenario-id name pattern,
    # so only the marker can tell them apart from a real run.
    out = tmp_path / "detections"
    out.mkdir()
    survivors = {
        "manifest.json": '{"important": true}\n',
        "package.json": '{"name": "not-a-detection", "version": "1.0.0"}\n',
        "S02.json": '{"caller": "a foreign file, not an m2 run"}\n',
        "SYN-MISMATCH.json": json.dumps({"schema_version": "m2-detect-v1", "scenario_id": "SYN-GONE"}) + "\n",
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


@pytest.mark.parametrize("scenario_id", ["summary", "Summary"])
def test_detect_refuses_the_reserved_scenario_id_summary(tmp_path: Path, scenario_id: str):
    # B4: `<scenario>.json` for a scenario named `summary` is `summary.json`, the name detect
    # reserves for its own counts. Case-insensitively, as a Windows filesystem would collide.
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    reserved = info.model_copy(update={"scenario_id": scenario_id})
    events = (make_event(scenario_id=scenario_id, record_id=1, event_id=4624),)
    corpus = tmp_path / "corpus"
    write_manifest(corpus, [write_scenario(corpus, reserved, events)])
    out = tmp_path / "detections"

    with pytest.raises(DetectionError, match="reserved"):
        write_detections(corpus, out)

    assert not out.exists()


def test_detect_refuses_to_overwrite_a_foreign_scenario_file(corpus_dir: Path, tmp_path: Path):
    # B5: detect owns `--out`, but a file it did not write is still the caller's data. A foreign
    # `SYN-B.json` must stop the whole run before anything — including summary.json — is written.
    out = tmp_path / "detections"
    out.mkdir()
    foreign = out / f"{SCENARIO}.json"
    foreign.write_text('{"caller": "not an m2 run"}\n', encoding="utf-8", newline="\n")

    with pytest.raises(DetectionError, match="refusing to overwrite"):
        write_detections(corpus_dir, out)

    assert foreign.read_text(encoding="utf-8") == '{"caller": "not an m2 run"}\n'
    assert not (out / SUMMARY_FILENAME).exists()


def test_detect_refuses_to_overwrite_a_foreign_summary(corpus_dir: Path, tmp_path: Path):
    out = tmp_path / "detections"
    out.mkdir()
    foreign = out / SUMMARY_FILENAME
    foreign.write_text('{"artifact": "someone-elses"}\n', encoding="utf-8", newline="\n")

    with pytest.raises(DetectionError, match="refusing to overwrite"):
        write_detections(corpus_dir, out)

    assert foreign.read_text(encoding="utf-8") == '{"artifact": "someone-elses"}\n'
    assert not (out / f"{SCENARIO}.json").exists()


def test_a_stale_run_file_of_a_scenario_the_corpus_holds_is_still_overwritten(corpus_dir: Path, tmp_path: Path):
    # The other side of B5: detect's own earlier run for the same scenario carries the marker, so
    # replacing it is the intended refresh rather than a collision.
    out = tmp_path / "detections"
    out.mkdir()
    (out / f"{SCENARIO}.json").write_text(_stale_run_payload(SCENARIO), encoding="utf-8", newline="\n")

    write_detections(corpus_dir, out)

    run = DetectionRun.model_validate_json((out / f"{SCENARIO}.json").read_text(encoding="utf-8"))
    assert [detection.rule_id for detection in run.detections] == ["R-AUTH-01", "R-EXEC-02"]


# --- F2: the refusal covers non-regular targets, and the write is all-or-nothing -------------


def test_detect_refuses_a_directory_at_a_target_name(corpus_dir: Path, tmp_path: Path):
    # F2: `is_file()` was False for a directory, so the pre-write check let it through and the run
    # wrote the other files first, then failed on the directory, leaving a half-refreshed `--out`.
    out = tmp_path / "detections"
    target = out / f"{SCENARIO}.json"
    target.mkdir(parents=True)

    with pytest.raises(DetectionError, match="not a regular file"):
        write_detections(corpus_dir, out)

    assert target.is_dir()
    assert not (out / SUMMARY_FILENAME).exists()


def test_detect_refuses_a_symlink_at_a_target_name(corpus_dir: Path, tmp_path: Path):
    # F2: the marker check reads through a link, but the write would follow it out of `--out`, so a
    # link is refused even when it points at a genuine M2 artefact.
    out = tmp_path / "detections"
    out.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(_stale_run_payload(SCENARIO), encoding="utf-8", newline="\n")
    link = out / f"{SCENARIO}.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available in this environment")

    with pytest.raises(DetectionError, match="symbolic link"):
        write_detections(corpus_dir, out)

    assert outside.read_text(encoding="utf-8") == _stale_run_payload(SCENARIO)
    assert not (out / SUMMARY_FILENAME).exists()


def test_a_failed_write_leaves_the_previous_run_intact(
    corpus_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # F2: every document is staged under a dotted temporary name and renamed only once all of them
    # exist. The previous artefact here differs from what this run writes, so a half-finished run
    # would be visible as a changed file.
    out = tmp_path / "detections"
    out.mkdir()
    run_path = out / f"{SCENARIO}.json"
    run_path.write_text(_stale_run_payload(SCENARIO), encoding="utf-8", newline="\n")
    before = run_path.read_bytes()

    real_write_text = engine._write_text
    calls: list[Path] = []

    def flaky(path: Path, payload: str) -> None:
        calls.append(path)
        if len(calls) == 2:
            raise OSError(28, "No space left on device", str(path))
        real_write_text(path, payload)

    monkeypatch.setattr(engine, "_write_text", flaky)
    with pytest.raises(OSError):
        write_detections(corpus_dir, out)

    assert run_path.read_bytes() == before
    assert not (out / SUMMARY_FILENAME).exists()
    assert not [path for path in out.iterdir() if path.name.startswith(".")]
