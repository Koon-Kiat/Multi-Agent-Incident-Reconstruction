"""T1.6: the corpus writer is deterministic, sorted, counted and duplicate-proof."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from m2.corpus import (
    CORPUS_MANIFEST_FILENAME,
    CORPUS_MANIFEST_SCHEMA_VERSION,
    CorpusError,
    duplicate_evidence_ids,
    event_sort_key,
    normalise_datasets,
    require_record_channel,
    scenario_directories,
    source_filename_of,
    write_manifest,
    write_scenario,
)
from m2.evtx_reader import RawRecord
from m2.manifest import load_scenario, sha256_file
from m2.tests.synthetic import SECURITY, SYSMON, build_scenario_dir, make_event, synthetic_payload
from m2.timeutil import iso_to_ticks


def test_event_sort_key_is_ticks_then_evidence_id():
    late = make_event(record_id=9, timestamp_ticks=iso_to_ticks("2026-09-21T02:06:00Z"))
    early = make_event(record_id=10, timestamp_ticks=iso_to_ticks("2026-09-21T02:05:00Z"))
    assert sorted([late, early], key=event_sort_key) == [early, late]


def test_equal_ticks_are_ordered_by_evidence_id():
    same = iso_to_ticks("2026-09-21T02:05:00Z")
    events = [make_event(record_id=20, timestamp_ticks=same), make_event(record_id=3, timestamp_ticks=same)]
    assert [event.evidence_id for event in sorted(events, key=event_sort_key)] == ["SYN-B-SEC-20", "SYN-B-SEC-3"]


def test_write_scenario_sorts_counts_and_hashes(tmp_path: Path):
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    out = tmp_path / "corpus"
    events = [
        make_event(record_id=2, timestamp_ticks=iso_to_ticks("2026-09-21T02:06:00Z"), channel=SECURITY),
        make_event(record_id=1, timestamp_ticks=iso_to_ticks("2026-09-21T02:05:00Z"), channel=SECURITY, event_id=4624),
        make_event(record_id=5, timestamp_ticks=iso_to_ticks("2026-09-21T02:05:30Z"), channel=SYSMON, event_id=1),
    ]
    corpus = write_scenario(out, info, events)

    assert corpus.jsonl.filename == "SYN-B.jsonl"
    assert corpus.jsonl.line_count == 3
    assert corpus.jsonl.sha256 == sha256_file(out / "SYN-B.jsonl")
    lines = (out / "SYN-B.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["evidence_id"] for line in lines] == ["SYN-B-SEC-1", "SYN-B-SYS-5", "SYN-B-SEC-2"]
    assert corpus.counts_by_channel == {SECURITY: 2, SYSMON: 1}
    assert corpus.counts_by_event_id == {SECURITY: {"4624": 1, "4688": 1}, SYSMON: {"1": 1}}
    assert [(source.channel, source.event_count) for source in corpus.files] == [(SECURITY, 2), (SYSMON, 1)]


def test_jsonl_uses_lf_endings_and_ends_with_a_newline(tmp_path: Path):
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    out = tmp_path / "corpus"
    write_scenario(out, info, [make_event(record_id=1)])
    payload = (out / "SYN-B.jsonl").read_bytes()
    assert b"\r\n" not in payload
    assert payload.endswith(b"\n")
    assert payload.count(b"\n") == 1


def test_empty_scenario_writes_an_empty_file(tmp_path: Path):
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    corpus = write_scenario(tmp_path / "corpus", info, [])
    assert corpus.jsonl.line_count == 0
    assert (tmp_path / "corpus" / "SYN-B.jsonl").read_bytes() == b""


def test_two_runs_are_byte_identical(tmp_path: Path):
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    events = [
        make_event(record_id=2, timestamp_ticks=iso_to_ticks("2026-09-21T02:06:00Z")),
        make_event(record_id=1, user=None, event_data={"SubjectUserName": "analyst", "Utf": "\u00e9"}),
        make_event(record_id=3, channel=SYSMON, event_id=1, event_data={"User": ""}),
    ]
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_corpus = write_scenario(first, info, events)
    second_corpus = write_scenario(second, info, events)
    write_manifest(first, [first_corpus])
    write_manifest(second, [second_corpus])

    assert (first / "SYN-B.jsonl").read_bytes() == (second / "SYN-B.jsonl").read_bytes()
    assert (first / CORPUS_MANIFEST_FILENAME).read_bytes() == (second / CORPUS_MANIFEST_FILENAME).read_bytes()
    assert first_corpus.jsonl.sha256 == second_corpus.jsonl.sha256


def test_manifest_records_the_schema_version_and_source_digests(tmp_path: Path):
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    corpus = write_scenario(tmp_path / "corpus", info, [make_event()])
    manifest = write_manifest(tmp_path / "corpus", [corpus])
    assert manifest.schema_version == CORPUS_MANIFEST_SCHEMA_VERSION
    payload = json.loads((tmp_path / "corpus" / CORPUS_MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert payload["scenarios"][0]["files"][0]["sha256"] == info.files[0].sha256
    assert payload["scenarios"][0]["files"][0]["size"] == len(synthetic_payload("Security.evtx"))


def test_duplicate_evidence_ids_helper():
    assert duplicate_evidence_ids(["a", "b", "c"]) == ()
    assert duplicate_evidence_ids(["a", "b", "a", "b", "b"]) == ("a", "b")
    assert duplicate_evidence_ids([]) == ()


def _stub_reader(monkeypatch, *, channel_for):
    """Replace the EVTX reader with two synthetic records per file."""

    def fake_iter_records(path: Path):
        channel = channel_for(path)
        for record_id in (1, 2):
            yield RawRecord(
                record_id=record_id,
                event_id=1 if channel == SYSMON else 4688,
                channel=channel,
                computer="MAIR-WIN11-LAB",
                filetime=0,
                event_data={"User": "analyst"} if channel == SYSMON else {"SubjectUserName": "analyst"},
                raw_xml="<Event/>",
            )

    monkeypatch.setattr("m2.corpus.iter_records", fake_iter_records)


def test_normalise_datasets_writes_a_verifiable_corpus(tmp_path: Path, monkeypatch):
    datasets = tmp_path / "datasets"
    build_scenario_dir(datasets, "lab")
    _stub_reader(monkeypatch, channel_for=lambda path: SYSMON if path.name == "Sysmon.evtx" else SECURITY)
    out = tmp_path / "corpus"

    manifest = normalise_datasets(datasets, out)

    assert [scenario.scenario_id for scenario in manifest.scenarios] == ["SYN-B"]
    scenario = manifest.scenarios[0]
    assert scenario.counts_by_channel == {SECURITY: 2, SYSMON: 2}
    assert scenario.jsonl.line_count == 4
    assert scenario.jsonl.sha256 == sha256_file(out / "SYN-B.jsonl")
    lines = [json.loads(line) for line in (out / "SYN-B.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {line["evidence_id"] for line in lines} == {"SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SYS-1", "SYN-B-SYS-2"}
    # filetime 0 is 1601-01-01, i.e. outside the SYN-B window, but the record is still kept.
    assert all(line["in_scenario_window"] is False for line in lines)


def test_duplicate_evidence_ids_abort_before_anything_is_written(tmp_path: Path, monkeypatch):
    datasets = tmp_path / "datasets"
    directory = build_scenario_dir(datasets, "lab")
    _add_second_security_file(directory)
    # Two declared Security files hand back the same record numbers, so the same evidence_id.
    _stub_reader(monkeypatch, channel_for=lambda path: SECURITY if path.name.startswith("Security") else SYSMON)
    out = tmp_path / "corpus"

    with pytest.raises(CorpusError, match="duplicate evidence_id"):
        normalise_datasets(datasets, out)

    assert list(out.glob("*.jsonl")) == []
    assert not (out / CORPUS_MANIFEST_FILENAME).exists()


def test_scenario_directories_are_sorted_and_ignore_other_directories(tmp_path: Path):
    root = tmp_path / "datasets"
    (root / "S02" / "metadata").mkdir(parents=True)
    (root / "S02" / "metadata" / "manifest.json").write_text("{}", encoding="utf-8")
    (root / "S01" / "metadata").mkdir(parents=True)
    (root / "S01" / "metadata" / "manifest.json").write_text("{}", encoding="utf-8")
    (root / "notes").mkdir()
    assert [path.name for path in scenario_directories(root)] == ["S01", "S02"]


def test_missing_datasets_directory_raises(tmp_path: Path):
    with pytest.raises(CorpusError, match="does not exist"):
        normalise_datasets(tmp_path / "absent", tmp_path / "corpus")


def test_datasets_without_scenarios_raises(tmp_path: Path):
    (tmp_path / "datasets").mkdir()
    with pytest.raises(CorpusError, match="no scenario directories"):
        normalise_datasets(tmp_path / "datasets", tmp_path / "corpus")


# --- channel attribution and per-file counts (phase-1 F2) -------------------------


def _raw(channel: str, record_id: int = 1) -> RawRecord:
    return RawRecord(
        record_id=record_id,
        event_id=1 if channel == SYSMON else 4688,
        channel=channel,
        computer="MAIR-WIN11-LAB",
        filetime=0,
        event_data={"User": "analyst"} if channel == SYSMON else {"SubjectUserName": "analyst"},
        raw_xml="<Event/>",
    )


def test_require_record_channel_accepts_a_match_and_rejects_a_mismatch(tmp_path: Path):
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    security, sysmon = info.files
    require_record_channel(security, _raw(SECURITY))
    require_record_channel(sysmon, _raw(SYSMON))
    with pytest.raises(CorpusError, match="manifest declares channel"):
        require_record_channel(security, _raw(SYSMON))


def test_a_record_from_another_channel_aborts_before_anything_is_written(tmp_path: Path, monkeypatch):
    datasets = tmp_path / "datasets"
    build_scenario_dir(datasets, "lab")
    # Every file hands back Sysmon records, so the Security file contradicts its manifest.
    _stub_reader(monkeypatch, channel_for=lambda path: SYSMON)
    out = tmp_path / "corpus"

    with pytest.raises(CorpusError, match="manifest declares channel"):
        normalise_datasets(datasets, out)

    assert list(out.glob("*.jsonl")) == []
    assert not (out / CORPUS_MANIFEST_FILENAME).exists()


def test_source_filename_of_requires_a_declared_source_file(tmp_path: Path):
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    with pytest.raises(CorpusError, match="does not reference any file"):
        source_filename_of(info, make_event(record_id=1, filename="Other.evtx"))


def _add_second_security_file(directory: Path) -> None:
    """Declare a second Security file in a synthetic lab manifest, with payload and digest."""
    manifest_path = directory / "metadata" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = dict(manifest["files"][0])
    entry["filename"] = "Security2.evtx"
    payload = synthetic_payload(entry["filename"])
    (directory / "raw" / entry["filename"]).write_bytes(payload)
    entry["size_bytes"] = len(payload)
    entry["sha256"] = hashlib.sha256(payload).hexdigest()
    manifest["files"].append(entry)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def test_event_count_is_attributed_to_each_source_file(tmp_path: Path):
    """Two files on one channel must not each claim the whole channel's count."""
    directory = build_scenario_dir(tmp_path / "datasets", "lab")
    _add_second_security_file(directory)
    info = load_scenario(directory)
    events = [
        make_event(record_id=1, filename="Security.evtx"),
        make_event(record_id=2, filename="Security2.evtx"),
        make_event(record_id=3, channel=SYSMON, filename="Sysmon.evtx"),
    ]

    corpus = write_scenario(tmp_path / "corpus", info, events)

    assert [(source.filename, source.event_count) for source in corpus.files] == [
        ("Security.evtx", 1),
        ("Sysmon.evtx", 1),
        ("Security2.evtx", 1),
    ]
    assert corpus.counts_by_channel == {SECURITY: 2, SYSMON: 1}


def test_written_manifest_counts_real_files_per_source(tmp_path: Path, monkeypatch):
    datasets = tmp_path / "datasets"
    build_scenario_dir(datasets, "lab")
    _stub_reader(monkeypatch, channel_for=lambda path: SYSMON if path.name == "Sysmon.evtx" else SECURITY)
    out = tmp_path / "corpus"

    manifest = normalise_datasets(datasets, out)

    assert [(source.filename, source.event_count) for source in manifest.scenarios[0].files] == [
        ("Security.evtx", 2),
        ("Sysmon.evtx", 2),
    ]
