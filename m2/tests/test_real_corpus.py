"""T1.6 real-evidence acceptance: full-corpus counts, overlaps, determinism, window flags.

Skipped in CI, where the datasets are checked out with ``lfs: false``. The expected counts
are public properties of the corpus, reproducible with Windows' own parser::

    Get-WinEvent -Path datasets/S01/raw/Security.evtx -Oldest | Measure-Object

reports 1807 Security and 893 Sysmon records for S01, and AGENTS.md section 3 pins S02 and
S03 Security to 349 and 352.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from m2.corpus import CORPUS_MANIFEST_FILENAME, CorpusManifest, normalise_datasets
from m2.manifest import sha256_file
from m2.schema import NormalisedEvent
from m2.tests.conftest import real_datasets

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SCENARIOS = ("S01", "S02", "S03")

EXPECTED_BY_CHANNEL = {
    "S01": {SECURITY: 1807, SYSMON: 893},
    "S02": {SECURITY: 349, SYSMON: 1581},
    "S03": {SECURITY: 352, SYSMON: 1679},
}
EXPECTED_IN_WINDOW = {
    "S01": {SECURITY: 1503, SYSMON: 670},
    "S02": {SECURITY: 171, SYSMON: 620},
    "S03": {SECURITY: 163, SYSMON: 780},
}
SECURITY_OVERLAP = 335
SYSMON_OVERLAP = 1526

# AGENTS.md section 3 uses S01-SEC-31213331 as an I1 example; python-evtx's default chunk
# iteration cannot see it, because it stops 276 records early.
DOCUMENTED_S01_EXAMPLE_ID = "S01-SEC-31213331"


@pytest.fixture(scope="module")
def corpus_dir(real_corpus_dir: Path) -> Path:
    """The session-wide real corpus (see ``conftest.real_corpus_dir``)."""
    return real_corpus_dir


@pytest.fixture(scope="module")
def rows(corpus_dir: Path) -> dict[str, list[dict]]:
    """Every written line, parsed once per test session."""
    return {scenario: read_jsonl(corpus_dir / f"{scenario}.jsonl") for scenario in SCENARIOS}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_counts_match_the_public_totals(corpus_dir: Path):
    manifest = read_manifest(corpus_dir)
    assert [scenario.scenario_id for scenario in manifest.scenarios] == list(SCENARIOS)
    assert {scenario.scenario_id: scenario.counts_by_channel for scenario in manifest.scenarios} == EXPECTED_BY_CHANNEL
    for scenario in manifest.scenarios:
        assert scenario.jsonl.line_count == sum(scenario.counts_by_channel.values())


def test_scenario_windows_flag_the_public_in_out_split(rows: dict[str, list[dict]]):
    for scenario_id, expected in EXPECTED_IN_WINDOW.items():
        counted: dict[str, int] = {}
        for row in rows[scenario_id]:
            if row["in_scenario_window"]:
                counted[row["channel"]] = counted.get(row["channel"], 0) + 1
        assert counted == expected


def test_every_written_line_is_a_valid_normalised_event(corpus_dir: Path):
    for scenario_id in SCENARIOS:
        lines = (corpus_dir / f"{scenario_id}.jsonl").read_text(encoding="utf-8").splitlines()
        assert lines
        for line in lines:
            event = NormalisedEvent.model_validate_json(line)
            assert event.scenario_id == scenario_id


def test_evidence_ids_are_unique_across_the_whole_corpus(rows: dict[str, list[dict]]):
    ids = [row["evidence_id"] for scenario_id in SCENARIOS for row in rows[scenario_id]]
    assert len(ids) == len(set(ids)) == sum(sum(channels.values()) for channels in EXPECTED_BY_CHANNEL.values())


def test_jsonl_is_sorted_by_ticks_then_evidence_id(rows: dict[str, list[dict]]):
    for scenario_id in SCENARIOS:
        keys = [(row["timestamp_ticks"], row["evidence_id"]) for row in rows[scenario_id]]
        assert keys == sorted(keys)


def test_overlapping_record_ids_stay_unique_across_scenarios(rows: dict[str, list[dict]]):
    ids: dict[tuple[str, str], dict[int, str]] = {}
    for scenario_id in ("S02", "S03"):
        for row in rows[scenario_id]:
            ids.setdefault((scenario_id, row["channel"]), {})[row["record_id"]] = row["evidence_id"]

    for channel, expected in ((SECURITY, SECURITY_OVERLAP), (SYSMON, SYSMON_OVERLAP)):
        shared = set(ids[("S02", channel)]) & set(ids[("S03", channel)])
        assert len(shared) == expected
        # The same record number is two different events, so it must be two different IDs.
        assert {ids[("S02", channel)][record] for record in shared} & {
            ids[("S03", channel)][record] for record in shared
        } == set()


def test_the_documented_example_id_from_s01_exists(rows: dict[str, list[dict]]):
    assert DOCUMENTED_S01_EXAMPLE_ID in {row["evidence_id"] for row in rows["S01"]}


def test_manifest_jsonl_digests_match_the_written_files(corpus_dir: Path):
    for scenario in read_manifest(corpus_dir).scenarios:
        assert scenario.jsonl.sha256 == sha256_file(corpus_dir / scenario.jsonl.filename)


def test_rebuilding_one_scenario_is_byte_identical(tmp_path: Path, corpus_dir: Path):
    """Re-parsing real evidence must reproduce the same bytes, not just the same counts."""
    datasets = real_datasets()
    copied = tmp_path / "datasets"
    shutil.copytree(datasets / "S02", copied / "S02")

    rebuilt = normalise_datasets(copied, tmp_path / "rebuilt")

    assert (tmp_path / "rebuilt" / "S02.jsonl").read_bytes() == (corpus_dir / "S02.jsonl").read_bytes()
    assert next(s for s in rebuilt.scenarios if s.scenario_id == "S02").jsonl.sha256 == next(
        scenario.jsonl.sha256 for scenario in read_manifest(corpus_dir).scenarios if scenario.scenario_id == "S02"
    )


def read_manifest(out: Path) -> CorpusManifest:
    return CorpusManifest.model_validate_json((out / CORPUS_MANIFEST_FILENAME).read_text(encoding="utf-8"))
