"""T1.3 / AGENTS I5: both dataset manifest shapes load, verify and fail closed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from event_processing.ids import CHANNEL_CODES
from event_processing.manifest import (
    LFS_POINTER_PREFIX,
    ManifestError,
    is_lfs_pointer,
    load_scenario,
    sha256_file,
    verify_file,
)
from event_processing.tests.conftest import real_evtx
from event_processing.tests.synthetic import build_scenario_dir, load_fixture, synthetic_payload, write_manifest, write_scenario_metadata
from event_processing.timeutil import iso_to_ticks

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def test_a_reserved_scenario_id_is_rejected_before_anything_is_written(tmp_path: Path):
    # B4: a scenario called `summary` would write `summary.json`, which detect uses for its own
    # summary. The reserved name is refused at the manifest, where the id enters event_processing.
    directory = build_scenario_dir(tmp_path, "lab")
    for name in ("manifest.json", "scenario_metadata.json"):
        path = directory / "metadata" / name
        document = json.loads(path.read_text(encoding="utf-8"))
        document["scenario_id"] = "summary"
        path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ManifestError, match="is reserved"):
        load_scenario(directory)


def test_loads_the_s01_shape(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "s01")
    info = load_scenario(directory)
    assert info.scenario_id == "SYN-A"
    assert info.host == "win-dc-mhaag-attack-range-602"
    assert [source.channel for source in info.files] == [SECURITY, SYSMON]
    assert [source.path.name for source in info.files] == ["Security.evtx", "Sysmon.evtx"]
    assert all(source.path.is_file() for source in info.files)
    assert info.window_start_ticks == iso_to_ticks("2022-08-31T17:46:45.197821Z")
    assert info.window_end_ticks == iso_to_ticks("2022-08-31T17:48:41.545700Z")
    for source in info.files:
        assert source.sha256 == hashlib.sha256(synthetic_payload(source.path.name)).hexdigest()
        assert source.size == len(synthetic_payload(source.path.name))


def test_loads_the_lab_shape_and_resolves_raw_paths(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    info = load_scenario(directory)
    assert info.scenario_id == "SYN-B"
    assert info.host == "MAIR-WIN11-LAB"
    assert [source.channel for source in info.files] == [SECURITY, SYSMON]
    # The lab shape stores a bare filename; the loader must place it under raw/.
    assert all(source.path.parent.name == "raw" for source in info.files)
    assert info.window_start_ticks == iso_to_ticks("2026-09-21T02:04:38.9439270Z")
    assert info.window_end_ticks == iso_to_ticks("2026-09-21T02:06:18.3126076Z")


def test_hash_mismatch_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab", corrupt_hashes=True)
    with pytest.raises(ManifestError, match="sha256"):
        load_scenario(directory)


def test_missing_evidence_file_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    (directory / "raw" / "Security.evtx").unlink()
    with pytest.raises(ManifestError, match="missing"):
        load_scenario(directory)


def test_lfs_pointer_is_reported_as_such(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    (directory / "raw" / "Security.evtx").write_bytes(LFS_POINTER_PREFIX + b".github.com/spec/v1\n")
    with pytest.raises(ManifestError, match="LFS pointer"):
        load_scenario(directory)


def test_verify_hashes_false_skips_the_digest_check(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab", corrupt_hashes=True)
    info = load_scenario(directory, verify_hashes=False)
    assert info.scenario_id == "SYN-B"


def test_unknown_manifest_shape_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    manifest = load_fixture("manifest_lab_shape.json")
    manifest.pop("collection_time_utc")
    manifest.pop("collection_host")
    write_manifest(directory, {"scenario_id": "SYN-B", "files": manifest["files"]})
    with pytest.raises(ManifestError, match="unknown manifest shape"):
        load_scenario(directory, verify_hashes=False)


def test_mixed_manifest_shape_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    manifest = load_fixture("manifest_s01_shape.json")
    manifest["collection_time_utc"] = "2026-09-21T02:09:40.5430006Z"
    manifest["collection_host"] = "MAIR-WIN11-LAB"
    write_manifest(directory, manifest)
    with pytest.raises(ManifestError, match="unknown manifest shape"):
        load_scenario(directory, verify_hashes=False)


def test_missing_manifest_raises(tmp_path: Path):
    with pytest.raises(ManifestError, match="is missing"):
        load_scenario(tmp_path / "S99")


def test_missing_scenario_metadata_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    (directory / "metadata" / "scenario_metadata.json").unlink()
    with pytest.raises(ManifestError, match="scenario_metadata.json"):
        load_scenario(directory, verify_hashes=False)


def test_malformed_json_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    (directory / "metadata" / "manifest.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ManifestError, match="not valid JSON"):
        load_scenario(directory, verify_hashes=False)


def test_scenario_id_mismatch_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    metadata = load_fixture("scenario_metadata_lab_shape.json")
    metadata["scenario_id"] = "SYN-Z"
    write_scenario_metadata(directory, metadata)
    with pytest.raises(ManifestError, match="differs"):
        load_scenario(directory, verify_hashes=False)


def test_unknown_window_fields_raise(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    metadata = load_fixture("scenario_metadata_lab_shape.json")
    metadata.pop("scenario_start_utc")
    metadata.pop("scenario_end_utc")
    write_scenario_metadata(directory, metadata)
    with pytest.raises(ManifestError, match="window field pair"):
        load_scenario(directory, verify_hashes=False)


def test_two_window_field_pairs_raise(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    metadata = load_fixture("scenario_metadata_lab_shape.json")
    metadata["capture_start_utc"] = "2022-08-31T17:46:45.197821Z"
    metadata["capture_end_utc"] = "2022-08-31T17:48:41.545700Z"
    write_scenario_metadata(directory, metadata)
    with pytest.raises(ManifestError, match="window field pair"):
        load_scenario(directory, verify_hashes=False)


def test_window_end_before_start_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    metadata = load_fixture("scenario_metadata_lab_shape.json")
    metadata["scenario_start_utc"] = "2026-09-21T02:06:18.3126076Z"
    metadata["scenario_end_utc"] = "2026-09-21T02:04:38.9439270Z"
    write_scenario_metadata(directory, metadata)
    with pytest.raises(ManifestError, match="window start"):
        load_scenario(directory, verify_hashes=False)


def test_malformed_window_timestamp_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    metadata = load_fixture("scenario_metadata_lab_shape.json")
    metadata["scenario_start_utc"] = "2026-13-21T02:04:38.9439270Z"
    write_scenario_metadata(directory, metadata)
    with pytest.raises(ManifestError, match="inconsistent"):
        load_scenario(directory, verify_hashes=False)


def test_malformed_digest_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    manifest = load_fixture("manifest_lab_shape.json")
    manifest["files"][0]["sha256"] = "Z" * 64
    write_manifest(directory, manifest)
    with pytest.raises(ManifestError, match="invalid manifest entry"):
        load_scenario(directory, verify_hashes=False)


def test_unsupported_channel_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    manifest = load_fixture("manifest_lab_shape.json")
    manifest["files"][0]["channel"] = "Application"
    write_manifest(directory, manifest)
    with pytest.raises(ManifestError, match="unsupported channel"):
        load_scenario(directory, verify_hashes=False)


def test_path_escaping_the_scenario_directory_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    manifest = load_fixture("manifest_s01_shape.json")
    manifest["files"][0]["relative_path"] = "../escaped.evtx"
    write_manifest(directory, manifest)
    with pytest.raises(ManifestError, match="escapes the scenario directory"):
        load_scenario(directory, verify_hashes=False)


def test_entry_without_a_usable_path_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    manifest = load_fixture("manifest_lab_shape.json")
    manifest["files"][0].pop("filename")
    write_manifest(directory, manifest)
    with pytest.raises(ManifestError, match="no usable path"):
        load_scenario(directory, verify_hashes=False)


def test_empty_files_list_raises(tmp_path: Path):
    directory = build_scenario_dir(tmp_path, "lab")
    manifest = load_fixture("manifest_lab_shape.json")
    manifest["files"] = []
    write_manifest(directory, manifest)
    with pytest.raises(ManifestError, match="non-empty 'files'"):
        load_scenario(directory, verify_hashes=False)


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    [
        ("pointer.evtx", LFS_POINTER_PREFIX + b".github.com/spec/v1\n", True),
        ("ElfFile.evtx", b"ElfFile\x00" + b"\x00" * 4096, False),
        ("long_pointer.evtx", LFS_POINTER_PREFIX + b"x" * 4096, False),
        ("missing.evtx", None, False),
    ],
)
def test_is_lfs_pointer(tmp_path: Path, name: str, content: bytes | None, expected: bool):
    path = tmp_path / name
    if content is not None:
        path.write_bytes(content)
    assert is_lfs_pointer(path) is expected


def test_verify_file_accepts_a_matching_digest(tmp_path: Path):
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"ElfFile\x00payload")
    verify_file(path, sha256_file(path).upper())


def test_verify_file_rejects_a_short_sha256_argument(tmp_path: Path):
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"ElfFile\x00payload")
    with pytest.raises(ManifestError):
        verify_file(path, "abc")


def test_real_scenarios_load_and_verify(real_evtx_path):
    """Skipped in CI (lfs: false); the digest check reads the real EVTX bytes locally."""
    for scenario, channel in (("S01", SECURITY), ("S02", SECURITY), ("S03", SECURITY)):
        path = real_evtx(scenario, channel)
        info = load_scenario(path.parent.parent)
        assert info.scenario_id == scenario
        assert {source.channel for source in info.files} == set(CHANNEL_CODES)
        assert info.window_start_ticks < info.window_end_ticks
        assert info.host
