"""Hand-written synthetic scenario directories for tests that must not need real EVTX.

The manifest and scenario-metadata *shapes* live in ``m2/tests/fixtures/*.json`` and mirror
the two real dataset shapes (AGENTS.md I5). Payload digests are **not** baked into those
fixtures: Git converts LF to CRLF on checkout, so a checked-in file's bytes — and therefore
its SHA-256 — are not stable across checkouts. The fixtures carry placeholder digests and
:func:`build_scenario_dir` patches in the digest of the payload it just wrote. Set
``corrupt_hashes=True`` for the mismatch path.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from m2.ids import make_evidence_id
from m2.normalise import make_raw_reference
from m2.schema import CHANNEL_SOURCE_TYPES, NormalisedEvent
from m2.timeutil import iso_to_ticks, ticks_to_iso

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
PAYLOAD_PREFIX = b"M2 synthetic evidence payload: "

SHAPES = {
    "s01": ("manifest_s01_shape.json", "scenario_metadata_s01_shape.json"),
    "lab": ("manifest_lab_shape.json", "scenario_metadata_lab_shape.json"),
}

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
CHANNEL_FILENAMES = {SECURITY: "Security.evtx", SYSMON: "Sysmon.evtx"}
SAMPLE_TICKS = iso_to_ticks("2026-09-21T02:05:30.0430374Z")
SAMPLE_SHA256 = "D396CE599723189331D440EDD55CC055C28EB4B6AD45A421D07A8E83A2F0EBA7"


def make_event(
    *,
    scenario_id: str = "SYN-B",
    channel: str = SECURITY,
    record_id: int = 1,
    event_id: int = 4688,
    timestamp_ticks: int = SAMPLE_TICKS,
    host: str | None = "MAIR-WIN11-LAB",
    user: str | None = "analyst",
    event_data: dict[str, str] | None = None,
    in_scenario_window: bool = True,
    parse_warnings: tuple[str, ...] = (),
) -> NormalisedEvent:
    """A small, valid normalised event; every field can be overridden."""
    return NormalisedEvent(
        evidence_id=make_evidence_id(scenario_id, channel, record_id),
        scenario_id=scenario_id,
        channel=channel,
        source_type=CHANNEL_SOURCE_TYPES[channel],
        record_id=record_id,
        source_event_id=event_id,
        timestamp_utc=ticks_to_iso(timestamp_ticks),
        timestamp_ticks=timestamp_ticks,
        host=host,
        user=user,
        event_data={"SubjectUserName": "analyst"} if event_data is None else event_data,
        raw_reference=make_raw_reference(scenario_id, CHANNEL_FILENAMES[channel], record_id),
        source_sha256=SAMPLE_SHA256,
        raw_xml="<Event><System><EventID>4688</EventID></System></Event>",
        in_scenario_window=in_scenario_window,
        parse_warnings=parse_warnings,
    )


def synthetic_payload(filename: str) -> bytes:
    """Deterministic bytes for a synthetic evidence file; never a real EVTX file."""
    return PAYLOAD_PREFIX + filename.encode("ascii") + b"\n"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def build_scenario_dir(
    root: Path,
    shape: str = "lab",
    *,
    corrupt_hashes: bool = False,
) -> Path:
    """Create ``root/<scenario_id>/{metadata,raw}`` from a fixture shape and return it."""
    manifest_name, metadata_name = SHAPES[shape]
    manifest = load_fixture(manifest_name)
    metadata = load_fixture(metadata_name)
    directory = root / metadata["scenario_id"]
    (directory / "metadata").mkdir(parents=True)
    (directory / "raw").mkdir(parents=True)

    for entry in manifest["files"]:
        payload = synthetic_payload(entry["filename"])
        (directory / "raw" / entry["filename"]).write_bytes(payload)
        entry["size_bytes"] = len(payload)
        entry["sha256"] = "0" * 64 if corrupt_hashes else hashlib.sha256(payload).hexdigest()

    write_manifest(directory, manifest)
    write_scenario_metadata(directory, metadata)
    return directory


def write_manifest(directory: Path, manifest: dict[str, Any]) -> None:
    _write_json(directory / "metadata" / "manifest.json", manifest)


def write_scenario_metadata(directory: Path, metadata: dict[str, Any]) -> None:
    _write_json(directory / "metadata" / "scenario_metadata.json", metadata)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
