"""Dual-shape dataset manifest loading (AGENTS.md I5).

Contract
--------

``datasets/<scenario>/metadata/`` holds two files in one of two shapes:

* ``S01``: ``manifest.json`` with ``schema_version``, ``generated_at_utc`` and per-file
  ``relative_path`` + ``source_channel``; ``scenario_metadata.json`` with
  ``capture_start_utc`` / ``capture_end_utc``.
* ``S02``/``S03``: ``manifest.json`` with ``collection_time_utc``, ``collection_host`` and
  per-file ``filename`` + ``channel`` (the file always lives under ``raw/``);
  ``scenario_metadata.json`` with ``scenario_start_utc`` / ``scenario_end_utc``.

Both shapes are parsed explicitly; nothing is inferred by guessing. A file that does not
match either shape, or that mixes them, raises :class:`ManifestError` instead of being
half-read. Source SHA-256 values are verified against the bytes on disk, and an unfetched
Git LFS pointer is reported as such rather than as a hash mismatch. ``size_bytes`` is kept
as metadata; the digest check already covers truncation and corruption.

``window_start_ticks`` / ``window_end_ticks`` are shared-epoch 100 ns ticks (see
:mod:`event_processing.timeutil`) and are inclusive at both ends.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from event_processing.ids import CHANNEL_CODES
from event_processing.timeutil import iso_to_ticks

MANIFEST_FILENAME = "manifest.json"
SCENARIO_METADATA_FILENAME = "scenario_metadata.json"
METADATA_DIRNAME = "metadata"
RAW_DIRNAME = "raw"

LFS_POINTER_PREFIX = b"version https://git-lfs"
LFS_POINTER_MAX_BYTES = 1024
_HASH_BLOCK_BYTES = 1024 * 1024

# (schema_version, generated_at_utc) identifies S01; (collection_time_utc, collection_host)
# identifies S02/S03. Requiring all markers of a shape means a mixed file matches neither.
S01_MANIFEST_MARKERS = ("schema_version", "generated_at_utc")
LAB_MANIFEST_MARKERS = ("collection_time_utc", "collection_host")

# Ordered: the first complete pair wins; two complete pairs is an error, not a coin toss.
WINDOW_FIELD_PAIRS = (
    ("capture_start_utc", "capture_end_utc"),
    ("scenario_start_utc", "scenario_end_utc"),
)


class ManifestError(ValueError):
    """Dataset metadata is absent, unreadable, inconsistent or fails verification."""


class SourceFile(BaseModel):
    """One original evidence file declared by a scenario manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    channel: str
    path: Path
    sha256: str = Field(pattern=r"^[0-9A-Fa-f]{64}$")
    size: int = Field(ge=0)


class ScenarioInfo(BaseModel):
    """Everything the normaliser needs about one scenario, in ticks and absolute paths."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    scenario_id: str
    files: tuple[SourceFile, ...] = Field(min_length=1)
    window_start_ticks: int
    window_end_ticks: int
    host: str | None = None

    @model_validator(mode="after")
    def ordered_window(self) -> ScenarioInfo:
        if self.window_start_ticks > self.window_end_ticks:
            raise ValueError("scenario window start must not be after its end")
        return self


def is_lfs_pointer(path: Path) -> bool:
    """True when ``path`` holds an unfetched Git LFS pointer instead of real content."""
    try:
        if path.stat().st_size > LFS_POINTER_MAX_BYTES:
            return False
        with path.open("rb") as handle:
            return handle.read(len(LFS_POINTER_PREFIX)) == LFS_POINTER_PREFIX
    except OSError:
        return False


def sha256_file(path: Path) -> str:
    """Lowercase hex SHA-256 of ``path``, streamed so large evidence files stay cheap."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_HASH_BLOCK_BYTES), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_file(path: Path, sha256: str) -> None:
    """Check that ``path`` exists, is not an LFS pointer and matches ``sha256`` exactly."""
    if not path.is_file():
        raise ManifestError(f"evidence file {path} is missing")
    if is_lfs_pointer(path):
        raise ManifestError(f"evidence file {path} is an unfetched Git LFS pointer")
    actual = sha256_file(path)
    if actual != sha256.lower():
        raise ManifestError(f"evidence file {path} has sha256 {actual}, manifest declares {sha256.lower()}")


def load_scenario(scenario_dir: Path | str, *, verify_hashes: bool = True) -> ScenarioInfo:
    """Read one scenario directory into a :class:`ScenarioInfo`.

    With ``verify_hashes=True`` (the default) every declared source file must exist, be real
    content and match its manifest digest before the caller parses anything.
    """
    directory = Path(scenario_dir)
    manifest = _load_json(directory / METADATA_DIRNAME / MANIFEST_FILENAME)
    metadata = _load_json(directory / METADATA_DIRNAME / SCENARIO_METADATA_FILENAME)
    shape = _manifest_shape(manifest, directory)

    files = tuple(_source_file(directory, entry, shape) for entry in _manifest_entries(manifest, directory))
    scenario_id = _require_str(manifest, "scenario_id", directory)
    metadata_scenario_id = metadata.get("scenario_id")
    if metadata_scenario_id is not None and metadata_scenario_id != scenario_id:
        raise ManifestError(
            f"{directory}: manifest scenario_id {scenario_id!r} differs from "
            f"scenario_metadata scenario_id {metadata_scenario_id!r}"
        )

    start_key, end_key = _window_keys(metadata, directory)
    try:
        info = ScenarioInfo(
            scenario_id=scenario_id,
            files=files,
            window_start_ticks=iso_to_ticks(_require_str(metadata, start_key, directory)),
            window_end_ticks=iso_to_ticks(_require_str(metadata, end_key, directory)),
            host=metadata.get("host"),
        )
    except ValueError as error:  # includes pydantic's ValidationError
        raise ManifestError(f"{directory}: scenario metadata is inconsistent: {error}") from error
    if verify_hashes:
        for source in info.files:
            verify_file(source.path, source.sha256)
    return info


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ManifestError(f"required metadata file {path} is missing")
    try:
        # utf-8-sig: the PowerShell-generated manifests carry a UTF-8 BOM.
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"{path} is not valid JSON: {error}") from error
    if not isinstance(data, dict):
        raise ManifestError(f"{path} must contain a JSON object")
    return data


def _manifest_shape(manifest: dict[str, Any], directory: Path) -> str:
    has_s01 = all(marker in manifest for marker in S01_MANIFEST_MARKERS)
    has_lab = all(marker in manifest for marker in LAB_MANIFEST_MARKERS)
    if has_s01 and not has_lab:
        return "s01"
    if has_lab and not has_s01:
        return "lab"
    raise ManifestError(
        f"{directory / METADATA_DIRNAME / MANIFEST_FILENAME}: unknown manifest shape; expected "
        f"all of {S01_MANIFEST_MARKERS} (S01) or all of {LAB_MANIFEST_MARKERS} (S02/S03)"
    )


def _manifest_entries(manifest: dict[str, Any], directory: Path) -> list[dict[str, Any]]:
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise ManifestError(f"{directory}: manifest must declare a non-empty 'files' list")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ManifestError(f"{directory}: every manifest 'files' entry must be an object")
    return entries


def _source_file(directory: Path, entry: dict[str, Any], shape: str) -> SourceFile:
    channel_key = "source_channel" if shape == "s01" else "channel"
    try:
        channel = entry[channel_key]
        size = entry["size_bytes"]
        declared = entry["sha256"]
    except KeyError as error:
        raise ManifestError(f"{directory}: manifest file entry {entry!r} is missing {error.args[0]!r}") from error
    if channel not in CHANNEL_CODES:
        raise ManifestError(f"{directory}: manifest declares unsupported channel {channel!r}")
    # S01 stores "raw/<name>" in relative_path; the lab shape stores a bare filename that
    # always lives under raw/.
    relative = entry.get("relative_path")
    if not isinstance(relative, str) or not relative:
        filename = entry.get("filename")
        if not isinstance(filename, str) or not filename:
            raise ManifestError(f"{directory}: manifest file entry {entry!r} has no usable path")
        relative = f"{RAW_DIRNAME}/{filename}"
    root = directory.resolve()
    path = (directory / relative).resolve()
    if not path.is_relative_to(root):
        raise ManifestError(f"{directory}: manifest path {relative!r} escapes the scenario directory")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ManifestError(f"{directory}: manifest size_bytes {size!r} for {relative!r} must be a non-negative int")
    try:
        return SourceFile(channel=channel, path=path, sha256=declared, size=size)
    except ValueError as error:  # includes pydantic's ValidationError
        raise ManifestError(f"{directory}: invalid manifest entry for {relative!r}: {error}") from error


def _window_keys(metadata: dict[str, Any], directory: Path) -> tuple[str, str]:
    complete = [pair for pair in WINDOW_FIELD_PAIRS if all(key in metadata for key in pair)]
    if len(complete) != 1:
        raise ManifestError(
            f"{directory / METADATA_DIRNAME / SCENARIO_METADATA_FILENAME}: expected exactly one complete "
            f"window field pair from {WINDOW_FIELD_PAIRS}, found {complete}"
        )
    return complete[0]


def _require_str(data: dict[str, Any], key: str, directory: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{directory}: {key!r} must be a non-empty string, got {value!r}")
    return value
