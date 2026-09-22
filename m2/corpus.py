"""Deterministic corpus writer.

Layout written under ``--out``::

    <out>/<scenario>.jsonl          one NormalisedEvent per line, sorted by (timestamp_ticks, evidence_id)
    <out>/corpus_manifest.json      schema version, source digests, per-channel/event-ID counts, jsonl digests

Guarantees:

* **Deterministic.** Two runs over the same inputs produce byte-identical files. Keys are
  sorted, non-ASCII is preserved rather than escaped, lines end in ``\n`` (never CRLF), the
  scenario order is sorted, and nothing records the wall-clock time of the run — a corpus
  file that contained "now" could never be reproduced or diffed.
* **Verified before parsed.** Every source file's SHA-256 is checked against its manifest
  before the EVTX parser sees it, so a wrong or truncated export aborts the run instead of
  silently producing a corpus from partial evidence.
* **No dropped records.** Every record the reader yields becomes an event; problems land in
  ``parse_warnings``.
* **Channels are checked against the manifest.** A record whose ``System/Channel`` differs from
  the channel its source file declares aborts the run. The alternative — trusting the manifest
  and warning — would leave ``raw_reference`` pointing at a file the corpus manifest describes
  as the wrong channel, and no consumer could tell. This is a container-level contradiction,
  not a record-level oddity, so it is not deferred to ``parse_warnings``.
* **Counts are per source file.** ``SourceDigest.event_count`` counts the events attributed to
  that file (by ``raw_reference``), never everything on its channel.
* **No duplicate ``evidence_id`` anywhere.** The ID embeds scenario, channel and record ID,
  so a duplicate means two different writes claimed the same event.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from m2.evtx_reader import RawRecord, iter_records
from m2.manifest import MANIFEST_FILENAME, METADATA_DIRNAME, ScenarioInfo, SourceFile, load_scenario, sha256_file
from m2.normalise import make_raw_reference, normalise_record
from m2.schema import SHA256_PATTERN, NormalisedEvent, event_to_json

CORPUS_MANIFEST_SCHEMA_VERSION = "m2-corpus-v1"
CORPUS_MANIFEST_FILENAME = "corpus_manifest.json"
JSONL_SUFFIX = ".jsonl"


class CorpusError(ValueError):
    """The corpus could not be written from the given datasets."""


class SourceDigest(BaseModel):
    """Manifest digest of one original file plus how many of its records were normalised."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    filename: str = Field(min_length=1)
    channel: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size: int = Field(ge=0)
    event_count: int = Field(ge=0)


class JsonlDigest(BaseModel):
    """Digest of one written ``.jsonl`` file."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    filename: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)
    line_count: int = Field(ge=0)


class ScenarioCorpus(BaseModel):
    """What one scenario contributed to the corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    scenario_id: str = Field(min_length=1)
    files: tuple[SourceDigest, ...] = Field(min_length=1)
    jsonl: JsonlDigest
    counts_by_channel: dict[str, int]
    counts_by_event_id: dict[str, dict[str, int]]


class CorpusManifest(BaseModel):
    """``corpus_manifest.json``: everything needed to verify a written corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: str = CORPUS_MANIFEST_SCHEMA_VERSION
    scenarios: tuple[ScenarioCorpus, ...]


def event_sort_key(event: NormalisedEvent) -> tuple[int, str]:
    """The one ordering M2 uses everywhere: ticks ascending, then ``evidence_id``."""
    return (event.timestamp_ticks, event.evidence_id)


def duplicate_evidence_ids(evidence_ids: Iterable[str]) -> tuple[str, ...]:
    """Every ID that occurs more than once, sorted; empty when the corpus is unique."""
    counts = Counter(evidence_ids)
    return tuple(sorted(evidence_id for evidence_id, count in counts.items() if count > 1))


def require_record_channel(source: SourceFile, raw: RawRecord) -> None:
    """Fail closed when a record's own channel contradicts the manifest channel of its file."""
    if raw.channel != source.channel:
        raise CorpusError(
            f"{source.path.name}: manifest declares channel {source.channel!r} but record {raw.record_id} "
            f"carries System/Channel {raw.channel!r}"
        )


def source_filename_of(info: ScenarioInfo, event: NormalisedEvent) -> str:
    """The declared source file ``event`` came from, matched by its exact ``raw_reference``."""
    for source in info.files:
        if event.raw_reference == make_raw_reference(info.scenario_id, source.path.name, event.record_id):
            return source.path.name
    raise CorpusError(
        f"event {event.evidence_id} does not reference any file declared by scenario {info.scenario_id}"
    )


def write_jsonl(path: Path, events: Sequence[NormalisedEvent]) -> JsonlDigest:
    """Write ``events`` sorted by :func:`event_sort_key` and return the file digest."""
    ordered = sorted(events, key=event_sort_key)
    payload = "".join(f"{event_to_json(event)}\n" for event in ordered)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8", newline="\n")
    return JsonlDigest(filename=path.name, sha256=sha256_file(path), line_count=len(ordered))


def write_scenario(out_dir: Path, info: ScenarioInfo, events: Sequence[NormalisedEvent]) -> ScenarioCorpus:
    """Write ``<scenario>.jsonl`` and describe what went into it."""
    jsonl = write_jsonl(out_dir / f"{info.scenario_id}{JSONL_SUFFIX}", events)
    by_channel = Counter(event.channel for event in events)
    by_event_id: dict[str, dict[str, int]] = {}
    for channel in sorted(by_channel):
        counts = Counter(str(event.source_event_id) for event in events if event.channel == channel)
        by_event_id[channel] = dict(sorted(counts.items(), key=lambda item: int(item[0])))
    per_file = Counter(source_filename_of(info, event) for event in events)
    files = tuple(
        SourceDigest(
            filename=source.path.name,
            channel=source.channel,
            sha256=source.sha256,
            size=source.size,
            event_count=per_file[source.path.name],
        )
        for source in info.files
    )
    return ScenarioCorpus(
        scenario_id=info.scenario_id,
        files=files,
        jsonl=jsonl,
        counts_by_channel=dict(sorted(by_channel.items())),
        counts_by_event_id=by_event_id,
    )


def write_manifest(out_dir: Path, scenarios: Sequence[ScenarioCorpus]) -> CorpusManifest:
    """Write ``corpus_manifest.json`` for already-written scenario files."""
    manifest = CorpusManifest(scenarios=tuple(scenarios))
    payload = json.dumps(manifest.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, indent=2)
    (out_dir / CORPUS_MANIFEST_FILENAME).write_text(f"{payload}\n", encoding="utf-8", newline="\n")
    return manifest


def scenario_directories(datasets_dir: Path | str) -> tuple[Path, ...]:
    """Every scenario directory under ``datasets_dir``, in sorted order."""
    root = Path(datasets_dir)
    if not root.is_dir():
        raise CorpusError(f"datasets directory {root} does not exist")
    return tuple(
        sorted(
            (entry for entry in root.iterdir() if (entry / METADATA_DIRNAME / MANIFEST_FILENAME).is_file()),
            key=lambda entry: entry.name,
        )
    )


def normalise_datasets(datasets_dir: Path | str, out_dir: Path | str) -> CorpusManifest:
    """Parse every scenario under ``datasets_dir`` and write the corpus under ``out_dir``."""
    directories = scenario_directories(datasets_dir)
    if not directories:
        raise CorpusError(f"no scenario directories under {datasets_dir} (expected <scenario>/metadata/manifest.json)")

    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)

    parsed: list[tuple[ScenarioInfo, list[NormalisedEvent]]] = []
    all_ids: list[str] = []
    for directory in directories:
        info = load_scenario(directory)
        events: list[NormalisedEvent] = []
        for source in info.files:
            for raw in iter_records(source.path):
                require_record_channel(source, raw)
                events.append(
                    normalise_record(
                        raw,
                        scenario_id=info.scenario_id,
                        source_filename=source.path.name,
                        source_sha256=source.sha256,
                        window_start_ticks=info.window_start_ticks,
                        window_end_ticks=info.window_end_ticks,
                    )
                )
        all_ids.extend(event.evidence_id for event in events)
        parsed.append((info, events))

    # Checked before anything is written, so a duplicated corpus is never left on disk.
    duplicates = duplicate_evidence_ids(all_ids)
    if duplicates:
        raise CorpusError(f"duplicate evidence_id in corpus: {', '.join(duplicates)}")
    scenarios = [write_scenario(destination, info, events) for info, events in parsed]
    return write_manifest(destination, scenarios)
