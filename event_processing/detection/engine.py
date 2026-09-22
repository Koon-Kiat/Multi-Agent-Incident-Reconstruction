"""The detection engine: run the rule catalogue over one verified corpus and write results.

Contract
--------

* The engine only ever reads a corpus through :class:`~event_processing.query.EventStore`, so every ``.jsonl``
  digest is verified before a rule sees a line. It never writes into ``datasets/``.
* A rule sees one scenario's events in ``(timestamp_ticks, evidence_id)`` ascending order, and
  the engine checks afterwards that no two detections in the run share a ``detection_id``.
* Output is **deterministic**: two runs over the same corpus write byte-identical files. Every
  document is sorted-key JSON with non-ASCII preserved, ``\\n`` line endings and no run
  timestamp. Run metadata stays in the separate ``DetectionRun`` header, which records the
  corpus manifest's sha256 so a run can be traced to the corpus revision it describes.
* ``<out>/<scenario>.json`` holds one :class:`~event_processing.detection.schema.DetectionRun` per scenario
  and ``<out>/summary.json`` holds the per-scenario, per-rule counts. Only scenarios present in
  the corpus are written, and a stale run file left in ``<out>`` by an earlier run — a scenario
  the corpus no longer holds, say — is **removed**, because a consumer that globs the directory
  would otherwise score a run that describes a corpus revision that no longer exists.
  The removal is deliberately narrow. Only a direct child that (a) is named ``<scenario_id>.json``
  or ``summary.json`` **and** (b) parses as JSON carrying this package's schema marker
  (``schema_version == "detection-run-v1"``, with a matching ``scenario_id`` for a scenario file or
  the ``artifact == "detection-summary"`` marker for the summary) is deleted. Everything else in
  ``<out>`` — a ``manifest.json``, a ``package.json``, a foreign or malformed ``S02.json`` — is
  left exactly as it is; ``detect`` owns only the artefacts it writes itself. Nothing outside
  ``<out>`` and no subdirectory is ever touched.
* ``--out`` is refused outright when it resolves inside a ``datasets/`` or ``ground_truth/`` tree
  (any path component named either, case-insensitively), and when it is the corpus directory
  itself. Both are invalid input rather than a failed run: ``python -m event_processing detect`` exits ``2`` and
  writes nothing.
* ``triggers_for(scenario_id)`` is the Incident Reconstruction Orchestrator-facing entry point: it returns the scenario's
  detections, ordered by ``(window_start_utc, detection_id)``, so a caller can route windows to
  Authentication Investigation Agent/Endpoint Investigation Agent without reading the written files.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from event_processing.corpus import CORPUS_MANIFEST_FILENAME
from event_processing.detection.rules import RULES, Rule
from event_processing.detection.schema import (
    DETECTION_RUN_SCHEMA_VERSION,
    DETECTION_SUMMARY_MARKER,
    Detection,
    DetectionRun,
    DetectionSummary,
    ScenarioSummary,
    run_to_json,
    summary_to_json,
)
from event_processing.ids import SCENARIO_ID_RE
from event_processing.manifest import sha256_file
from event_processing.query import EventStore

SUMMARY_FILENAME = "summary.json"

# Trees that the caller's output path must never resolve into. The check is by path component,
# not by comparing against this repository's own roots, so it also refuses a directory named
# `datasets` next to the caller's own evidence: over-refusal is harmless, data loss is not.
PROTECTED_OUTPUT_TREE_NAMES = ("datasets", "ground_truth")
_PROTECTED_OUTPUT_PARTS = frozenset(name.casefold() for name in PROTECTED_OUTPUT_TREE_NAMES)


class DetectionError(ValueError):
    """The corpus cannot be detected over, or the rules produced an inconsistent run."""


class DetectionOutputError(DetectionError):
    """``--out`` names a directory ``detect`` must not write into; invalid input, never a run."""


class DetectionEngine:
    """Run every rule of the catalogue over one :class:`EventStore`.

    ``corpus_manifest_sha256`` is recorded in every artefact, so a stored run says which corpus
    revision produced it. Build it with :func:`corpus_manifest_digest`, or go through
    :func:`write_detections`, which does both.
    """

    def __init__(self, store: EventStore, *, corpus_manifest_sha256: str, rules: tuple[Rule, ...] = RULES) -> None:
        self._store = store
        self._corpus_manifest_sha256 = corpus_manifest_sha256
        self._rules = rules

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    @property
    def corpus_manifest_sha256(self) -> str:
        return self._corpus_manifest_sha256

    @property
    def scenario_ids(self) -> tuple[str, ...]:
        """Every scenario in the store, sorted; a scenario with no events is absent."""
        return self._store.scenario_ids

    def triggers_for(self, scenario_id: str) -> tuple[Detection, ...]:
        """Every detection of one scenario, ordered by ``(window_start_utc, detection_id)``.

        An unknown scenario, like a scenario with no matching event, yields no detection.
        """
        detections = [
            detection for rule in self._rules for detection in rule.fn(self._store.scenario_events(scenario_id))
        ]
        seen: set[str] = set()
        for detection in detections:
            if detection.detection_id in seen:
                raise DetectionError(f"two detections share the id {detection.detection_id}")
            seen.add(detection.detection_id)
        return tuple(sorted(detections, key=lambda detection: (detection.window_start_utc, detection.detection_id)))

    def run(self, scenario_id: str) -> DetectionRun:
        """One scenario's :class:`DetectionRun`, including every rule that was run over it."""
        return DetectionRun(
            scenario_id=scenario_id,
            corpus_manifest_sha256=self._corpus_manifest_sha256,
            rules=tuple(rule.spec.record() for rule in self._rules),
            detections=self.triggers_for(scenario_id),
        )

    def runs(self) -> tuple[DetectionRun, ...]:
        """One run per scenario in the store, in scenario order."""
        return tuple(self.run(scenario_id) for scenario_id in self._store.scenario_ids)

    def summary(self) -> DetectionSummary:
        """Per-scenario, per-rule counts for every scenario the corpus holds."""
        return summarise(self._corpus_manifest_sha256, self.runs())


def summarise(corpus_manifest_sha256: str, runs: Sequence[DetectionRun]) -> DetectionSummary:
    """Count the detections of each run per scenario and per rule."""
    scenarios = []
    for run in runs:
        counts = Counter(detection.rule_id for detection in run.detections)
        scenarios.append(
            ScenarioSummary(
                scenario_id=run.scenario_id,
                total=len(run.detections),
                counts_by_rule=dict(sorted(counts.items())),
            )
        )
    return DetectionSummary(corpus_manifest_sha256=corpus_manifest_sha256, scenarios=tuple(scenarios))


def corpus_manifest_digest(corpus_dir: Path | str) -> str:
    """The sha256 of ``corpus_manifest.json``, which identifies the corpus revision."""
    path = Path(corpus_dir) / CORPUS_MANIFEST_FILENAME
    if not path.is_file():
        raise DetectionError(f"corpus manifest {path} is missing; run 'python -m event_processing normalise' first")
    return sha256_file(path)


def write_detections(corpus_dir: Path | str, out_dir: Path | str) -> DetectionSummary:
    """Detect over a written corpus and write one run file per scenario plus ``summary.json``.

    ``out_dir`` is the directory ``detect`` owns: after writing this run's files, every stale
    **Event Processing & Detection Engine detection artefact** among its direct children is removed, and every other file is left
    alone (see the module docstring). ``out_dir`` may not resolve inside a ``datasets/`` or
    ``ground_truth/`` tree, and may not be the corpus directory, whose ``corpus_manifest.json``
    is not a detection artefact.
    """
    directory = Path(corpus_dir)
    destination = Path(out_dir)
    _refuse_protected_output(destination)
    if destination.resolve() == directory.resolve():
        raise DetectionOutputError(
            f"--out {destination} is the corpus directory; detect removes stale run files from "
            "--out, so the two directories must differ"
        )
    digest = corpus_manifest_digest(directory)
    engine = DetectionEngine(EventStore.load(directory), corpus_manifest_sha256=digest)
    runs = engine.runs()

    destination.mkdir(parents=True, exist_ok=True)
    written = {SUMMARY_FILENAME}
    for run in runs:
        name = f"{run.scenario_id}.json"
        _write_text(destination / name, f"{run_to_json(run)}\n")
        written.add(name)
    summary = summarise(engine.corpus_manifest_sha256, runs)
    _write_text(destination / SUMMARY_FILENAME, f"{summary_to_json(summary)}\n")
    _remove_stale_runs(destination, written)
    return summary


def _refuse_protected_output(destination: Path) -> None:
    """Fail closed when ``destination`` resolves into a tree ``detect`` must never write to."""
    for part in destination.resolve().parts:
        if part.casefold() in _PROTECTED_OUTPUT_PARTS:
            raise DetectionOutputError(
                f"--out {destination} is inside the {part}/ tree; "
                f"{' and '.join(f'{name}/' for name in PROTECTED_OUTPUT_TREE_NAMES)} are read-only for event_processing"
            )


def _remove_stale_runs(destination: Path, written: set[str]) -> tuple[Path, ...]:
    """Delete the Event Processing & Detection Engine detection artefacts in ``destination`` that this run did not write.

    Only a file that both carries an Event Processing & Detection Engine detection name and parses as an Event Processing & Detection Engine detection document is
    removed (see :func:`_is_detection_artefact`). A file this package did not write is data that
    belongs to whoever put it there, so it is left untouched rather than deleted or warned about.
    """
    removed: list[Path] = []
    for path in sorted(destination.glob("*.json")):
        if path.name not in written and _is_detection_artefact(path):
            path.unlink()
            removed.append(path)
    return tuple(removed)


def _is_detection_artefact(path: Path) -> bool:
    """True only for a JSON file that carries the name and the schema marker ``detect`` writes.

    A scenario run must be named ``<scenario_id>.json`` and declare that same ``scenario_id``
    alongside the run schema version; the summary must be named ``summary.json`` and declare the
    detection-summary ``artifact`` marker beside the same schema version. The marker is what makes
    the removal safe: ``manifest.json`` and ``package.json`` also match the scenario-id pattern,
    and only the marker distinguishes them from a real run.
    """
    document = _load_json_object(path)
    if document is None or document.get("schema_version") != DETECTION_RUN_SCHEMA_VERSION:
        return False
    if path.name == SUMMARY_FILENAME:
        return document.get("artifact") == DETECTION_SUMMARY_MARKER
    if not SCENARIO_ID_RE.fullmatch(path.stem):
        return False
    return document.get("scenario_id") == path.stem


def _load_json_object(path: Path) -> dict[str, object] | None:
    """The file's JSON object, or ``None`` for anything else, including unreadable or malformed."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _write_text(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8", newline="\n")
