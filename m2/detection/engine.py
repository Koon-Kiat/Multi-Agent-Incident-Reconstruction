"""The detection engine: run the rule catalogue over one verified corpus and write results.

Contract
--------

* The engine only ever reads a corpus through :class:`~m2.query.EventStore`, so every ``.jsonl``
  digest is verified before a rule sees a line. It never writes into ``datasets/``.
* A rule sees one scenario's events in ``(timestamp_ticks, evidence_id)`` ascending order, and
  the engine checks afterwards that no two detections in the run share a ``detection_id``.
* Output is **deterministic**: two runs over the same corpus write byte-identical files. Every
  document is sorted-key JSON with non-ASCII preserved, ``\\n`` line endings and no run
  timestamp. Run metadata stays in the separate ``DetectionRun`` header, which records the
  corpus manifest's sha256 so a run can be traced to the corpus revision it describes.
* ``<out>/<scenario>.json`` holds one :class:`~m2.detection.schema.DetectionRun` per scenario
  and ``<out>/summary.json`` holds the per-scenario, per-rule counts. Only scenarios present in
  the corpus are written, and a stale ``*.json`` file left in ``<out>`` by an earlier run — a
  scenario the corpus no longer holds, say — is **removed**, because a consumer that globs the
  directory would otherwise score a run that describes a corpus revision that no longer exists.
  The removal is confined to the direct ``*.json`` children of the ``--out`` the caller named, so
  it never touches another directory, and ``--out`` may not be the corpus directory itself.
* ``triggers_for(scenario_id)`` is the M5-facing entry point: it returns the scenario's
  detections, ordered by ``(window_start_utc, detection_id)``, so a caller can route windows to
  M3/M4 without reading the written files.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from m2.corpus import CORPUS_MANIFEST_FILENAME
from m2.detection.rules import RULES, Rule
from m2.detection.schema import (
    Detection,
    DetectionRun,
    DetectionSummary,
    ScenarioSummary,
    run_to_json,
    summary_to_json,
)
from m2.manifest import sha256_file
from m2.query import EventStore

SUMMARY_FILENAME = "summary.json"


class DetectionError(ValueError):
    """The corpus cannot be detected over, or the rules produced an inconsistent run."""


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
        raise DetectionError(f"corpus manifest {path} is missing; run 'python -m m2 normalise' first")
    return sha256_file(path)


def write_detections(corpus_dir: Path | str, out_dir: Path | str) -> DetectionSummary:
    """Detect over a written corpus and write one run file per scenario plus ``summary.json``.

    ``out_dir`` is the directory ``detect`` owns: after writing this run's files, every other
    direct ``*.json`` child is removed as stale (see the module docstring). ``out_dir`` may not be
    the corpus directory, whose ``corpus_manifest.json`` is not a detection artefact.
    """
    directory = Path(corpus_dir)
    destination = Path(out_dir)
    if destination.resolve() == directory.resolve():
        raise DetectionError(
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


def _remove_stale_runs(destination: Path, written: set[str]) -> tuple[Path, ...]:
    """Delete the ``*.json`` files in ``destination`` that this run did not write.

    Only the direct children of the directory ``detect`` was given are considered: no
    subdirectory and no path outside ``destination`` is ever touched. The caller has already
    established that ``destination`` is not the corpus directory (see :func:`write_detections`).
    """
    removed: list[Path] = []
    for path in sorted(destination.glob("*.json")):
        if path.name not in written:
            path.unlink()
            removed.append(path)
    return tuple(removed)


def _write_text(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8", newline="\n")
