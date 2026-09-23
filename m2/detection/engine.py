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
  the corpus are written, and a stale run file left in ``<out>`` by an earlier run — a scenario
  the corpus no longer holds, say — is **removed**, because a consumer that globs the directory
  would otherwise score a run that describes a corpus revision that no longer exists.
  The removal is deliberately narrow. Only a direct child that (a) is named ``<scenario_id>.json``
  or ``summary.json`` **and** (b) parses as JSON carrying this package's schema marker
  (``schema_version == "m2-detect-v1"``, with a matching ``scenario_id`` for a scenario file or
  the ``artifact == "detection-summary"`` marker for the summary) is deleted. Everything else in
  ``<out>`` — a ``manifest.json``, a ``package.json``, a foreign or malformed ``S02.json`` — is
  left exactly as it is; ``detect`` owns only the artefacts it writes itself. Nothing outside
  ``<out>`` and no subdirectory is ever touched.
* ``--out`` is refused outright when it resolves inside a ``datasets/`` or ``ground_truth/`` tree
  (any path component named either, case-insensitively), and when it is the corpus directory
  itself. Both are invalid input rather than a failed run: ``python -m m2 detect`` exits ``2`` and
  writes nothing.
* Before it writes, the engine checks every name it is about to use. A pre-existing file that does
  not carry the M2 detection marker is a foreign file, not a stale run of ours, so the whole run
  fails (``python -m m2 detect`` exits ``1``) and **nothing** — not even ``summary.json`` — is
  written. The same refusal covers a name that is not a regular file (a directory called
  ``S02.json``) and a symbolic link, because writing through either would not stay inside ``--out``
  or would not be the artefact the check inspected. A genuine M2 run for the same scenario is the
  artefact this run refreshes.
* The write itself is a two-phase rename: every document is first written to a dotted ``.tmp``
  sibling and all of them must succeed before any is renamed onto its final name. An I/O failure
  part way through therefore leaves the previous run's files in place and no temporary behind. A
  run also sweeps **its own** staging leftovers out of ``--out`` before it writes, because a
  process killed mid-run cannot clean up after itself; only a regular file matching the staging
  name pattern is removed.
* ``triggers_for(scenario_id)`` is the M5-facing entry point: it returns the scenario's
  detections, ordered by ``(window_start_utc, detection_id)``, so a caller can route windows to
  M3/M4 without reading the written files.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from m2.corpus import CORPUS_MANIFEST_FILENAME
from m2.detection.rules import RULES, Rule
from m2.detection.schema import (
    DETECTION_RUN_SCHEMA_VERSION,
    DETECTION_SUMMARY_MARKER,
    Detection,
    DetectionRun,
    DetectionSummary,
    ScenarioSummary,
    run_to_json,
    summary_to_json,
)
from m2.ids import SCENARIO_ID_RE, is_reserved_scenario_id
from m2.manifest import sha256_file
from m2.protected_paths import PROTECTED_OUTPUT_TREE_NAMES, protected_output_component
from m2.query import EventStore

SUMMARY_FILENAME = "summary.json"
# The name `_write_all` stages a document under: `.<target name>.tmp`. Every document detect
# writes ends in `.json`, so this one glob also matches a leftover whose scenario the corpus no
# longer holds.
STAGING_GLOB = ".*.json.tmp"


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
        reserved = sorted(scenario_id for scenario_id in store.scenario_ids if is_reserved_scenario_id(scenario_id))
        if reserved:
            raise DetectionError(
                f"scenario id {reserved[0]!r} is reserved; its run file would collide with "
                f"detect's own {SUMMARY_FILENAME}"
            )
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

    ``out_dir`` is the directory ``detect`` owns: after writing this run's files, every stale
    **M2 detection artefact** among its direct children is removed, and every other file is left
    alone (see the module docstring). ``out_dir`` may not resolve inside a ``datasets/`` or
    ``ground_truth/`` tree, and may not be the corpus directory, whose ``corpus_manifest.json``
    is not a detection artefact. A pre-existing file at a name this run would write must likewise
    be an M2 detection artefact, or the run fails before writing anything. Every document is staged
    under a dotted temporary name and renamed into place only once all of them exist, so an I/O
    failure part way through leaves the previous run's files intact. Before writing, the run
    removes any regular staging file (``.<name>.json.tmp``) an earlier killed run left behind; only
    a file matching that pattern is touched.
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

    written = {SUMMARY_FILENAME} | {f"{run.scenario_id}.json" for run in runs}
    # Checked before anything is written: a foreign file at a name this run would use stops the
    # whole run rather than being overwritten under the assumption that `--out` is ours.
    _refuse_foreign_overwrite(destination, written)

    destination.mkdir(parents=True, exist_ok=True)
    _sweep_own_staging_leftovers(destination)
    summary = summarise(engine.corpus_manifest_sha256, runs)
    payloads = [(destination / f"{run.scenario_id}.json", f"{run_to_json(run)}\n") for run in runs]
    payloads.append((destination / SUMMARY_FILENAME, f"{summary_to_json(summary)}\n"))
    _write_all(payloads)
    _remove_stale_runs(destination, written)
    return summary


def _refuse_protected_output(destination: Path) -> None:
    """Fail closed when ``destination`` resolves into a tree ``detect`` must never write to."""
    component = protected_output_component(destination)
    if component is not None:
        raise DetectionOutputError(
            f"--out {destination} is inside the {component}/ tree; "
            f"{' and '.join(f'{name}/' for name in PROTECTED_OUTPUT_TREE_NAMES)} are read-only for m2"
        )


def _refuse_foreign_overwrite(destination: Path, names: set[str]) -> None:
    """Refuse when a name this run would write is not an M2 detection artefact ``detect`` may replace.

    ``detect`` owns the *names* it writes, never the directory: a pre-existing ``SYN-B.json`` or
    ``summary.json`` that does not carry the M2 schema marker belongs to someone else, so the run
    stops before writing anything rather than replacing it. A genuine M2 run for the same scenario
    is the artefact this run refreshes, so it is not a collision.

    Anything that is not a regular file is refused outright, and a symbolic link is refused even when
    it points at a genuine M2 artefact: the marker check inspects the target, while the write would
    follow the link and land outside ``--out`` (or fail half way, as a directory named ``S02.json``
    did before).
    """
    for name in sorted(names):
        path = destination / name
        if path.is_symlink():
            raise DetectionError(
                f"{path} is a symbolic link; refusing to write through a link that may leave {destination}"
            )
        if not path.exists():
            continue
        if not path.is_file():
            raise DetectionError(
                f"{path} already exists and is not a regular file; refusing to write over it"
            )
        if not _is_detection_artefact(path):
            raise DetectionError(
                f"{path} already exists and is not an m2 detection artefact; "
                "refusing to overwrite a file this run did not write"
            )


def _sweep_own_staging_leftovers(destination: Path) -> tuple[Path, ...]:
    """Remove this package's staging leftovers from ``destination`` before a run writes.

    ``_write_all`` removes its temporaries when a write raises, but a process killed mid-run (or a
    power loss) leaves ``.<name>.json.tmp`` behind, and ``_remove_stale_runs`` never reaps them
    because it scans ``*.json``. Only a regular file matching :data:`STAGING_GLOB` is removed —
    including one from a killed run whose scenario the corpus no longer holds. A directory or a
    symbolic link at such a name, and every other file, is left exactly as it is.
    """
    removed: list[Path] = []
    for path in sorted(destination.glob(STAGING_GLOB)):
        if path.is_symlink() or not path.is_file():
            continue
        path.unlink()
        removed.append(path)
    return tuple(removed)


def _write_all(payloads: Sequence[tuple[Path, str]]) -> None:
    """Write every payload through a dotted ``.tmp`` sibling, then rename all of them into place.

    Nothing is renamed until every document has been written, so an I/O failure part way through
    leaves the previous run's files exactly as they were instead of mixing two runs in one
    directory. The temporaries are removed on failure. A ``.`` prefix and a ``.tmp`` suffix keep
    them out of both ``_remove_stale_runs``'s ``*.json`` scan and a consumer's own glob.
    """
    staged: list[tuple[Path, Path]] = []
    try:
        for target, payload in payloads:
            temporary = target.with_name(f".{target.name}.tmp")
            _write_text(temporary, payload)
            staged.append((temporary, target))
        for temporary, target in staged:
            os.replace(temporary, target)
    except BaseException:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
        raise


def _remove_stale_runs(destination: Path, written: set[str]) -> tuple[Path, ...]:
    """Delete the M2 detection artefacts in ``destination`` that this run did not write.

    Only a file that both carries an M2 detection name and parses as an M2 detection document is
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
