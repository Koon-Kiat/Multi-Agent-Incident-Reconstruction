"""Precision, recall and F1 for the detection baseline, against agreed labels.

Contract
--------

* The **unit** is one ``evidence_id``. A detection *flags* exactly the evidence IDs in its
  ``trigger_evidence_ids``; a label names one evidence ID. There is no other unit.
* Labels come from outside Event Processing & Detection Engine: Dataset & Ground Truth Management/Evidence Verification & Evaluation own the answer key and the definitions. This module only
  defines the **input format** and the arithmetic. Event Processing & Detection Engine never locates, requests or invents a label
  file.
* :func:`load_labels` reads a ``.csv`` with a header row or a ``.json`` document, both carrying
  rows of ``{evidence_id, label, reason?}`` where ``label`` is ``positive``, ``negative`` or
  ``excluded``. **Any evidence ID not listed is negative.** A label row that is not a well-formed
  evidence ID, or an ``evidence_id`` listed twice, is rejected — the file fails closed rather than
  scoring something ambiguous.
* ``excluded`` is for events the agreed definitions put outside the scored population (operator
  and scaffolding activity, the runbook's own audit-log clear). Excluded events are tallied
  separately (``flagged_excluded``, ``unflagged_excluded``) and **never** enter precision or
  recall.
* ``flagged`` is the union of every detection's triggers, deduplicated across rules and across
  scenarios: an event two rules both report is one flagged event. Then ``TP = flagged ∩
  positive``, ``FP = flagged − positive − excluded`` (every flagged event that is not a positive
  and not excluded is a false positive, whether it is listed negative or merely absent from the
  label file) and ``FN = positive − flagged``.
* Precision = ``TP / (TP + FP)``, recall = ``TP / (TP + FN)``, F1 = ``2PR / (P + R)``. A metric
  with a zero denominator is reported as ``None``, never as 0. The raw counts and both
  denominators travel with every figure.
* :func:`score` reports **overall**, per **scenario** and per **rule**. An event two rules flagged
  is attributed to each of them, so per-rule TPs do not sum to the overall TP; the overall figure
  is the deduplicated one. Per-rule recall uses the same positive population as the overall one.
* A label set and a run set that cannot describe one population fail closed rather than being
  scored: a label whose scenario has no detection run is rejected, two runs for one scenario are
  rejected, and runs naming different corpus manifests are rejected (:func:`validate_runs`). Give
  ``known_evidence_ids`` (the CLI reads them from the corpus) and a label naming an event the
  corpus does not hold is rejected too, so a typo cannot turn into a silent false negative.
* Everything is frozen, read-only and deterministic: the same inputs produce the same report,
  serialised as sorted-key JSON with ``\\n`` endings and no "now" timestamp. The report is a
  record of arithmetic, not a verdict — it is only as meaningful as the label definitions the
  teams agreed to (see ``docs/DETECTION_METRICS_PROPOSAL.md``).
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from event_processing.detection.engine import SUMMARY_FILENAME
from event_processing.detection.schema import DetectionRun
from event_processing.ids import parse_evidence_id

SCORE_REPORT_SCHEMA_VERSION = "detection-score-v1"
SCORE_REPORT_FILENAME = "score_report.json"
SCORE_UNITS = ("evidence_id",)
LABEL_VALUES = ("positive", "negative", "excluded")
LABEL_COLUMNS = ("evidence_id", "label", "reason")

Label = Literal["positive", "negative", "excluded"]


class ScoreError(ValueError):
    """A label file, a detection directory or a score request cannot be used as given."""


class LabelRow(BaseModel):
    """One labelled evidence ID: the external input to :func:`score`."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    evidence_id: str = Field(min_length=1)
    label: Label
    reason: str | None = None

    @model_validator(mode="after")
    def evidence_id_is_well_formed(self) -> LabelRow:
        try:
            parse_evidence_id(self.evidence_id)
        except ValueError as error:
            raise ValueError(f"label evidence_id {self.evidence_id!r} is not a well-formed evidence ID") from error
        return self


class ScoreCounts(BaseModel):
    """One scope's counts and metrics, with the denominators they were derived from.

    ``positives``, ``negatives`` and ``excluded`` count the *explicit* label rows. An event a
    detection flagged that the label file does not list is a false positive by definition, so
    ``fp`` can exceed ``negatives``; ``positives == tp + fn`` and
    ``flagged == tp + fp + flagged_excluded`` always hold.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    flagged: int = Field(ge=0)
    positives: int = Field(ge=0)
    negatives: int = Field(ge=0)
    excluded: int = Field(ge=0)
    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)
    flagged_excluded: int = Field(ge=0)
    unflagged_excluded: int = Field(ge=0)
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    precision_denominator: int = Field(ge=0)
    recall_denominator: int = Field(ge=0)

    @model_validator(mode="after")
    def counts_and_metrics_are_consistent(self) -> ScoreCounts:
        if self.flagged != self.tp + self.fp + self.flagged_excluded:
            raise ValueError("flagged must equal tp + fp + flagged_excluded")
        if self.positives != self.tp + self.fn:
            raise ValueError("positives must equal tp + fn")
        if self.excluded != self.flagged_excluded + self.unflagged_excluded:
            raise ValueError("excluded must equal flagged_excluded + unflagged_excluded")
        if self.precision_denominator != self.tp + self.fp:
            raise ValueError("precision_denominator must equal tp + fp")
        if self.recall_denominator != self.tp + self.fn:
            raise ValueError("recall_denominator must equal tp + fn")
        if (self.precision is None) != (self.precision_denominator == 0):
            raise ValueError("precision must be None exactly when its denominator is zero")
        if (self.recall is None) != (self.recall_denominator == 0):
            raise ValueError("recall must be None exactly when its denominator is zero")
        if self.precision is None or self.recall is None or self.precision + self.recall == 0:
            if self.f1 is not None:
                raise ValueError("f1 must be None when a metric is undefined or P + R is zero")
        else:
            expected = 2 * self.precision * self.recall / (self.precision + self.recall)
            if self.f1 is None or abs(self.f1 - expected) > 1e-12:
                raise ValueError("f1 must equal 2PR / (P + R)")
        return self


class ScenarioScore(BaseModel):
    """One scenario's counts and metrics."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    scenario_id: str = Field(min_length=1)
    counts: ScoreCounts


class RuleScore(BaseModel):
    """One rule's counts and metrics, attributed by the detections that rule emitted."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    rule_id: str = Field(min_length=1)
    counts: ScoreCounts


class ScoreReport(BaseModel):
    """``score_report.json``: overall, per-scenario and per-rule metrics for one labelled run."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: str = SCORE_REPORT_SCHEMA_VERSION
    unit: str
    overall: ScoreCounts
    scenarios: tuple[ScenarioScore, ...]
    rules: tuple[RuleScore, ...]

    @model_validator(mode="after")
    def identities_are_unique(self) -> ScoreReport:
        if self.unit not in SCORE_UNITS:
            raise ValueError(f"unit {self.unit!r} is not one of {SCORE_UNITS}")
        for field_name, identities in (
            ("scenarios", [scenario.scenario_id for scenario in self.scenarios]),
            ("rules", [rule.rule_id for rule in self.rules]),
        ):
            if len(set(identities)) != len(identities):
                raise ValueError(f"{field_name} must not repeat an id")
        return self


def score(
    detection_runs: Sequence[DetectionRun],
    labels: Sequence[LabelRow],
    *,
    unit: str = "evidence_id",
    known_evidence_ids: Collection[str] | None = None,
) -> ScoreReport:
    """Score detection runs against labels, overall, per scenario and per rule.

    ``known_evidence_ids`` is optional here but never omitted by the CLI: pass the evidence IDs of
    the corpus being scored and a label naming an event the corpus does not hold raises
    :class:`ScoreError` instead of becoming a silent false negative. A caller that has only the
    label file omits it, and the well-formedness, duplicate, run-set and scenario checks still
    apply — a label naming a scenario with no detection run is always rejected, because there is
    no way to score it honestly.
    """
    if unit not in SCORE_UNITS:
        raise ScoreError(f"unit {unit!r} is not supported; the only unit is 'evidence_id'")
    runs = validate_runs(detection_runs)
    rows = validate_labels(labels, known_evidence_ids=known_evidence_ids)

    by_scenario_positives, by_scenario_negatives, by_scenario_excluded = _label_sets_by_scenario(rows)
    positives = _ids_of(rows, "positive")
    negatives = _ids_of(rows, "negative")
    excluded = _ids_of(rows, "excluded")

    flagged_overall = _flagged_by_rule(runs)
    flagged_scenarios = _flagged_by_scenario(runs)
    unrun = sorted(
        (set(by_scenario_positives) | set(by_scenario_negatives) | set(by_scenario_excluded))
        - set(flagged_scenarios)
    )
    if unrun:
        raise ScoreError(
            f"label scenario {unrun[0]!r} has no detection run in the scored set; refusing to count "
            "its labels silently"
        )
    scenario_ids = sorted(
        set(flagged_scenarios)
        | set(by_scenario_positives)
        | set(by_scenario_negatives)
        | set(by_scenario_excluded)
    )

    overall = _counts(
        flagged=frozenset(
            evidence_id for ids in flagged_scenarios.values() for evidence_id in ids
        ),
        positives=positives,
        negatives=negatives,
        excluded=excluded,
    )
    scenarios = tuple(
        ScenarioScore(
            scenario_id=scenario_id,
            counts=_counts(
                flagged=flagged_scenarios.get(scenario_id, frozenset()),
                positives=by_scenario_positives.get(scenario_id, frozenset()),
                negatives=by_scenario_negatives.get(scenario_id, frozenset()),
                excluded=by_scenario_excluded.get(scenario_id, frozenset()),
            ),
        )
        for scenario_id in scenario_ids
    )
    rules = tuple(
        RuleScore(
            rule_id=rule_id,
            counts=_counts(
                flagged=flagged,
                positives=positives,
                negatives=negatives,
                excluded=excluded,
            ),
        )
        for rule_id, flagged in sorted(flagged_overall.items())
    )
    return ScoreReport(unit=unit, overall=overall, scenarios=scenarios, rules=rules)


def validate_runs(detection_runs: Sequence[DetectionRun]) -> tuple[DetectionRun, ...]:
    """Return ``detection_runs`` as a tuple, rejecting a set that is not one scoring population.

    A score describes **one corpus revision** and **one run per scenario**. Two runs for one
    scenario would make the per-scenario counts (only the last run is kept) disagree with the
    per-rule ones (both are unioned), and runs naming different ``corpus_manifest_sha256`` values
    would mix two revisions in one report. Both fail closed instead of being merged, because a
    merge would silently change which events were flagged.
    """
    runs = tuple(detection_runs)
    counts: dict[str, int] = {}
    for run in runs:
        counts[run.scenario_id] = counts.get(run.scenario_id, 0) + 1
    repeated = sorted(scenario_id for scenario_id, count in counts.items() if count > 1)
    if repeated:
        raise ScoreError(
            f"scenario {repeated[0]!r} has more than one detection run; a score describes exactly "
            "one run per scenario"
        )
    digests = sorted({run.corpus_manifest_sha256 for run in runs})
    if len(digests) > 1:
        raise ScoreError(
            f"the detection runs name {len(digests)} different corpus manifests "
            f"({', '.join(digests[:2])}, ...); a score must describe one corpus revision"
        )
    return runs


def validate_labels(
    labels: Sequence[LabelRow], *, known_evidence_ids: Collection[str] | None = None
) -> tuple[LabelRow, ...]:
    """Return ``labels`` as a tuple, rejecting duplicates and (optionally) unknown evidence IDs."""
    rows = tuple(labels)
    seen: set[str] = set()
    for row in rows:
        if row.evidence_id in seen:
            raise ScoreError(f"evidence_id {row.evidence_id!r} is labelled more than once")
        seen.add(row.evidence_id)
    if known_evidence_ids is not None:
        universe = set(known_evidence_ids)
        unknown = sorted(evidence_id for evidence_id in seen if evidence_id not in universe)
        if unknown:
            raise ScoreError(f"label evidence_id {unknown[0]!r} is not in the corpus being scored")
    return rows


def load_labels(
    path: Path | str, *, known_evidence_ids: Collection[str] | None = None
) -> tuple[LabelRow, ...]:
    """Read a label file: a ``.csv`` with header ``evidence_id,label,reason`` or a ``.json`` list.

    Both shapes carry the same rows. The CSV header must name ``evidence_id`` and ``label`` (and
    may name ``reason``); no other column is accepted. The JSON form is either a list of objects or
    an object with a ``labels`` list. Empty rows and a ``""``/absent ``reason`` become
    ``reason=None``; every other deviation is a :class:`ScoreError` naming the row.
    """
    source = Path(path)
    if not source.is_file():
        raise ScoreError(f"label file {source} does not exist")
    if source.suffix.lower() == ".csv":
        rows = _read_csv_labels(source)
    elif source.suffix.lower() == ".json":
        rows = _read_json_labels(source)
    else:
        raise ScoreError(f"label file {source} must be .csv or .json")
    return validate_labels(rows, known_evidence_ids=known_evidence_ids)


def load_detection_runs(directory: Path | str) -> tuple[DetectionRun, ...]:
    """Read every ``<scenario>.json`` run written by ``python -m event_processing detect``, sorted by file name.

    ``summary.json`` is not a run and is skipped. A file that is not a valid ``DetectionRun`` or
    whose name does not match the scenario inside it fails the whole read rather than being
    ignored, because scoring a partial or mislabelled directory silently would understate or
    misattribute the flagged set. A directory holding runs from more than one corpus manifest is
    rejected for the same reason (see :func:`validate_runs`).
    """
    source = Path(directory)
    if not source.is_dir():
        raise ScoreError(f"detections directory {source} does not exist")
    paths = sorted(path for path in source.glob("*.json") if path.name != SUMMARY_FILENAME)
    if not paths:
        raise ScoreError(f"detections directory {source} holds no run files")
    runs = []
    for path in paths:
        try:
            run = DetectionRun.model_validate_json(path.read_text(encoding="utf-8"))
        except ValidationError as error:
            raise ScoreError(f"{path} is not a valid detection run: {error}") from error
        if path.stem != run.scenario_id:
            raise ScoreError(
                f"{path} holds the run for scenario {run.scenario_id!r}; a run file must be named "
                "<scenario_id>.json"
            )
        runs.append(run)
    return validate_runs(runs)


def report_to_json(report: ScoreReport) -> str:
    """One report as a sorted-key JSON document; no trailing newline, no run timestamp."""
    return json.dumps(report.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, indent=2)


def write_report(report: ScoreReport, out_dir: Path | str) -> Path:
    """Write ``<out>/score_report.json`` with ``\\n`` line endings and return its path."""
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / SCORE_REPORT_FILENAME
    path.write_text(f"{report_to_json(report)}\n", encoding="utf-8", newline="\n")
    return path


def _read_csv_labels(path: Path) -> list[LabelRow]:
    text = path.read_text(encoding="utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    header = tuple(reader.fieldnames or ())
    if not set(("evidence_id", "label")).issubset(header):
        raise ScoreError(f"{path} needs an 'evidence_id' and a 'label' column, found {header!r}")
    extra = sorted(set(header) - set(LABEL_COLUMNS))
    if extra:
        raise ScoreError(f"{path} has unsupported column(s) {extra!r}; allowed: {list(LABEL_COLUMNS)}")
    rows: list[LabelRow] = []
    for number, raw in enumerate(reader, start=2):
        if all(not value for value in raw.values()):
            continue
        rows.append(_label_row(path, f"line {number}", raw))
    return rows


def _read_json_labels(path: Path) -> list[LabelRow]:
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ScoreError(f"{path} is not valid JSON: {error}") from error
    if isinstance(document, dict) and set(document) == {"labels"}:
        document = document["labels"]
    if not isinstance(document, list):
        raise ScoreError(f"{path} must hold a list of label rows or an object with a 'labels' list")
    rows: list[LabelRow] = []
    for index, raw in enumerate(document, start=1):
        if not isinstance(raw, dict):
            raise ScoreError(f"{path} row {index} must be an object, not {type(raw).__name__}")
        rows.append(_label_row(path, f"row {index}", raw))
    return rows


def _label_row(path: Path, position: str, raw: dict[str, Any]) -> LabelRow:
    extra = sorted(set(raw) - set(LABEL_COLUMNS))
    if extra:
        raise ScoreError(f"{path} {position} has unsupported field(s) {extra!r}")
    evidence_id = raw.get("evidence_id")
    label = raw.get("label")
    if evidence_id is None or label is None:
        raise ScoreError(f"{path} {position} must carry both 'evidence_id' and 'label'")
    reason = raw.get("reason")
    if reason == "":
        reason = None
    try:
        return LabelRow(evidence_id=evidence_id, label=label, reason=reason)
    except ValidationError as error:
        raise ScoreError(f"{path} {position} is not a valid label row: {error}") from error


def _ids_of(rows: Sequence[LabelRow], label: Label) -> frozenset[str]:
    return frozenset(row.evidence_id for row in rows if row.label == label)


def _label_sets_by_scenario(
    rows: Sequence[LabelRow],
) -> tuple[dict[str, frozenset[str]], dict[str, frozenset[str]], dict[str, frozenset[str]]]:
    by_label: dict[str, dict[str, set[str]]] = {value: {} for value in LABEL_VALUES}
    for row in rows:
        scenario_id = parse_evidence_id(row.evidence_id).scenario_id
        by_label[row.label].setdefault(scenario_id, set()).add(row.evidence_id)
    return (
        {scenario: frozenset(ids) for scenario, ids in by_label["positive"].items()},
        {scenario: frozenset(ids) for scenario, ids in by_label["negative"].items()},
        {scenario: frozenset(ids) for scenario, ids in by_label["excluded"].items()},
    )


def _flagged_by_scenario(
    detection_runs: Sequence[DetectionRun],
) -> dict[str, frozenset[str]]:
    flagged = {
        run.scenario_id: {
            evidence_id for detection in run.detections for evidence_id in detection.trigger_evidence_ids
        }
        for run in detection_runs
    }
    return {scenario_id: frozenset(ids) for scenario_id, ids in flagged.items()}


def _flagged_by_rule(detection_runs: Sequence[DetectionRun]) -> dict[str, frozenset[str]]:
    flagged: dict[str, set[str]] = {}
    for run in detection_runs:
        for detection in run.detections:
            flagged.setdefault(detection.rule_id, set()).update(detection.trigger_evidence_ids)
    return {rule_id: frozenset(ids) for rule_id, ids in flagged.items()}


def _counts(
    *,
    flagged: frozenset[str],
    positives: frozenset[str],
    negatives: frozenset[str],
    excluded: frozenset[str],
) -> ScoreCounts:
    tp = len(flagged & positives)
    fp = len(flagged - positives - excluded)
    fn = len(positives - flagged)
    flagged_excluded = len(flagged & excluded)
    unflagged_excluded = len(excluded - flagged)
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    precision = None if precision_denominator == 0 else tp / precision_denominator
    recall = None if recall_denominator == 0 else tp / recall_denominator
    if precision is None or recall is None or precision + recall == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return ScoreCounts(
        flagged=len(flagged),
        positives=len(positives),
        negatives=len(negatives),
        excluded=len(excluded),
        tp=tp,
        fp=fp,
        fn=fn,
        flagged_excluded=flagged_excluded,
        unflagged_excluded=unflagged_excluded,
        precision=precision,
        recall=recall,
        f1=f1,
        precision_denominator=precision_denominator,
        recall_denominator=recall_denominator,
    )
