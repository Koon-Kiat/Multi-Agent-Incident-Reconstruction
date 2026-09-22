"""Detection artefacts: one detection, one run, and the run summary.

Contract
--------

* :class:`Detection` is a **finding**, not a conclusion: it names the rule that fired, the exact
  ``evidence_id`` values that triggered it, the closed span those triggers occupy and a short
  rationale. It never names a verdict, a severity or a score — those belong to M6 and to the
  metrics phase.
* ``detection_id`` is deterministic: ``<scenario>-<rule_id>-<closing trigger id>``, the trigger
  that **ends** the detection's canonical ``(timestamp_ticks, evidence_id)`` order. Every rule
  partitions its trigger events except R-AUTH-01, which task_plan.md T3.2 anchors on each
  successful logon and which therefore emits one detection per success: two close successes can
  confirm the same failures and share a first trigger. The closing trigger is unique to a
  detection (the success for R-AUTH-01, the last event of a burst for the windowed rules), so
  the ID stays unique; the engine re-checks uniqueness of the whole run before writing.
* ``window_start_utc``/``window_end_utc`` are the **closed** span ``[start, end]`` that contains
  every trigger, taken from the earliest and latest trigger tick. Both ends are inclusive: this
  is a description of the evidence behind the detection, not a query bound. A consumer that
  wants the events of a detection must query ``[window_start_utc, window_end_utc + 1 tick)``,
  because the query API is ``[start, end)`` (AGENTS.md I3). A single-event detection has
  ``window_start_utc == window_end_utc``.
* Timestamps are canonical ``YYYY-MM-DDTHH:MM:SS.fffffffZ`` strings (I2), so a detection keeps
  the full 100 ns precision of the event that caused it.
* ``attack_technique`` carries the rule's **primary** ATT&CK technique, or ``None`` when the
  rule maps to no single technique. A rule that covers several techniques names the primary
  here and lists the rest in ``rationale``.
* Everything is frozen, strict and extra-forbid, and serialisation is sorted-key JSON with
  non-ASCII preserved and no run timestamp, so two runs over one corpus are byte-identical.
* ``severity`` is the rule's own coarse signal strength (``low``/``medium``/``high``), fixed in
  the rule definition before any real run. It is **not** a verdict, a score or a probability;
  it exists so a consumer can order or filter detections without re-deriving intent from prose.
  A single detection may override its rule's default (R-EXEC-01 emits low single hits and a
  medium burst).

``DetectionRun`` is one scenario's run: it records the rules *and their parameters* that
produced the detections, together with the sha256 of the corpus manifest they were computed
from, so a stored run can be traced to the exact corpus revision it describes. The scenario is
part of the run record as well as the file name, so a zero-detection file still says which
scenario it describes.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from m2.ids import SCENARIO_ID_RE, parse_evidence_id
from m2.schema import SHA256_PATTERN
from m2.timeutil import iso_to_ticks, ticks_to_iso

DETECTION_RUN_SCHEMA_VERSION = "m2-detect-v1"

ATTACK_TECHNIQUE_PATTERN = r"^T[0-9]{4}(\.[0-9]{3})?$"

Severity = Literal["low", "medium", "high"]


class RuleRecord(BaseModel):
    """One rule's identity and thresholds, recorded with the run that used them.

    ``params`` holds the values the rule was *run* with, so a stored detection can be
    reproduced without reading the current source. Keys are sorted at serialisation time and
    never carry a "now" value.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    rule_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    params: dict[str, int | str] = Field(default_factory=dict)


class Detection(BaseModel):
    """One rule firing, with the events that triggered it and why."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    detection_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    scenario_id: str = Field(pattern=SCENARIO_ID_RE.pattern)
    trigger_evidence_ids: tuple[str, ...] = Field(min_length=1)
    window_start_utc: str
    window_end_utc: str
    attack_technique: str | None = Field(default=None, pattern=ATTACK_TECHNIQUE_PATTERN)
    severity: Severity
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def triggers_are_unique_and_scoped(self) -> Detection:
        if len(set(self.trigger_evidence_ids)) != len(self.trigger_evidence_ids):
            raise ValueError("trigger_evidence_ids must not repeat an evidence_id")
        for evidence_id in self.trigger_evidence_ids:
            reference = parse_evidence_id(evidence_id)
            if reference.scenario_id != self.scenario_id:
                raise ValueError(f"trigger {evidence_id!r} belongs to scenario {reference.scenario_id!r}")
        return self

    @model_validator(mode="after")
    def detection_id_is_derived(self) -> Detection:
        expected = make_detection_id(self.scenario_id, self.rule_id, self.trigger_evidence_ids[-1])
        if self.detection_id != expected:
            raise ValueError(f"detection_id {self.detection_id!r} must equal {expected!r}")
        return self

    @model_validator(mode="after")
    def window_is_canonical_and_ordered(self) -> Detection:
        start = _canonical_ticks(self.window_start_utc, "window_start_utc")
        end = _canonical_ticks(self.window_end_utc, "window_end_utc")
        if start > end:
            raise ValueError(
                f"window_start_utc {self.window_start_utc!r} must not be after window_end_utc {self.window_end_utc!r}"
            )
        return self


class DetectionRun(BaseModel):
    """One scenario's detection run over one verified corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: str = DETECTION_RUN_SCHEMA_VERSION
    scenario_id: str = Field(pattern=SCENARIO_ID_RE.pattern)
    corpus_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    rules: tuple[RuleRecord, ...]
    detections: tuple[Detection, ...]

    @model_validator(mode="after")
    def identities_are_unique(self) -> DetectionRun:
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("rules must not repeat a rule_id")
        detection_ids = [detection.detection_id for detection in self.detections]
        if len(set(detection_ids)) != len(detection_ids):
            raise ValueError("detections must not repeat a detection_id")
        for detection in self.detections:
            if detection.scenario_id != self.scenario_id:
                raise ValueError(f"detection {detection.detection_id!r} belongs to another scenario")
        return self


class ScenarioSummary(BaseModel):
    """How many detections one scenario produced, in total and per rule."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    scenario_id: str = Field(pattern=SCENARIO_ID_RE.pattern)
    total: int = Field(ge=0)
    counts_by_rule: dict[str, int]

    @model_validator(mode="after")
    def counts_are_consistent(self) -> ScenarioSummary:
        if any(count < 0 for count in self.counts_by_rule.values()):
            raise ValueError("counts_by_rule must not hold a negative count")
        if sum(self.counts_by_rule.values()) != self.total:
            raise ValueError("counts_by_rule must add up to total")
        return self


class DetectionSummary(BaseModel):
    """``summary.json``: per-scenario, per-rule detection counts for one corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: str = DETECTION_RUN_SCHEMA_VERSION
    corpus_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    scenarios: tuple[ScenarioSummary, ...]

    @model_validator(mode="after")
    def scenarios_are_unique(self) -> DetectionSummary:
        scenario_ids = [scenario.scenario_id for scenario in self.scenarios]
        if len(set(scenario_ids)) != len(scenario_ids):
            raise ValueError("scenarios must not repeat a scenario_id")
        return self


def make_detection_id(scenario_id: str, rule_id: str, closing_trigger_evidence_id: str) -> str:
    """The one deterministic ID for a detection of ``rule_id`` in ``scenario_id``.

    ``closing_trigger_evidence_id`` is the detection's last trigger in
    ``(timestamp_ticks, evidence_id)`` order. Naming the **first** trigger would not identify a
    detection uniquely: R-AUTH-01 emits one detection per successful logon, and two successes
    inside one 300 s span confirm the same failures (task_plan.md T3.2 allows those overlapping
    detections), so both would be named after the same first failure. The closing trigger is the
    event that settles the detection — the success for R-AUTH-01, the last event of a burst for
    the windowed rules — and is unique to it.
    """
    return f"{scenario_id}-{rule_id}-{closing_trigger_evidence_id}"


def detection_to_json(detection: Detection) -> str:
    """One detection as a single sorted-key JSON line."""
    return json.dumps(detection.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)


def run_to_json(run: DetectionRun) -> str:
    """One run as a sorted-key JSON document; no trailing newline, no run timestamp."""
    return _document(run)


def summary_to_json(summary: DetectionSummary) -> str:
    """One summary as a sorted-key JSON document; no trailing newline, no run timestamp."""
    return _document(summary)


def _document(model: BaseModel) -> str:
    return json.dumps(model.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, indent=2)


def _canonical_ticks(value: str, field: str) -> int:
    """Parse a canonical detection timestamp, failing closed on anything else."""
    try:
        ticks = iso_to_ticks(value)
    except ValueError as error:
        raise ValueError(f"{field} is not a UTC ISO 8601 timestamp: {error}") from error
    if ticks_to_iso(ticks) != value:
        raise ValueError(f"{field} {value!r} must be the canonical {ticks_to_iso(ticks)!r}")
    return ticks
