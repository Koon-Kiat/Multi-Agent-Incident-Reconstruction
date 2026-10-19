"""Loads the private ground-truth tables. This is the only module that reads the answer key.

The key arrives from Dataset & Ground Truth Management as ``<scenario>_ground_truth.csv`` files and
stays outside version control (``ground_truth/private/``). The evaluator reads it only after a run
has been written, never while an investigation is in progress, and never alters it: the key comes from
the lab record, not from anything an AI produced.

A stage cites original Event Record IDs on two channels. A record number is unique only within one
scenario and channel, so every one is turned into a scenario-scoped evidence ID here.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from event_processing.ids import make_evidence_id, parse_evidence_id

REQUIRED_COLUMNS = ("scenario_id", "stage_id", "stage_order", "time_utc", "expected_label",
                    "security_record_ids", "sysmon_record_ids")
EXCLUSIONS_FILE = "scoring_exclusions.json"
EXCLUSIONS_SCHEMA = "scoring-exclusions-v1"
LABELS = ("malicious", "benign")


class GroundTruthError(ValueError):
    pass


@dataclass(frozen=True)
class Stage:
    scenario_id: str
    stage_id: str
    order: int
    label: str
    time_utc: str
    evidence_ids: tuple[str, ...]
    techniques: tuple[str, ...]


def _ids(value: str | None) -> list[int]:
    return [int(part) for part in (value or "").replace(",", ";").split(";") if part.strip()]


def load_stages(path: Path) -> tuple[Stage, ...]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = [name for name in REQUIRED_COLUMNS if name not in (reader.fieldnames or ())]
        if missing:
            raise GroundTruthError(f"{path.name} is missing column(s): {', '.join(missing)}")
        stages = []
        for row in reader:
            if any(row.get(name) is None for name in REQUIRED_COLUMNS):
                raise GroundTruthError(f"{path.name}: incomplete stage row")
            scenario = row["scenario_id"].strip()
            label = row["expected_label"].strip().casefold()
            if label not in LABELS:
                raise GroundTruthError(f"{path.name}: stage {row['stage_id']} has label {label!r}")
            try:
                evidence = tuple(
                    [make_evidence_id(scenario,"Security",n) for n in _ids(row["security_record_ids"])]
                    + [make_evidence_id(scenario,"Microsoft-Windows-Sysmon/Operational",n) for n in _ids(row["sysmon_record_ids"])])
                order = int(row["stage_order"])
            except ValueError as error:
                raise GroundTruthError(f"{path.name}: invalid stage order or evidence ID") from error
            if not evidence:
                raise GroundTruthError(f"{path.name}: stage {row['stage_id']} cites no records")
            techniques = tuple(t.strip() for t in (row.get("mitre_technique") or "").replace(",", ";").split(";")
                               if t.strip())
            if len(set(evidence)) != len(evidence):
                raise GroundTruthError(f"{path.name}: duplicate evidence IDs within a stage")
            stages.append(Stage(scenario, row["stage_id"].strip(), order, label,
                                row["time_utc"].strip(), evidence, techniques))
    if not stages:
        raise GroundTruthError(f"{path.name} holds no stages")
    if len({s.scenario_id for s in stages}) != 1:
        raise GroundTruthError(f"{path.name}: mixed scenarios in one ground-truth file")
    if any(not s.stage_id for s in stages) or len({s.stage_id for s in stages}) != len(stages):
        raise GroundTruthError(f"{path.name}: empty or duplicate stage IDs")
    orders = sorted(stage.order for stage in stages)
    if orders != list(range(1, len(stages) + 1)):
        raise GroundTruthError(f"{path.name}: stage_order is not a contiguous 1..n sequence")
    return tuple(sorted(stages, key=lambda stage: stage.order))


def load_ground_truth(directory: Path | str, scenarios: tuple[str, ...] | None = None) -> dict[str, tuple[Stage, ...]]:
    directory = Path(directory)
    if not directory.is_dir():
        raise GroundTruthError(f"ground-truth directory {directory} does not exist")
    files = sorted(directory.glob("*_ground_truth.csv"))
    if not files:
        raise GroundTruthError(f"no *_ground_truth.csv files in {directory}")
    table = {}
    for path in files:
        stages = load_stages(path)
        if stages[0].scenario_id in table:
            raise GroundTruthError(f"duplicate ground-truth files for {stages[0].scenario_id}")
        table[stages[0].scenario_id] = stages
    if scenarios is not None:
        absent = [s for s in scenarios if s not in table]
        if absent:
            raise GroundTruthError(f"no ground truth for scenario(s): {', '.join(absent)}")
        table = {s: table[s] for s in scenarios}
    return table


def load_neutral_evidence(directory: Path | str) -> dict[str, frozenset[str]]:
    """Records Dataset & Ground Truth Management designated contextual: real activity, deliberately not a
    scored stage. A claim resting only on them is neither matched nor a false positive."""
    path = Path(directory) / EXCLUSIONS_FILE
    if not path.is_file():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError,ValueError) as error:
        raise GroundTruthError(f"invalid {EXCLUSIONS_FILE}") from error
    if not isinstance(document,dict) or document.get("schema_version") != EXCLUSIONS_SCHEMA:
        raise GroundTruthError(f"{EXCLUSIONS_FILE} must declare schema_version {EXCLUSIONS_SCHEMA!r}")
    mapping = document.get("neutral_evidence_ids")
    if not isinstance(mapping,dict):
        raise GroundTruthError("neutral_evidence_ids must be a scenario-to-ID-list mapping")
    for scenario,ids in mapping.items():
        if not isinstance(ids,list) or any(not isinstance(i,str) for i in ids):
            raise GroundTruthError("neutral evidence IDs must be lists of strings")
        try:
            valid = all(parse_evidence_id(i).scenario_id == scenario for i in ids)
        except ValueError as error:
            raise GroundTruthError("invalid neutral evidence ID") from error
        if not valid or len(set(ids)) != len(ids):
            raise GroundTruthError("neutral evidence IDs must be unique and belong to their scenario")
    return {scenario: frozenset(ids) for scenario, ids in mapping.items()}
