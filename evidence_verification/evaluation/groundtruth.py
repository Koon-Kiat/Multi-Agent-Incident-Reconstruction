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
            scenario = row["scenario_id"].strip()
            label = row["expected_label"].strip().casefold()
            if label not in LABELS:
                raise GroundTruthError(f"{path.name}: stage {row['stage_id']} has label {label!r}")
            evidence = tuple(
                [f"{scenario}-SEC-{n}" for n in _ids(row["security_record_ids"])]
                + [f"{scenario}-SYS-{n}" for n in _ids(row["sysmon_record_ids"])])
            if not evidence:
                raise GroundTruthError(f"{path.name}: stage {row['stage_id']} cites no records")
            techniques = tuple(t.strip() for t in (row.get("mitre_technique") or "").replace(",", ";").split(";")
                               if t.strip())
            stages.append(Stage(scenario, row["stage_id"].strip(), int(row["stage_order"]), label,
                                row["time_utc"].strip(), evidence, techniques))
    if not stages:
        raise GroundTruthError(f"{path.name} holds no stages")
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
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if document.get("schema_version") != EXCLUSIONS_SCHEMA:
        raise GroundTruthError(f"{EXCLUSIONS_FILE} must declare schema_version {EXCLUSIONS_SCHEMA!r}")
    return {scenario: frozenset(ids) for scenario, ids in document.get("neutral_evidence_ids", {}).items()}
