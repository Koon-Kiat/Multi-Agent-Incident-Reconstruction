"""Rules-only detection baseline: turns the key into an event-level label file and scores it with the Event Processing &
Detection Engine's scorer.

The Event Processing & Detection Engine owns the scoring arithmetic and its metric definitions are a
DRAFT awaiting a joint agreement (docs/DETECTION_METRICS_PROPOSAL.md). This module only produces the label
file those definitions call for, and calls the engine's own loader and scorer unchanged, so the numbers
are the engine's numbers. Every result is stamped PROVISIONAL until that agreement is recorded.

Two views are produced, as the proposal asks:

``primary``  positive = a record cited by a malicious stage; excluded = records outside the declared
             scenario window (the operator's session, including the runbook's log clear) and records the
             key's owner designated contextual; every other record is negative.
``strict``   the same positives, with nothing excluded: scaffolding that a rule flags counts as a false
             positive.

The label files are the answer key in another format. They are written under the run's output directory
(ignored by version control) and never anywhere an investigation component can read.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from event_processing.detection.engine import corpus_manifest_digest
from event_processing.metrics import load_detection_runs, load_labels, report_to_json, score
from event_processing.query import EventStore

from .groundtruth import Stage


def write_labels(path: Path, stages_by_scenario: dict[str, tuple[Stage, ...]], neutral: dict[str, frozenset[str]],
                 store: EventStore, *, exclude_scaffolding: bool) -> dict[str, int]:
    rows: dict[str, tuple[str, str]] = {}
    for scenario, stages in stages_by_scenario.items():
        if exclude_scaffolding:
            for event in store.scenario_events(scenario):
                if not event.in_scenario_window:
                    rows[event.evidence_id] = ("excluded", "outside the declared scenario window")
            for evidence_id in neutral.get(scenario, ()):
                rows[evidence_id] = ("excluded", "designated contextual by the key's owner")
        for stage in stages:
            for evidence_id in stage.evidence_ids:
                if stage.label == "malicious":
                    rows[evidence_id] = ("positive", "cited by a malicious stage")
                elif evidence_id not in rows:
                    rows[evidence_id] = ("negative", "cited by a benign stage")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("evidence_id", "label", "reason"))
        for evidence_id in sorted(rows):
            writer.writerow((evidence_id, *rows[evidence_id]))
    counts = {"positive": 0, "negative": 0, "excluded": 0}
    for label, _ in rows.values():
        counts[label] += 1
    return counts


def score_detections(corpus: Path, detections: Path, out_dir: Path, stages_by_scenario: dict[str, tuple[Stage, ...]],
                     neutral: dict[str, frozenset[str]], store: EventStore) -> dict:
    digest = corpus_manifest_digest(corpus)
    runs = load_detection_runs(detections)
    result: dict = {"status": "PROVISIONAL - metric definitions are a draft awaiting a joint agreement",
                    "corpus_manifest_sha256": digest}
    for view, exclude in (("primary", True), ("strict", False)):
        path = out_dir / f"labels_{view}.csv"
        label_counts = write_labels(path, stages_by_scenario, neutral, store, exclude_scaffolding=exclude)
        report = score(runs, load_labels(path), known_evidence_ids=store.evidence_ids, corpus_manifest_sha256=digest)
        result[view] = {"label_counts": label_counts, "report": json.loads(report_to_json(report))}
    return result
