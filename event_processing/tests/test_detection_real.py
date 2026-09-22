"""T3.3 (real): the detection engine over the real exports.

The counts in :data:`BASELINE_COUNTS` and the digests in :data:`BASELINE_DIGESTS` are the
phase-3 baseline recorded in ``docs/DETECTION_RULES.md``. They are the outcome of running
thresholds that were fixed before the first real run over a corpus that is pinned by the
phase-1 digests; they are not a target and not something to adjust. The structural assertions
are the real point: every trigger resolves, every window is exactly the span of its triggers,
and two runs are byte-identical.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from event_processing.detection.engine import (
    SUMMARY_FILENAME,
    DetectionEngine,
    corpus_manifest_digest,
    write_detections,
)
from event_processing.detection.rules import RULES
from event_processing.query import EventStore
from event_processing.timeutil import iso_to_ticks, ticks_to_iso

CORPUS_MANIFEST_SHA256 = "34c5d0ac01e5a6028cbc2a6deb39197a179007be549971119f83e6000f9069c7"

BASELINE_COUNTS = {
    "S01": {"R-CRED-01": 2, "R-EXEC-01": 6, "R-LOG-01": 1},
    "S02": {"R-AUTH-01": 1, "R-AUTH-03": 6, "R-EXEC-01": 4, "R-FILE-01": 3, "R-LOG-01": 1},
    "S03": {"R-AUTH-03": 6, "R-EXEC-01": 4, "R-FILE-01": 3, "R-LOG-01": 1},
}

# Re-pinned for the owner-requested descriptive schema identifiers. Comparison
# with the pre-migration run proved only schema_version and the dependent corpus
# manifest hash changed. Counts, triggers and all detection content are unchanged;
# the canonical behavioral digests below pin that independent comparison too.
BASELINE_DIGESTS = {
    "S01.json": "bddcc3184d80a5ce07a27563d2f2a20a47af90830a418fc722d5a1dfc4318161",
    "S02.json": "549afd3e9821a045b8b84cd425d0df592f6efc996bb5e26ee3e79f155f8b654a",
    "S03.json": "dcd730c0e8eea90cf405906e9e2bed9c3c9dcca6586708cc52af7f56e0718028",
    "summary.json": "a16836328abd1136bfb21fa573d221a6227c88c237d8544ab0783a645af8395c",
}

BEHAVIOR_DIGESTS = {'S01.json': 'bd5e6191bbe96e16b47907b83a3fdf4702e47cac6bad1cc722020db5c2d19ba5', 'S02.json': 'ba6ec25d1454b0be00c1d9b33c40ef3cda02f68cc0943b87ff9faa150ab1d72d', 'S03.json': '2a9143f12c629d5ad0150e677a133c3503e6d93a0daed1370bc67965544b013f'}

RULE_VERSIONS = {rule.spec.rule_id: rule.spec.version for rule in RULES}


def test_the_declared_baseline_reproduces_on_the_real_corpus(real_corpus_dir: Path, tmp_path: Path):
    summary = write_detections(real_corpus_dir, tmp_path / "detections")
    assert {scenario.scenario_id: dict(scenario.counts_by_rule) for scenario in summary.scenarios} == BASELINE_COUNTS


def test_the_declared_output_digests_reproduce_on_the_real_corpus(real_corpus_dir: Path, tmp_path: Path):
    assert corpus_manifest_digest(real_corpus_dir) == CORPUS_MANIFEST_SHA256
    out = tmp_path / "detections"
    write_detections(real_corpus_dir, out)
    assert sorted(path.name for path in out.iterdir()) == sorted(BASELINE_DIGESTS)
    for name, expected in BASELINE_DIGESTS.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == expected, name
        if name in BEHAVIOR_DIGESTS:
            content = json.loads((out / name).read_bytes())
            content.pop("schema_version")
            content.pop("corpus_manifest_sha256")
            canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
            assert hashlib.sha256(canonical).hexdigest() == BEHAVIOR_DIGESTS[name], name



def test_two_real_runs_are_byte_identical(real_corpus_dir: Path, tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_detections(real_corpus_dir, first)
    write_detections(real_corpus_dir, second)
    names = sorted(path.name for path in first.iterdir())
    assert names == sorted(path.name for path in second.iterdir())
    assert SUMMARY_FILENAME in names
    for name in names:
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_every_trigger_resolves_and_every_window_is_the_span_of_its_triggers(real_corpus_dir: Path):
    store = EventStore.load(real_corpus_dir)
    engine = DetectionEngine(store, corpus_manifest_sha256=corpus_manifest_digest(real_corpus_dir))
    checked = 0
    for scenario_id in engine.scenario_ids:
        for detection in engine.triggers_for(scenario_id):
            assert detection.scenario_id == scenario_id
            assert detection.rule_version == RULE_VERSIONS[detection.rule_id]
            assert detection.rationale
            ticks = []
            for evidence_id in detection.trigger_evidence_ids:
                found = store.lookup(evidence_id)
                assert found.status == "found", evidence_id
                assert found.event is not None and found.event.scenario_id == scenario_id
                ticks.append(found.event.timestamp_ticks)
            assert detection.window_start_utc == ticks_to_iso(min(ticks))
            assert detection.window_end_utc == ticks_to_iso(max(ticks))
            checked += 1
    assert checked == sum(sum(counts.values()) for counts in BASELINE_COUNTS.values())


def test_the_audit_log_clear_fires_in_every_scenario(real_corpus_dir: Path):
    # A known corpus property from Evidence Verification & Evaluation's interface note: every runbook export logs one 1102.
    store = EventStore.load(real_corpus_dir)
    engine = DetectionEngine(store, corpus_manifest_sha256=corpus_manifest_digest(real_corpus_dir))
    for scenario_id in engine.scenario_ids:
        clears = [detection for detection in engine.triggers_for(scenario_id) if detection.rule_id == "R-LOG-01"]
        assert len(clears) == 1
        found = store.lookup(clears[0].trigger_evidence_ids[0])
        assert found.status == "found" and found.event is not None
        assert (found.event.channel, found.event.source_event_id) == ("Security", 1102)


def test_the_s02_failed_logon_burst_ends_on_the_public_4624_anchor(real_corpus_dir: Path):
    store = EventStore.load(real_corpus_dir)
    engine = DetectionEngine(store, corpus_manifest_sha256=corpus_manifest_digest(real_corpus_dir))
    bursts = [detection for detection in engine.triggers_for("S02") if detection.rule_id == "R-AUTH-01"]
    assert len(bursts) == 1
    detection = bursts[0]
    # The detection is anchored on the 4624 (T3.2), so its id names that success and its last
    # trigger is the public S02-SEC-43584 anchor.
    assert detection.detection_id == "S02-R-AUTH-01-S02-SEC-43584"
    assert detection.trigger_evidence_ids == (
        "S02-SEC-43571",
        "S02-SEC-43573",
        "S02-SEC-43575",
        "S02-SEC-43578",
        "S02-SEC-43580",
        "S02-SEC-43584",
    )
    assert detection.window_end_utc == ticks_to_iso(iso_to_ticks("2026-09-21T02:05:30.0430374Z"))
