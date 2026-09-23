"""T3.3 (real): the detection engine over the real exports.

The counts in :data:`BASELINE_COUNTS` and the digests in :data:`BASELINE_DIGESTS` are the
phase-3 baseline recorded in ``docs/M2_DETECTION_RULES.md``. They are the outcome of running
thresholds that were fixed before the first real run over a corpus that is pinned by the
phase-1 digests; they are not a target and not something to adjust. The structural assertions
are the real point: every trigger resolves, every window is exactly the span of its triggers,
and two runs are byte-identical.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from m2.detection.engine import (
    SUMMARY_FILENAME,
    DetectionEngine,
    corpus_manifest_digest,
    write_detections,
)
from m2.detection.rules import RULES
from m2.query import EventStore
from m2.timeutil import iso_to_ticks, ticks_to_iso

CORPUS_MANIFEST_SHA256 = "ebf5f9df82e51e20e737c418f2059a0c3a4abb59f00347f6f2960a6d4c13e968"

BASELINE_COUNTS = {
    "S01": {"R-CRED-01": 2, "R-EXEC-01": 6, "R-LOG-01": 1},
    "S02": {"R-AUTH-01": 1, "R-AUTH-03": 6, "R-EXEC-01": 4, "R-FILE-01": 3, "R-LOG-01": 1},
    "S03": {"R-AUTH-03": 6, "R-EXEC-01": 4, "R-FILE-01": 3, "R-LOG-01": 1},
}

# The four SHA-256 values in the doc's "Output digests" table, pinned here so a rule change
# cannot leave the doc quoting stale bytes without a test failing. Re-pinned after the phase-5
# F1 fix, which added the `detection-summary` marker to `summary.json` so `detect` can recognise
# its own summary before removing a stale one: the counts and the three scenario files are
# byte-identical, and only `summary.json` moves.
BASELINE_DIGESTS = {
    "S01.json": "30f11dfc273566b2b5b44960e13a511ac067a7a6ae5ec9c9029581d768c2c114",
    "S02.json": "c8a15743010ac43d21ce67142727a4262e80f5ce0b93a714dabb39fc1a01bb85",
    "S03.json": "289e4b1690dce2f494e6e94a356535b88f005d41206d954c42efe405b6879af4",
    "summary.json": "62c5ce9ebd8291b80efb990c8ec07cab88680340879518796347410e752974fa",
}

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
    # A known corpus property from M6's interface note: every runbook export logs one 1102.
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
