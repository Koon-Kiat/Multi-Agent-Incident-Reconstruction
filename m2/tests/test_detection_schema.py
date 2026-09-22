"""T3.1: the detection artefacts.

Everything here is synthetic: no corpus, no EVTX and no rule logic. The point is that a
detection cannot be stored unless it is self-consistent (derived ID, scenario-scoped triggers,
one canonical closed window) and that a run cannot silently hold two identities for one thing.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from m2.detection.schema import (
    DETECTION_RUN_SCHEMA_VERSION,
    Detection,
    DetectionRun,
    DetectionSummary,
    RuleRecord,
    ScenarioSummary,
    detection_to_json,
    make_detection_id,
    run_to_json,
    summary_to_json,
)
from m2.timeutil import iso_to_ticks, ticks_to_iso

SHA = "D396CE599723189331D440EDD55CC055C28EB4B6AD45A421D07A8E83A2F0EBA7"
BASE = iso_to_ticks("2026-09-21T02:05:30.0430374Z")
START = ticks_to_iso(BASE)
END = ticks_to_iso(BASE + 10)


def detection(**overrides) -> Detection:
    fields = {
        # The ID names the closing trigger (the last of the pair), not the first: see
        # m2/detection/schema.py — R-AUTH-01's overlapping detections share their first trigger.
        "detection_id": make_detection_id("SYN-B", "R-AUTH-01", "SYN-B-SEC-2"),
        "rule_id": "R-AUTH-01",
        "rule_version": "1",
        "scenario_id": "SYN-B",
        "trigger_evidence_ids": ("SYN-B-SEC-1", "SYN-B-SEC-2"),
        "window_start_utc": START,
        "window_end_utc": END,
        "attack_technique": "T1110",
        "severity": "high",
        "rationale": "three failed logons followed by a success for the same account",
    }
    fields.update(overrides)
    return Detection(**fields)


def run(**overrides) -> DetectionRun:
    fields = {
        "scenario_id": "SYN-B",
        "corpus_manifest_sha256": SHA,
        "rules": (RuleRecord(rule_id="R-AUTH-01", version="1", params={"min_failures": 3, "window_seconds": 300}),),
        "detections": (detection(),),
    }
    fields.update(overrides)
    return DetectionRun(**fields)


def test_a_valid_detection_round_trips_through_its_wire_format():
    original = detection()
    assert Detection.model_validate_json(detection_to_json(original)) == original
    assert original.detection_id == "SYN-B-R-AUTH-01-SYN-B-SEC-2"
    assert original.attack_technique == "T1110"


def test_a_single_event_detection_has_a_zero_width_window():
    single = detection(
        detection_id=make_detection_id("SYN-B", "R-AUTH-03", "SYN-B-SEC-9"),
        rule_id="R-AUTH-03",
        trigger_evidence_ids=("SYN-B-SEC-9",),
        window_start_utc=END,
        window_end_utc=END,
    )
    assert single.window_start_utc == single.window_end_utc


def test_a_detection_id_that_is_not_derived_is_rejected():
    with pytest.raises(ValidationError, match="must equal"):
        detection(detection_id="whatever")


def test_a_detection_id_must_name_the_closing_trigger_not_the_first_one():
    # The change-control record for the T3.2 failed-logon semantics: with overlapping R-AUTH-01
    # detections the first trigger is shared, so an ID built from it is no longer the detection's.
    with pytest.raises(ValidationError, match="must equal"):
        detection(detection_id=make_detection_id("SYN-B", "R-AUTH-01", "SYN-B-SEC-1"))


def test_a_detection_needs_at_least_one_trigger():
    with pytest.raises(ValidationError):
        detection(trigger_evidence_ids=())


def test_trigger_ids_must_be_unique_well_formed_and_in_this_scenario():
    with pytest.raises(ValidationError, match="must not repeat"):
        detection(trigger_evidence_ids=("SYN-B-SEC-1", "SYN-B-SEC-1"))
    with pytest.raises(ValidationError, match="malformed evidence_id"):
        detection(trigger_evidence_ids=("nope",))
    with pytest.raises(ValidationError, match="belongs to scenario"):
        detection(trigger_evidence_ids=("SYN-C-SEC-1",))


def test_a_detection_window_must_be_canonical_and_ordered():
    with pytest.raises(ValidationError, match="canonical"):
        detection(window_start_utc="2026-09-21T02:05:30.043037Z")
    with pytest.raises(ValidationError, match="must not be after"):
        detection(window_start_utc=END, window_end_utc=START)
    with pytest.raises(ValidationError, match="not a UTC ISO 8601"):
        detection(window_start_utc="2026-09-21 02:05:30")


def test_an_attack_technique_is_optional_but_never_a_free_string():
    assert detection(attack_technique=None).attack_technique is None
    assert detection(attack_technique="T1070.001").attack_technique == "T1070.001"
    with pytest.raises(ValidationError):
        detection(attack_technique="1110")
    with pytest.raises(ValidationError):
        detection(attack_technique="T1110/T1078")


def test_severity_is_one_of_three_values():
    assert detection(severity="low").severity == "low"
    assert detection(severity="medium").severity == "medium"
    with pytest.raises(ValidationError):
        detection(severity="critical")


def test_a_run_records_the_rules_its_parameters_and_the_corpus_revision():
    stored = run()
    assert stored.schema_version == DETECTION_RUN_SCHEMA_VERSION
    assert stored.rules[0].params == {"min_failures": 3, "window_seconds": 300}
    assert DetectionRun.model_validate_json(run_to_json(stored)) == stored


def test_a_run_rejects_duplicate_identities_and_a_foreign_detection():
    with pytest.raises(ValidationError, match="rule_id"):
        run(
            rules=(
                RuleRecord(rule_id="R-AUTH-01", version="1"),
                RuleRecord(rule_id="R-AUTH-01", version="2"),
            )
        )
    with pytest.raises(ValidationError, match="detection_id"):
        run(detections=(detection(), detection()))
    foreign = detection(
        detection_id=make_detection_id("SYN-C", "R-AUTH-01", "SYN-C-SEC-1"),
        scenario_id="SYN-C",
        trigger_evidence_ids=("SYN-C-SEC-1",),
    )
    with pytest.raises(ValidationError, match="another scenario"):
        run(detections=(foreign,))


def test_a_run_without_detections_is_valid():
    empty = run(detections=())
    assert empty.detections == ()


def test_a_summary_totals_its_per_rule_counts():
    summary = DetectionSummary(
        corpus_manifest_sha256=SHA,
        scenarios=(ScenarioSummary(scenario_id="SYN-B", total=2, counts_by_rule={"R-AUTH-01": 1, "R-EXEC-02": 1}),),
    )
    assert DetectionSummary.model_validate_json(summary_to_json(summary)) == summary


def test_a_summary_whose_counts_do_not_add_up_is_rejected():
    with pytest.raises(ValidationError, match="add up"):
        ScenarioSummary(scenario_id="SYN-B", total=3, counts_by_rule={"R-AUTH-01": 1})
    with pytest.raises(ValidationError, match="negative"):
        ScenarioSummary(scenario_id="SYN-B", total=1, counts_by_rule={"R-AUTH-01": 2, "R-EXEC-02": -1})
    with pytest.raises(ValidationError, match="repeat a scenario_id"):
        DetectionSummary(
            corpus_manifest_sha256=SHA,
            scenarios=(
                ScenarioSummary(scenario_id="SYN-B", total=0, counts_by_rule={}),
                ScenarioSummary(scenario_id="SYN-B", total=0, counts_by_rule={}),
            ),
        )


def test_serialised_documents_have_sorted_keys_and_no_trailing_newline():
    document = run_to_json(run())
    assert not document.endswith("\n")
    assert list(json.loads(document)) == sorted(json.loads(document))
    assert run_to_json(run()) == document


def test_the_schema_version_is_pinned():
    assert DETECTION_RUN_SCHEMA_VERSION == "m2-detect-v1"


def test_a_run_declaring_another_schema_version_is_rejected():
    # B9: the version is a marker detect and score rely on, not free text.
    assert run().schema_version == DETECTION_RUN_SCHEMA_VERSION
    with pytest.raises(ValidationError, match="schema_version"):
        run(schema_version="m2-detect-v2")


def test_a_summary_declaring_another_schema_version_is_rejected():
    fields = {
        "corpus_manifest_sha256": SHA,
        "scenarios": (ScenarioSummary(scenario_id="SYN-B", total=0, counts_by_rule={}),),
    }
    assert DetectionSummary(**fields).schema_version == DETECTION_RUN_SCHEMA_VERSION
    with pytest.raises(ValidationError, match="schema_version"):
        DetectionSummary(schema_version="m2-detect-v2", **fields)
