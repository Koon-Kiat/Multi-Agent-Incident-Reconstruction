"""The blind component review: neutral packets, attested labels and fixed outcome rules. Synthetic only."""

import json
import random

import pytest

from event_processing.corpus import SourceDigest, ScenarioCorpus, write_jsonl, write_manifest
from event_processing.detection.engine import corpus_manifest_digest
from evidence_verification.evaluation.component_review import (OUTCOMES, assertions, main, prepare, score)
from evidence_verification.evaluation.validation import EvaluationError
from evidence_verification.tests.conftest import SCENARIO, corpus_events, iso, make_claim, make_reconstruction, sec_id

TEMPLATE_TEXT = f"Security audit log cleared (Security 1102) observed from {iso(4)} to {iso(4)}."


@pytest.fixture
def component(tmp_path):
    corpus = tmp_path/"corpus"
    corpus.mkdir()
    events = [e for e in corpus_events() if e.scenario_id == SCENARIO and e.channel == "Security"]
    write_manifest(corpus, [ScenarioCorpus(scenario_id=SCENARIO,
        files=(SourceDigest(filename="Security.evtx", channel="Security", sha256=events[0].source_sha256,
                            size=0, event_count=len(events)),),
        jsonl=write_jsonl(corpus/f"{SCENARIO}.jsonl", events), counts_by_channel={"Security": len(events)},
        counts_by_event_id={"Security": {"1102": 1, "4624": 1, "4625": 2, "4648": 1}})])
    first = make_claim(rationale="ORCHESTRATOR RATIONALE")
    second = make_claim(claim_id=f"{SCENARIO}-CLM-02", position=2, claim_type="audit_log_cleared",
                        claim_text=TEMPLATE_TEXT, first_utc=iso(4), last_utc=iso(4),
                        evidence_ids=(sec_id(14),), context_evidence_ids=(sec_id(14), sec_id(13)))
    rec = make_reconstruction(first, second).model_copy(
        update={"mode": "multi-agent", "corpus_manifest_sha256": corpus_manifest_digest(corpus)})
    runs = tmp_path/"runs"
    (runs/"multi-agent").mkdir(parents=True)
    (runs/"multi-agent"/f"{SCENARIO}.reconstruction.json").write_text(rec.model_dump_json(), encoding="utf8")
    verdicts = tmp_path/"audit.json"
    verdicts.write_text(json.dumps({"real_corpus_component": {"cases": 2,
        "verdicts": {"confirmed": 1, "partially_supported": 1, "unverified": 0, "rejected": 0},
        "lowered_claims": [{"claim_id": f"{SCENARIO}-CLM-02", "verdict": "partially_supported"}]}}), encoding="utf8")
    packet = prepare(corpus, runs, tmp_path/"packet", rng=random.Random(0))
    return dict(corpus=corpus, runs=runs, verdicts=verdicts, packet=packet, out=tmp_path/"result")


def complete(component, support_by_text=None, **overrides):
    path = component["packet"]/"labels.json"
    labels = json.loads(path.read_text())
    labels.update({"reviewer": "Synthetic Reviewer", "review_date": "2026-10-20", "independent_of_verifier": True,
                   "disclosures": "synthetic fixture"})
    for item in labels["claims"]:
        support = (support_by_text or {}).get(item["claim_text"], "supported")
        for part in item["assertions"]:
            part["support"] = "supported" if support == "supported" else "unsupported"
        item.update(support=support, notes="Checked against the cited records.")
    labels.update(overrides)
    path.write_text(json.dumps(labels), encoding="utf8")
    return labels


def run_score(component):
    return score(component["packet"], component["corpus"], component["runs"], component["verdicts"], component["out"])


def test_template_claims_split_into_behaviour_and_time_span():
    assert assertions(TEMPLATE_TEXT) == ["The recorded activity is: Security audit log cleared (Security 1102)",
                                         f"It was observed from {iso(4)} to {iso(4)}"]
    assert assertions("Two failed logons preceded a success.") == ["Two failed logons preceded a success."]


def test_packet_hides_claim_identity_verdicts_and_rationale(component):
    packet = (component["packet"]/"packet.md").read_text()
    assert f"{SCENARIO}-CLM-" not in packet and "ORCHESTRATOR RATIONALE" not in packet
    assert "## R01" in packet and "## R02" in packet and sec_id(14) in packet
    assert "### Context records (1)" in packet  # the context-only record is shown separately
    labels = json.loads((component["packet"]/"labels.json").read_text())
    assert labels["reviewer"] == "" and labels["independent_of_verifier"] is False
    assert all(c["support"] is None and all(a["support"] is None for a in c["assertions"]) for c in labels["claims"])
    assert f"{SCENARIO}-CLM-" not in json.dumps(labels)
    sealed = json.loads((component["packet"]/"sealed"/"mapping.json").read_text())
    assert {c["claim_id"] for c in sealed["claims"].values()} == {f"{SCENARIO}-CLM-01", f"{SCENARIO}-CLM-02"}


def test_prepare_and_score_refuse_existing_output(component, tmp_path):
    with pytest.raises(EvaluationError, match="exists"):
        prepare(component["corpus"], component["runs"], component["packet"])
    complete(component)
    component["out"].mkdir()
    with pytest.raises(EvaluationError, match="exists"):
        run_score(component)


def test_unblinded_outcomes_follow_the_fixed_rules(component):
    complete(component)
    result = run_score(component)
    by_id = {row["claim_id"]: row for row in result["claims"]}
    assert by_id[f"{SCENARIO}-CLM-01"]["outcome"] == "correct"
    assert by_id[f"{SCENARIO}-CLM-02"]["outcome"] == "false_alarm"
    assert result["lowered_claim_review"] == {"lowered": 1, "justified": 0, "false_alarm": 1, "unresolved": 0}
    assert result["not_fully_supported_detection"]["precision"] == 0.0
    assert result["not_fully_supported_detection"]["recall"] is None
    assert json.loads((component["out"]/"result.json").read_text()) == result


def test_a_justified_downgrade_and_a_missed_claim(component):
    complete(component, {TEMPLATE_TEXT: "unsupported", make_claim().claim_text: "partially_supported"})
    result = run_score(component)
    assert result["outcomes"]["justified"] == 1 and result["outcomes"]["missed"] == 1
    assert result["not_fully_supported_detection"]["recall"] == 0.5


@pytest.mark.parametrize("lowered", [True, False])
def test_uncertain_labels_stay_unresolved(lowered):
    assert OUTCOMES[(lowered, "uncertain")] == "unresolved"


@pytest.mark.parametrize("overrides", [
    {"reviewer": " "}, {"review_date": ""}, {"independent_of_verifier": False}, {"method": "model_review"}])
def test_unattested_reviews_are_refused(component, overrides):
    complete(component, **overrides)
    with pytest.raises(EvaluationError, match="named reviewer"):
        run_score(component)


def test_incomplete_or_inconsistent_labels_are_refused(component):
    labels = complete(component)
    labels["claims"][0]["support"] = None
    (component["packet"]/"labels.json").write_text(json.dumps(labels), encoding="utf8")
    with pytest.raises(EvaluationError, match="incomplete label"):
        run_score(component)
    labels = complete(component)
    labels["claims"][0]["assertions"][0]["support"] = "unsupported"
    (component["packet"]/"labels.json").write_text(json.dumps(labels), encoding="utf8")
    with pytest.raises(EvaluationError, match="every assertion"):
        run_score(component)
    labels = complete(component)
    labels["claims"].pop()
    (component["packet"]/"labels.json").write_text(json.dumps(labels), encoding="utf8")
    with pytest.raises(EvaluationError, match="every packet code"):
        run_score(component)


def test_changed_claims_or_packet_are_refused(component):
    complete(component)
    packet = component["packet"]/"packet.md"
    original = packet.read_text()
    packet.write_text(original + "edited\n", encoding="utf8")
    with pytest.raises(EvaluationError, match="belong together"):
        run_score(component)
    packet.write_text(original, encoding="utf8", newline="\n")
    path = component["runs"]/"multi-agent"/f"{SCENARIO}.reconstruction.json"
    doc = json.loads(path.read_text())
    doc["claims"][0]["claim_text"] = "Edited after the packet was prepared."
    path.write_text(json.dumps(doc), encoding="utf8")
    with pytest.raises(EvaluationError, match="claim changed"):
        run_score(component)


def test_a_verdict_file_for_other_claims_is_refused(component):
    complete(component)
    component["verdicts"].write_text(json.dumps({"real_corpus_component": {"cases": 2,
        "verdicts": {"confirmed": 1}, "lowered_claims": [{"claim_id": "S09-CLM-01", "verdict": "unverified"}]}}))
    with pytest.raises(EvaluationError, match="exactly these claims"):
        run_score(component)


def test_cli_prepare_reports_invalid_input(tmp_path, capsys):
    with pytest.raises(SystemExit) as raised:
        main(["prepare", "--corpus", str(tmp_path/"missing"), "--runs", str(tmp_path), "--out", str(tmp_path/"p")])
    assert raised.value.code == 2 and "error:" in capsys.readouterr().err
