"""Synthetic artifact fixtures exercise the final-comparison gate, not model accuracy."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from event_processing.corpus import SourceDigest,ScenarioCorpus,write_jsonl,write_manifest
from event_processing.detection.engine import corpus_manifest_digest,write_detections
from event_processing.provenance import implementation_digest,json_digest
from event_processing.query import EventStore
from evidence_verification.evaluation.runner import evaluate,EvaluationError
from evidence_verification.evaluation.independent import REVIEW_SCHEMA,CONTRACT_SCHEMA,key_digests
from evidence_verification.evaluation.prepare_review import prepare
from evidence_verification.tests.conftest import security,make_claim,make_reconstruction,SCENARIO,iso
from evidence_verification.verifier import assess
from incident_reconstruction.models import OrchestrationRun
from incident_reconstruction.pipeline import PipelineSummary,PipelineOutput
from incident_reconstruction.verification import VerificationReport


def metadata():
    return {"runtime":"ollama","version":"synthetic-unit-fixture","model":"fixture-model","digest":"a"*64,
        "configuration":{"model":"fixture-model","num_ctx":8192,"temperature":0.0,"seed":0,"think":False}}


@pytest.fixture
def experiment(tmp_path):
    corpus=tmp_path/"corpus";corpus.mkdir()
    events=[security(10,0,4625),security(11,1,4625),security(12,2,4624)]
    write_manifest(corpus,[ScenarioCorpus(scenario_id=SCENARIO,
        files=(SourceDigest(filename="Security.evtx",channel="Security",sha256=events[0].source_sha256,size=0,event_count=3),),
        jsonl=write_jsonl(corpus/f"{SCENARIO}.jsonl",events),counts_by_channel={"Security":3},
        counts_by_event_id={"Security":{"4625":2,"4624":1}})])
    digest=corpus_manifest_digest(corpus);store=EventStore(events)
    key=tmp_path/"key";key.mkdir()
    (key/f"{SCENARIO}_ground_truth.csv").write_text(
        "scenario_id,stage_id,stage_order,time_utc,expected_label,security_record_ids,sysmon_record_ids\n"
        +f"{SCENARIO},stage1,1,{iso(0)},malicious,10;11;12,\n",encoding="utf8")
    detections=tmp_path/"detections";write_detections(corpus,detections)
    runs=tmp_path/"runs";reviews=[]
    for mode in ("single-agent","multi-agent","full"):
        roles={role:metadata() for role in ("authentication","endpoint","reconstruction","single_agent")}
        rec=make_reconstruction(make_claim()).model_copy(update={"mode":mode,"corpus_manifest_sha256":digest,
            "llm":metadata(),"orchestration_started_utc":None if mode=="single-agent" else iso(0)})
        orchestration=None if mode=="single-agent" else OrchestrationRun(scenario_id=SCENARIO,
            corpus_manifest_sha256=digest,started_utc=iso(0),finished_utc=iso(2),latency_seconds=2.0,
            policies={},limits={},llm=roles,detections=(),tasks=(),coverage=())
        verification=None if mode!="full" else VerificationReport(scenario_id=SCENARIO,
            verifier={"mode":"deterministic_and_agent","model":metadata()},
            decisions=tuple(a.decision() for a in assess(rec,store)),latency_seconds=0.0,
            reconstruction_sha256=json_digest(rec.model_dump(mode="json")))
        summary=PipelineSummary(mode=mode,scenario_id=SCENARIO,corpus_manifest_sha256=digest,
            started_utc=iso(0),finished_utc=iso(2),latency_seconds=2.0,phases=(),llm=roles,
            detections=0,claims=1,model_calls=1,implementation_sha256=implementation_digest(),
            detection_sha256=json_digest([]))
        PipelineOutput(summary,rec,orchestration,verification).write(runs)
        reviews.append({"mode":mode,"scenario_id":SCENARIO,"reconstruction_sha256":json_digest(rec.model_dump(mode="json")),
            "claims":[{"claim_id":c.claim_id,"claim_sha256":json_digest(c.model_dump(mode="json")),
                "support":"supported","correct_stage_ids":["stage1"],"notes":"Synthetic unit fixture independently described."} for c in rec.claims]})
    review=tmp_path/"reviews.json";contract=tmp_path/"contract.json"
    common={"corpus_manifest_sha256":digest,"ground_truth_sha256":key_digests(key)}
    review.write_text(json.dumps({"schema_version":REVIEW_SCHEMA,**common,"method":"independent_human_review",
        "independent_of_verifier":True,"reviewer":"synthetic test fixture","runs":reviews}),encoding="utf8")
    contract.write_text(json.dumps({"schema_version":CONTRACT_SCHEMA,**common,"unit":"evidence_id",
        "positive_policy":"malicious-stage-evidence-v1","exclusions":"out-of-window-and-owner-contextual-v1",
        "negative_population_reviewed":True,"f1_convention":"zero-when-precision-and-recall-defined-zero-v2",
        "approved_by":{k:"synthetic unit fixture" for k in ("dataset","detection","evaluation")}}),encoding="utf8")
    return dict(corpus=corpus,runs=runs,ground_truth=key,detections=detections,claim_reviews=review,scoring_contract=contract,
                out=tmp_path/"evaluation",label="SYNTHETIC UNIT TEST ONLY")


def mutate_run(experiment,mode,kind,change,*,seal=False):
    folder=experiment["runs"]/mode
    path=folder/f"{SCENARIO}.{kind}.json"
    doc=json.loads(path.read_text());change(doc);path.write_text(json.dumps(doc),encoding="utf8")
    if seal and kind!="pipeline":
        pipe=folder/f"{SCENARIO}.pipeline.json"
        p=json.loads(pipe.read_text());p["artifact_sha256"][path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        pipe.write_text(json.dumps(p),encoding="utf8")


def test_complete_bound_approved_comparison_is_accepted(experiment):
    result=evaluate(**experiment)
    assert result["scored"] and result["comparison_complete"] and result["semantic_review_complete"]
    assert all(r["semantic_correctness"]["correct_stage_recall"]==1.0 for r in result["runs"])
    with pytest.raises(EvaluationError,match="already exists"):
        evaluate(**experiment)


def test_descriptive_results_round_trip_and_legacy_display_preserve_measurements(experiment):
    import csv
    from evidence_verification.evaluation.legacy import LEGACY_CONFIGURATIONS, LEGACY_RULES_ONLY
    from evidence_verification.evaluation.report import render
    from incident_reconstruction.terminology import EVALUATION_CONFIGURATIONS, EVALUATION_NAMES, RULES_ONLY

    result = evaluate(**experiment)
    assert result["schema_version"] == "evaluation-results-v3"
    saved = json.loads((experiment["out"] / "results.json").read_text(encoding="utf8"))
    assert saved == result
    assert {run["configuration"] for run in saved["runs"]} == set(EVALUATION_CONFIGURATIONS.values())
    with (experiment["out"] / "claims.csv").open(encoding="utf8", newline="") as handle:
        assert {row["configuration"] for row in csv.DictReader(handle)} == set(EVALUATION_CONFIGURATIONS.values())
    markdown = (experiment["out"] / "results.md").read_text(encoding="utf8")
    for label in EVALUATION_NAMES.values():
        assert label in markdown
    assert not any(old in markdown for old in LEGACY_CONFIGURATIONS)

    # Build an old-format synthetic result; display adaptation cannot rescore or
    # change original bytes, measurements, status, or recorded provenance.
    legacy = deepcopy(result)
    reverse = {value: key for key, value in LEGACY_CONFIGURATIONS.items()}
    for run in legacy["runs"]:
        run["configuration"] = reverse[run["configuration"]]
    legacy["totals"] = {reverse[key]: value for key, value in legacy["totals"].items()}
    legacy[LEGACY_RULES_ONLY] = legacy.pop(RULES_ONLY)
    for schema in ("evaluation-results-v1", "evaluation-results-v2"):
        legacy["schema_version"] = schema
        before = json.dumps(legacy, sort_keys=True)
        assert render(legacy) == markdown
        assert json.dumps(legacy, sort_keys=True) == before


def test_evaluation_cli_prints_names_instead_of_serialized_identifiers(experiment, capsys):
    from evidence_verification.evaluation.__main__ import main
    from incident_reconstruction.terminology import EVALUATION_CONFIGURATIONS, EVALUATION_NAMES

    arguments = []
    for key in ("corpus", "runs", "ground_truth", "out", "detections", "claim_reviews", "scoring_contract"):
        arguments.extend(["--" + key.replace("_", "-"), str(experiment[key])])
    assert main(arguments + ["--label", "SYNTHETIC UNIT TEST ONLY"]) == 0
    output = capsys.readouterr().out
    for identifier in EVALUATION_CONFIGURATIONS.values():
        assert EVALUATION_NAMES[identifier] in output
        assert identifier not in output


def test_fake_verifier_is_refused_even_with_real_pipeline_metadata(experiment):
    mutate_run(experiment,"full","verification",lambda d:d["verifier"].update(model={"runtime":"fake"}),seal=True)
    with pytest.raises(EvaluationError,match="fake"):
        evaluate(**experiment)
    result=evaluate(**experiment,allow_fake=True)
    assert result["plumbing_only"] and not result["scored"]


def test_different_models_across_configs_are_refused(experiment):
    def change(d):
        d["llm"]["endpoint"]["model"]="other"
        d["llm"]["endpoint"]["configuration"]["model"]="other"
    mutate_run(experiment,"multi-agent","pipeline",change)
    with pytest.raises(EvaluationError,match="differ"):
        evaluate(**experiment)


@pytest.mark.parametrize("kind,change,match",[
    ("pipeline",lambda d:d.update(mode="full"),"mode"),
    ("pipeline",lambda d:d.update(implementation_sha256="0"*64),"implementation"),
    ("pipeline",lambda d:d.update(detection_sha256="0"*64),"triggers"),
    ("reconstruction",lambda d:d["claims"][0].update(claim_text="Changed content"),"artifact"),
    ("verification",lambda d:d.update(reconstruction_sha256="0"*64),"verification"),
])
def test_stale_or_misidentified_artifacts_are_refused(experiment,kind,change,match):
    mode="full" if kind=="verification" else "single-agent"
    mutate_run(experiment,mode,kind,change,seal=kind=="verification")
    with pytest.raises(EvaluationError,match=match): evaluate(**experiment)


def test_missing_run_is_not_a_successfully_scored_experiment(experiment):
    (experiment["runs"]/"single-agent"/f"{SCENARIO}.reconstruction.json").unlink()
    with pytest.raises(EvaluationError,match="missing configuration"): evaluate(**experiment)
    result=evaluate(**experiment,allow_partial=True)
    assert not result["scored"] and not result["comparison_complete"]


def test_rules_only_baseline_is_required_for_final_comparison(experiment):
    experiment["detections"]=None
    with pytest.raises(EvaluationError,match="Rules-only Detection Baseline"): evaluate(**experiment)


def test_missing_independent_labels_and_unapproved_contract_cannot_be_final(experiment):
    experiment["claim_reviews"]=None;experiment["scoring_contract"]=None
    with pytest.raises(EvaluationError,match="independent claim reviews"): evaluate(**experiment)
    result=evaluate(**experiment,allow_partial=True)
    assert not result["scored"] and not result["semantic_review_complete"]
    assert result["runs"][0]["semantic_correctness"]["correct_stage_recall"] is None


def test_review_templates_contain_no_invented_answers_or_owner_approvals(experiment,tmp_path):
    dest=tmp_path/"forms"
    prepare(experiment["corpus"],experiment["runs"],experiment["ground_truth"],dest)
    review=json.loads((dest/"claim_reviews.json").read_text())
    assert review["reviewer"]=="" and not review["independent_of_verifier"]
    assert all(c["support"] is None for r in review["runs"] for c in r["claims"])
    contract=json.loads((dest/"scoring_contract.json").read_text())
    assert not contract["negative_population_reviewed"] and not any(contract["approved_by"].values())
    experiment["claim_reviews"]=dest/"claim_reviews.json"
    with pytest.raises(EvaluationError,match="independent"): evaluate(**experiment)


def test_independent_incorrect_claim_is_not_credited_as_a_correct_stage(experiment):
    review=json.loads(experiment["claim_reviews"].read_text())
    for row in review["runs"]:
        row["claims"][0].update(support="unsupported",correct_stage_ids=[],notes="Synthetic incorrect interpretation.")
    experiment["claim_reviews"].write_text(json.dumps(review),encoding="utf8")
    result=evaluate(**experiment)
    assert all(r["reconstruction"]["stage_recall"]==1.0 for r in result["runs"])
    assert all(r["semantic_correctness"]["correct_stage_recall"]==0.0 for r in result["runs"])


def test_changing_exclusions_invalidates_existing_independent_approval(experiment):
    (experiment["ground_truth"]/"scoring_exclusions.json").write_text(json.dumps(
        {"schema_version":"scoring-exclusions-v1","neutral_evidence_ids":{}}),encoding="utf8")
    with pytest.raises(EvaluationError,match="stale"):
        evaluate(**experiment)


def test_duplicate_verifier_decisions_are_refused(experiment):
    mutate_run(experiment,"full","verification",lambda d:d["decisions"].append(d["decisions"][0]),seal=True)
    with pytest.raises(EvaluationError,match="verification"):
        evaluate(**experiment)


def test_reverify_preserves_source_and_updates_only_verification_call_totals(experiment,tmp_path,monkeypatch):
    from evidence_verification.evaluation import reverify as R
    pipeline=experiment["runs"]/"full"/f"{SCENARIO}.pipeline.json"
    doc=json.loads(pipeline.read_text())
    doc.update(model_calls=5,verification_model_calls=2,phases=[{"phase":"verification","seconds":0.0}])
    pipeline.write_text(json.dumps(doc),encoding="utf8");before=pipeline.read_bytes()
    class Verifier:
        calls=0
        def metadata(self): return {"runtime":"synthetic-test","agent_model_calls":self.calls}
        def verify(self,rec,store):
            self.calls+=3
            return tuple(a.decision() for a in assess(rec,store))
    monkeypatch.setattr(R,"load_verifier",lambda spec:Verifier())
    dest=tmp_path/"posthoc"
    R.reverify(corpus=experiment["corpus"],source=experiment["runs"],destination=dest,verifier_spec="synthetic:test")
    changed=json.loads((dest/"full"/pipeline.name).read_text())
    assert pipeline.read_bytes()==before
    assert changed["model_calls"]==6 and changed["verification_model_calls"]==3
    assert changed["post_hoc"]


def test_reverify_rejects_a_foreign_corpus_before_creating_output(experiment,tmp_path):
    from evidence_verification.evaluation.reverify import reverify
    mutate_run(experiment,"full","reconstruction",lambda d:d.update(corpus_manifest_sha256="0"*64))
    dest=tmp_path/"foreign"
    with pytest.raises(ValueError,match="different corpus"):
        reverify(corpus=experiment["corpus"],source=experiment["runs"],destination=dest,verifier_spec="unused:test")
    assert not dest.exists()


@pytest.mark.parametrize("support",["supported","unsupported"])
def test_operational_failure_does_not_earn_an_unsupported_claim_catch(experiment,support):
    def incomplete(doc):
        doc["decisions"][0].update(verdict="unverified",conflicts=["verification_incomplete: synthetic transport failure"])
    mutate_run(experiment,"full","verification",incomplete,seal=True)
    reviews=json.loads(experiment["claim_reviews"].read_text())
    full=next(r for r in reviews["runs"] if r["mode"]=="full")
    full["claims"][0].update(support=support,correct_stage_ids=["stage1"] if support=="supported" else [])
    experiment["claim_reviews"].write_text(json.dumps(reviews),encoding="utf8")
    result=evaluate(**experiment)
    audit=next(r for r in result["runs"] if r["configuration"]=="specialist_agent_incident_reconstruction_with_independent_evidence_verification")["semantic_correctness"]["unsupported_claim_detection"]
    assert audit["tp"]==audit["fp"]==audit["tn"]==0
    assert audit["fn"]==(support=="unsupported")
    assert audit["operational_abstentions"][support]==1 and audit["decision_coverage"]==0.0
