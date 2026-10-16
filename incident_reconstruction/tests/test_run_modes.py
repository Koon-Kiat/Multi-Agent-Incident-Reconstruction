import json

import pytest

from authentication_agent.errors import InvestigationError
from incident_reconstruction import IncidentOrchestrator
from incident_reconstruction.claims import Reconstruction
from incident_reconstruction.narrative import FakeReconstructionLLM
from incident_reconstruction.pipeline import Pipeline, PipelineSummary
from incident_reconstruction.single_agent import FakeSingleAgentLLM, SingleAgentInvestigator
from incident_reconstruction.verification import (
    PendingVerifier,
    VerificationDecision,
    VerificationReport,
    load_verifier,
    run_verification,
)

from .conftest import SCENARIO

NULLS = dict.fromkeys(("start_utc", "end_utc", "account", "host", "process_guid", "evidence_id"))


class Scripted:
    """A model that answers each turn from a function of (turn, messages, schema)."""

    def __init__(self, respond):
        self.respond, self.turn, self.schemas = respond, 0, []

    def metadata(self):
        return {"runtime": "scripted"}

    def complete(self, messages, schema, limits):
        self.schemas.append(schema)
        self.turn += 1
        reply = self.respond(self.turn, messages, schema)
        if isinstance(reply, Exception):
            raise reply
        return reply if isinstance(reply, str) else json.dumps(reply)


def finish(*claims):
    return {"action": "finish", "arguments": NULLS, "claims": list(claims)}


def claim(cited, claim_type="observed_activity", **overrides):
    return {"claim_type": claim_type, "claim_text": "Observed.", "rationale": "Cited records.",
            "assessment": "requires_review", "cited_evidence_ids": list(cited), "technique_ids": [], **overrides}


def single(store, engine, llm, **options):
    agent = SingleAgentInvestigator(store, llm, **options)
    return agent.investigate(SCENARIO, engine.triggers_for(SCENARIO), corpus_manifest_sha256="0" * 64)


# --- single-agent baseline -------------------------------------------------------------------

def test_single_agent_baseline_queries_both_sources_and_cites_what_it_retrieved(store, engine):
    result = single(store, engine, FakeSingleAgentLLM())
    assert result.mode == "single-agent" and result.orchestration_started_utc is None
    assert result.model_calls == 4  # two queries, "finish", then the final timeline turn
    assert len(result.claims) == len(engine.triggers_for(SCENARIO))
    assert "tool calls used: 2 of 16" in result.investigation_gaps
    for c in result.claims:
        assert c.detection_ids and c.evidence_ids == c.context_evidence_ids
        assert all(store.lookup(eid).event is not None for eid in c.evidence_ids)
    assert Reconstruction.model_validate_json(result.model_dump_json()) == result


def test_host_orders_claims_by_evidence_time_not_model_order(store, engine, events):
    late, early = events["late_process"].evidence_id, events["fail1"].evidence_id

    def respond(turn, messages, schema):
        if turn == 1:
            return {"action": "query_endpoint", "arguments": NULLS, "claims": []}
        return finish(claim([late], "late"), claim([early], "early"))

    result = single(store, engine, Scripted(respond))
    assert [c.claim_type for c in result.claims] == ["early", "late"]
    assert [c.claim_id for c in result.claims] == [f"{SCENARIO}-CLM-01", f"{SCENARIO}-CLM-02"]


def test_citations_are_limited_to_retrieved_records(store, engine, events):
    unseen = events["process_parent"].evidence_id  # Not a trigger, and never queried.
    trigger = events["fail1"].evidence_id

    def respond(turn, messages, schema):
        enum = schema["properties"]["claims"]["items"]["properties"]["cited_evidence_ids"]["items"]["enum"]
        assert unseen not in enum and trigger in enum
        return finish(claim([unseen]), claim([trigger], technique_ids=["T9999"]), claim([trigger]))

    result = single(store, engine, Scripted(respond))
    assert len(result.claims) == 1
    assert any("claim 1 from the model was dropped (cited_evidence_ids)" in g for g in result.investigation_gaps)
    assert any("claim 2 from the model was dropped (technique_ids)" in g for g in result.investigation_gaps)


def test_queries_outside_the_window_are_refused_to_the_model(store, engine):
    def respond(turn, messages, schema):
        if turn == 1:
            return {"action": "query_endpoint", "claims": [],
                    "arguments": {**NULLS, "start_utc": "2020-01-01T00:00:00Z", "end_utc": "2020-01-01T00:01:00Z"}}
        feedback = json.loads(messages[-1]["content"])
        assert "within" in feedback["error"]
        return finish()

    result = single(store, engine, Scripted(respond))
    assert result.claims == () and "tool calls used: 1 of 16" in result.investigation_gaps


def test_the_budget_forces_a_finish(store, engine):
    def respond(turn, messages, schema):
        if schema["properties"]["action"]["enum"] == ["finish"]:
            return finish()
        return {"action": "query_authentication", "arguments": NULLS, "claims": []}

    llm = Scripted(respond)
    result = single(store, engine, llm, tool_calls=3)
    assert llm.turn == 4 and "tool calls used: 3 of 3" in result.investigation_gaps


def test_model_failures_end_the_baseline_without_repairing_it(store, engine):
    failed = single(store, engine, Scripted(lambda *_: InvestigationError("model_timeout")))
    assert failed.claims == ()
    assert any("model call failed (model_timeout)" in g for g in failed.investigation_gaps)
    garbled = single(store, engine, Scripted(lambda *_: "not json"))
    assert any("not a valid action" in g for g in garbled.investigation_gaps)


# --- verification connection -----------------------------------------------------------------

@pytest.fixture
def reconstruction(store, engine, investigators):
    run = IncidentOrchestrator(store, engine, investigators).run(SCENARIO)
    from incident_reconstruction.reconstruction import reconstruct
    return reconstruct(run, store, FakeReconstructionLLM(), mode="full")


class FixedVerifier:
    def __init__(self, decide):
        self.decide = decide

    def metadata(self):
        return {"verifier": "fixed"}

    def verify(self, reconstruction, store):
        return self.decide(reconstruction)


def make_verifier():
    return FixedVerifier(lambda r: [VerificationDecision(claim_id=c.claim_id, verdict="confirmed", reason="ok")
                                    for c in r.claims])


def test_pending_verifier_never_implies_support(reconstruction, store):
    report = run_verification(PendingVerifier(), reconstruction, store)
    assert {d.verdict for d in report.decisions} == {"unverified"}
    assert [d.claim_id for d in report.decisions] == [c.claim_id for c in reconstruction.claims]
    assert report.integrity_notes == ()


def test_decisions_are_recorded_unchanged_and_gaps_marked(reconstruction, store):
    first, second, *rest = [c.claim_id for c in reconstruction.claims]
    verifier = FixedVerifier(lambda r: [
        VerificationDecision(claim_id=first, verdict="rejected", reason="timestamp conflict", conflicts=("t",)),
        VerificationDecision(claim_id=first, verdict="confirmed", reason="second opinion"),
        VerificationDecision(claim_id="ELSEWHERE-CLM-01", verdict="confirmed", reason="x"),
    ])
    report = run_verification(verifier, reconstruction, store)
    by_id = {d.claim_id: d for d in report.decisions}
    assert (by_id[first].verdict, by_id[first].reason, by_id[first].conflicts) == ("rejected", "timestamp conflict", ("t",))
    assert by_id[second].verdict == "unverified" and by_id[second].reason == "no_decision_returned"
    assert any("duplicate decision" in n for n in report.integrity_notes)
    assert any("unknown claim ELSEWHERE-CLM-01" in n for n in report.integrity_notes)
    # Claims themselves are never marked by verification.
    assert {c.verification_status for c in reconstruction.claims} == {"not_verified"}


@pytest.mark.parametrize("decide", [lambda r: (_ for _ in ()).throw(RuntimeError("secret")), lambda r: ["confirmed"]])
def test_a_failing_verifier_leaves_every_claim_unverified(reconstruction, store, decide):
    report = run_verification(FixedVerifier(decide), reconstruction, store)
    assert {d.verdict for d in report.decisions} == {"unverified"}
    assert report.integrity_notes[0].startswith("verifier_failed:")
    assert "secret" not in report.model_dump_json()


def test_verifiers_load_by_import_path():
    verifier = load_verifier("incident_reconstruction.tests.test_run_modes:make_verifier")
    assert verifier.metadata() == {"verifier": "fixed"}
    with pytest.raises(ValueError, match="package.module:factory"):
        load_verifier("no_colon")


# --- pipeline modes --------------------------------------------------------------------------

@pytest.fixture
def pipeline(store, engine, investigators):
    return Pipeline(store, engine, orchestrator=IncidentOrchestrator(store, engine, investigators),
                    reconstruction_llm=FakeReconstructionLLM(),
                    single_agent=SingleAgentInvestigator(store, FakeSingleAgentLLM()),
                    verifier=make_verifier(), llm_metadata={"runtime": "fake"})


@pytest.mark.parametrize("mode, phases, kinds", [
    ("single-agent", ["detection", "single_agent"], ["reconstruction"]),
    ("multi-agent", ["detection", "investigation", "reconstruction"], ["reconstruction", "orchestration"]),
    ("full", ["detection", "investigation", "reconstruction", "verification"],
     ["reconstruction", "orchestration", "verification"]),
])
def test_each_mode_runs_its_phases_and_writes_its_artifacts(pipeline, tmp_path, mode, phases, kinds):
    output = pipeline.run(mode, SCENARIO)
    summary = output.summary
    assert [p.phase for p in summary.phases] == phases
    assert summary.mode == output.reconstruction.mode == mode
    assert summary.latency_seconds >= sum(p.seconds for p in summary.phases) - 0.01
    assert summary.claims == len(output.reconstruction.claims) and summary.detections == 5
    written = output.write(tmp_path)
    assert sorted(p.name for p in written) == sorted([f"{SCENARIO}.{k}.json" for k in kinds] + [f"{SCENARIO}.pipeline.json"])
    stored = PipelineSummary.model_validate_json((tmp_path / mode / f"{SCENARIO}.pipeline.json").read_text(encoding="utf-8"))
    assert stored.artifacts == tuple(f"{SCENARIO}.{k}.json" for k in kinds)
    if mode == "full":
        assert summary.verdicts == {"confirmed": summary.claims}
        assert VerificationReport.model_validate_json((tmp_path / mode / f"{SCENARIO}.verification.json").read_text(encoding="utf-8"))
    else:
        assert summary.verdicts is None


def test_modes_share_the_same_triggers(pipeline):
    single_run = pipeline.run("single-agent", SCENARIO)
    multi_run = pipeline.run("multi-agent", SCENARIO)
    assert single_run.summary.detections == multi_run.summary.detections == len(multi_run.orchestration.detections)


def test_modes_refuse_missing_components(store, engine):
    bare = Pipeline(store, engine)
    for mode, message in [("single-agent", "SingleAgentInvestigator"), ("multi-agent", "IncidentOrchestrator"),
                          ("bogus", "unknown mode")]:
        with pytest.raises(ValueError, match=message):
            bare.run(mode, SCENARIO)


def test_claims_are_only_offered_in_the_final_turn(store, engine, events):
    trigger = events["fail1"].evidence_id

    def respond(turn, messages, schema):
        claims = schema["properties"]["claims"]
        if schema["properties"]["action"]["enum"] != ["finish"]:
            assert claims["maxItems"] == 0
            return {"action": "finish", "arguments": NULLS, "claims": []}
        assert claims["maxItems"] > 0 and "Investigation is over" in messages[-1]["content"]
        return finish(claim([trigger]))

    llm = Scripted(respond)
    result = single(store, engine, llm)
    assert llm.turn == 2 and len(result.claims) == 1
