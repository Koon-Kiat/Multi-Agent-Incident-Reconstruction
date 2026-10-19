import json

import pytest

from authentication_agent.config import Limits
from authentication_agent.errors import InvestigationError
from authentication_agent.llm.fake import FakeLLM as AuthenticationFake
from endpoint_agent.llm.fake import FakeLLM as EndpointFake
from event_processing.query import EventStore
from incident_reconstruction import IncidentOrchestrator
from incident_reconstruction.orchestrator import corpus_investigators
from incident_reconstruction.attack import status_for
from incident_reconstruction.claims import Claim, ClaimEntities, ClaimLink, Reconstruction
from incident_reconstruction.narrative import FakeReconstructionLLM, parse_reply, reply_schema
from incident_reconstruction.reconstruction import reconstruct
from incident_reconstruction.stages import account_key, build_stages

from .conftest import CHILD, ROOT, SCENARIO, StubEngine, detection, security, sysmon


class ScriptedLLM:
    def __init__(self, reply):
        self.reply, self.calls = reply, 0

    def metadata(self):
        return {"runtime": "scripted"}

    def complete(self, messages, schema, limits):
        self.calls += 1
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply(json.loads(messages[-1]["content"])) if callable(self.reply) else self.reply


@pytest.fixture
def run(store, engine, investigators):
    return IncidentOrchestrator(store, engine, investigators).run(SCENARIO)


def reply(facts, **overrides):
    body = {"claim_text": "Observed activity.", "rationale": "Records share a process.",
            "assessment": "requires_review", "cited_evidence_ids": facts["allowed_evidence_ids"][:1],
            "technique_ids": [t["technique_id"] for t in facts["candidate_techniques"]][:1]}
    return json.dumps({**body, **overrides})


def test_stages_follow_time_and_split_interleaved_rules(run, store):
    stages = build_stages(run, store)
    assert [s.rule_id for s in stages] == ["R-AUTH-01", "R-AUTH-03", "R-EXEC-01", "R-FILE-01", "R-EXEC-01"]
    assert [s.claim_id for s in stages] == [f"{SCENARIO}-CLM-0{i}" for i in range(1, 6)]
    assert all(a.first_ticks <= b.first_ticks for a, b in zip(stages, stages[1:]))


def test_consecutive_detections_of_one_rule_form_one_stage(store, events, investigators):
    detections = (detection("R-EXEC-01", events["process_parent"]), detection("R-EXEC-01", events["process_child"]))
    run = IncidentOrchestrator(store, StubEngine(detections), investigators).run(SCENARIO)
    (stage,) = build_stages(run, store)
    assert len(stage.detections) == 2
    assert stage.trigger_ids == (events["process_parent"].evidence_id, events["process_child"].evidence_id)


def test_findings_link_by_trigger_process_and_lineage(run, store, events):
    authentication, explicit, execution, file_write, late = build_stages(run, store)
    # The authentication agent's findings cite the R-AUTH-01 triggers directly.
    assert {f.agent_type for f in authentication.findings} == {"authentication"}
    assert authentication.direct_finding_ids == {f.finding_id for f in authentication.findings}
    # The child's own creation is direct; its parent's creation joins through lineage.
    linked = {f.observed_events.evidence_id for f in execution.findings}
    assert {events["process_child"].evidence_id, events["process_parent"].evidence_id} <= linked
    # The file write is the same process as the executed child, so the stages are linked.
    assert any(link.claim_id == execution.claim_id and "same process" in link.reason for link in file_write.links)
    # The late record reuses the child's process GUID: the same process, fifteen minutes on.
    assert late.findings
    assert {link.claim_id for link in late.links if "same process" in link.reason} == {execution.claim_id,
                                                                                      file_write.claim_id}
    # The explicit-credential logon shares the non-system account with the failed-logon stage.
    assert any(link.claim_id == authentication.claim_id and "analyst" in link.reason for link in explicit.links)


def test_indirect_links_never_repeat_a_finding(run, store):
    stages = build_stages(run, store)
    direct = {fid for stage in stages for fid in stage.direct_finding_ids}
    indirect = [f.finding_id for stage in stages for f in stage.findings if f.finding_id not in stage.direct_finding_ids]
    # A finding citing two stages' triggers supports both; a merely related one joins one stage,
    # and never one that another stage already owns through its triggers.
    assert len(indirect) == len(set(indirect))
    assert not set(indirect) & direct


def test_security_process_creation_joins_the_matching_sysmon_record(investigators):
    image = "C:\\Windows\\System32\\whoami.exe"
    sysmon_creation = sysmon(40, 10, ProcessGuid=CHILD, ProcessId="400", Image=image, User="LAB-A\\analyst",
                             ParentProcessGuid=ROOT, ParentImage="C:\\Windows\\System32\\cmd.exe")
    security_creation = security(41, 10.5, 4688, NewProcessName=image, SubjectUserName="analyst")
    store = EventStore([sysmon_creation, security_creation])
    detections = (detection("R-EXEC-01", security_creation),)
    agents = corpus_investigators(store, authentication_llm=AuthenticationFake(), endpoint_llm=EndpointFake(),
                                  limits=Limits())
    run = IncidentOrchestrator(store, StubEngine(detections), agents).run(SCENARIO)
    (stage,) = build_stages(run, store)
    (finding,) = [f for f in stage.findings if f.finding_id in stage.direct_finding_ids]
    assert finding.observed_events.evidence_id == sysmon_creation.evidence_id


def test_system_identities_never_link_stages():
    assert account_key("NT AUTHORITY\\SYSTEM") is None
    assert account_key("DWM-3") is None and account_key("UMFD-2") is None
    assert account_key("LAB-A$") is None and account_key("-") is None
    assert account_key("LAB-A\\Analyst") == "lab-a\\analyst"


def test_reconstruction_claims_are_scoped_ordered_and_unverified(run, store):
    result = reconstruct(run, store, FakeReconstructionLLM())
    assert [c.position for c in result.claims] == [1, 2, 3, 4, 5]
    assert result.model_calls == 5
    for claim in result.claims:
        assert claim.verification_status == "not_verified"
        assert claim.narrative_source == "model"
        assert set(claim.evidence_ids) <= set(claim.context_evidence_ids)
        assert all(store.lookup(eid).event is not None for eid in claim.context_evidence_ids)
    assert Reconstruction.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("override, reason", [
    ({"cited_evidence_ids": ["SYN-ORCH-SEC-999"]}, "cited_evidence_ids"),
    ({"technique_ids": ["T9999"]}, "technique_ids"),
    ({"assessment": "malicious"}, "assessment"),
    ({"claim_text": "The account was verified as compromised."}, "overclaiming_language"),
    ({"rationale": ""}, "rationale"),
])
def test_invalid_replies_fall_back_to_template_with_the_reason(run, store, override, reason):
    llm = ScriptedLLM(lambda facts: reply(facts, **override))
    result = reconstruct(run, store, llm)
    assert {c.narrative_source for c in result.claims} == {"template"}
    assert all(f"model reply rejected ({reason})" in c.uncertainty[0] for c in result.claims)


def test_non_json_and_failing_models_never_abort_reconstruction(run, store):
    garbled = reconstruct(run, store, ScriptedLLM("not json"))
    assert all("reply_not_json" in c.uncertainty[0] for c in garbled.claims)
    failing = reconstruct(run, store, ScriptedLLM(InvestigationError("model_timeout")))
    assert all("model call failed (model_timeout)" in c.uncertainty[0] for c in failing.claims)
    leaky = reconstruct(run, store, ScriptedLLM(RuntimeError("raw event text")))
    assert "raw event text" not in leaky.model_dump_json()
    none = reconstruct(run, store, None)
    assert none.model_calls == 0 and {c.narrative_source for c in none.claims} == {"template"}


def test_model_text_and_citations_are_kept_when_valid(run, store):
    llm = ScriptedLLM(lambda facts: reply(facts, claim_text=f"Stage {facts['position']} activity.",
                                          assessment="benign_possible"))
    result = reconstruct(run, store, llm)
    assert [c.claim_text for c in result.claims] == [f"Stage {i} activity." for i in range(1, 6)]
    assert {c.assessment for c in result.claims} == {"benign_possible"}
    assert all(len(c.evidence_ids) == 1 for c in result.claims)


def test_attack_status_reflects_strength_selection_and_sufficiency(run, store):
    assert status_for("defining", selected=True, insufficient=False) == "supported"
    assert status_for("indicative", selected=True, insufficient=False) == "tentative"
    assert status_for("defining", selected=False, insufficient=False) == "uncertain"
    assert status_for("defining", selected=True, insufficient=True) == "uncertain"
    result = reconstruct(run, store, ScriptedLLM(lambda facts: reply(facts)))
    authentication = result.claims[0]
    # R-AUTH-01 offers T1110 then T1078; the reply selected only the first.
    assert [(m.technique_id, m.status) for m in authentication.attack] == [("T1110", "tentative"), ("T1078", "uncertain")]
    # Mappings rest on the stage's trigger evidence: the two failures and the success.
    assert all(len(m.evidence_ids) == 3 and set(m.evidence_ids) <= set(authentication.context_evidence_ids)
               for m in authentication.attack)


def test_reply_schema_enumerates_only_stage_evidence_and_candidates(run, store):
    stage = build_stages(run, store)[0]
    schema = reply_schema(stage)
    assert schema["properties"]["cited_evidence_ids"]["items"]["enum"] == list(stage.context_evidence_ids)
    assert schema["properties"]["technique_ids"]["items"]["enum"] == ["T1110", "T1078"]
    with pytest.raises(ValueError):
        parse_reply(stage, json.dumps({"claim_text": "x"}))


def test_claims_reject_out_of_stage_evidence_and_unknown_links():
    base = dict(claim_id="S-CLM-01", position=1, claim_type="t", claim_text="x", rationale="y",
                assessment="requires_review", first_utc="a", last_utc="b", entities=ClaimEntities(),
                context_evidence_ids=("S-SEC-1",), detection_ids=("d",), narrative_source="template")
    with pytest.raises(ValueError, match="own stage"):
        Claim(**base, evidence_ids=("S-SEC-2",))
    claim = Claim(**base, evidence_ids=("S-SEC-1",), related_claims=(ClaimLink(claim_id="S-CLM-09", reason="r"),))
    with pytest.raises(ValueError, match="unknown claim"):
        Reconstruction(prompt_version="p", scenario_id="S", corpus_manifest_sha256="0", orchestration_started_utc="t",
                       llm={}, claims=(claim,), unlinked_findings={}, investigation_gaps=(), model_calls=0,
                       latency_seconds=0)
