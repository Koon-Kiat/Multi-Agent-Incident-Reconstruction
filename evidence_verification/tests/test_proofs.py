import json
import pytest
from evidence_verification import agent as A,proofs as P
from evidence_verification.tests.conftest import make_claim,make_reconstruction,assess_one,sec_id


def valid(view,status="supported"):
    return {"clauses":{cid:{"support":status,"proof_ids":list(view.facts) if status!="unsupported" else [],
                            "reason":"Synthetic contract fixture."} for cid in view.clauses}}


def test_clause_partition_preserves_every_non_whitespace_character():
    text="A process wrote x.ps1, and it then ran. That caused an attack; because a user said so."
    assert "".join(text.split())=="".join("".join(P.clauses(text).values()).split())


def test_numeric_event_list_remains_one_clause_and_causal_additions_are_separate():
    assert len(P.clauses("Events 4625, 4625 and 4624 occurred in that order."))==1
    assert len(P.clauses("A process ran to prepare another action after a user opened an attachment."))==2
    assert len(P.clauses("Sysmon 10 access to lsass.exe with an access mask was observed."))==1
    assert len(P.clauses("A file was created observed from 2026-10-19T06:00:00Z to 2026-10-19T06:00:00Z."))==2


def test_source_computations_use_primary_population_and_exact_source_times(store):
    events=assess_one(make_claim(),store).evidence.context_events()
    summary=P.computations(events,{sec_id(10),sec_id(11),sec_id(12)})
    groups={g["event_id"]:g for g in summary["event_groups"]}
    assert groups[4625]["count"]==2 and groups[4625]["elapsed_seconds"]=="1"
    assert groups[4624]["count"]==1 and groups[4624]["elapsed_seconds"]=="0"
    subset=P.computations(events,{sec_id(10)})["event_groups"]
    assert len(subset)==1 and subset[0]["count"]==1
    from evidence_verification.tests.conftest import security
    precise=P.computations([security(1,0,4625),security(2,0.0000001,4625)],{sec_id(1),sec_id(2)})
    assert precise["event_groups"][0]["elapsed_seconds"]=="0.0000001"


def test_indexed_facts_are_complete_and_exclude_reconstruction_reasoning(store):
    claim=make_claim(rationale="RATIONALE-SENTINEL",uncertainty=("PRIVATE-SENTINEL",),detection_ids=("DETECTION-SENTINEL",))
    view=P.build(assess_one(claim,store),A._record)
    text=json.dumps(view.messages)
    assert all(s not in text for s in ("RATIONALE-SENTINEL","PRIVATE-SENTINEL","DETECTION-SENTINEL"))
    assert {v[0] for v in view.facts.values()}==set(claim.context_evidence_ids)
    assert set(view.schema["properties"]["clauses"]["required"])==set(view.clauses)
    assert P.read(json.dumps(valid(view)),view).outcome=="supported"


@pytest.mark.parametrize("mutation",["omit","unknown","invented_quote","no_proof"])
def test_missing_clauses_and_forged_source_references_fail_closed(store,mutation):
    claim=make_claim(claim_text=make_claim().claim_text+" An attacker stole the password.")
    view=P.build(assess_one(claim,store),A._record);reply=valid(view)
    first=next(iter(reply["clauses"]))
    if mutation=="omit": reply["clauses"].pop(next(reversed(reply["clauses"])))
    if mutation=="unknown": reply["clauses"][first]["proof_ids"]=["F-not-recorded"]
    if mutation=="invented_quote": reply["clauses"][first]["quote"]="analyst invented password theft"
    if mutation=="no_proof": reply["clauses"][first]["proof_ids"]=[]
    with pytest.raises(ValueError): P.read(json.dumps(reply),view)


def test_repeating_a_known_citation_neither_adds_weight_nor_invalidates_the_review(store):
    view=P.build(assess_one(make_claim(),store),A._record)
    reply=valid(view);first=next(iter(reply["clauses"]))
    reply["clauses"][first]["proof_ids"]=["F0","F0"]
    assert P.read(json.dumps(reply),view).outcome=="supported"


def test_unsupported_secondary_clause_cannot_disappear_in_a_valid_reply(store):
    view=P.build(assess_one(make_claim(claim_text=make_claim().claim_text+" An attacker stole the password."),store),A._record)
    reply=valid(view);cid=next(reversed(reply["clauses"]))
    reply["clauses"][cid]={"support":"unsupported","proof_ids":[],"reason":"No password theft is recorded."}
    reading=P.read(json.dumps(reply),view)
    assert reading.outcome=="partially_supported" and "password" in reading.not_shown[0][0]


def test_format_repair_is_bounded_and_not_desired_verdict_feedback(store):
    class Repair:
        calls=0
        def metadata(self): return {"runtime":"synthetic-contract-test"}
        def complete(self,messages,schema,limits):
            self.calls+=1
            payload=json.loads(messages[1]["content"])
            if self.calls==1: return '{"clauses":{}}'
            assert "Do not upgrade unsupported content" in messages[-1]["content"]
            return json.dumps({"clauses":{cid:{"support":"unsupported","proof_ids":[],"reason":"No support selected."}
                for cid in payload["clauses"]}})
    llm=Repair();verifier=A.AgentVerifier(llm)
    decision=verifier.verify(make_reconstruction(make_claim()),store)[0]
    assert decision.verdict=="unverified" and llm.calls==2
    assert verifier.metadata()["agent_format_retries"]==1
    assert verifier.metadata()["agent_failed"]==0


def test_an_invalid_second_reply_is_an_operational_abstention(store):
    class Invalid:
        def metadata(self): return {"runtime":"synthetic-contract-test"}
        def complete(self,*args): return '{"clauses":{}}'
    verifier=A.AgentVerifier(Invalid());decision=verifier.verify(make_reconstruction(make_claim()),store)[0]
    assert decision.verdict=="unverified"
    assert any(c.startswith("verification_incomplete") for c in decision.conflicts)
    assert verifier.metadata()["agent_model_calls"]==2 and verifier.metadata()["agent_failed"]==1


def test_grouped_facts_roundtrip_every_value_without_filling_absent_fields(store):
    assessment=assess_one(make_claim(),store)
    view=P.build(assessment,A._record,compact=True)
    records=json.loads(view.messages[1]["content"])["records"]
    restored=[{"evidence_id":eid} for eid in records["record_ids"]]
    for fid,(key,value,indices) in records["facts"].items():
        indices=range(len(restored)) if indices=="all" else indices
        assert view.facts[fid]==(tuple(records["record_ids"][i] for i in indices),key,value)
        for index in indices:restored[index][key]=value
    expected=[]
    for event in assessment.evidence.context_events():
        raw=A._record(event)
        expected.append({**{k:v for k,v in raw.items() if k!="fields"},
            **{"event_data."+k:v for k,v in raw["fields"].items()}})
    assert restored==expected
    assert P.read(json.dumps(valid(view)),view).outcome=="supported"


def test_grouped_facts_distinguish_metadata_and_same_named_source_fields(store):
    assessment=assess_one(make_claim(),store)
    def collision(event):
        raw=A._record(event);raw["fields"]["host"]="SOURCE-HOST"
        if event.evidence_id==sec_id(10):raw["fields"]["OnlyFirst"]="present"
        return raw
    view=P.build(assessment,collision,compact=True)
    selected={key:(ids,value) for ids,key,value in view.facts.values()}
    assert selected["host"][1]!=selected["event_data.host"][1]
    assert selected["event_data.OnlyFirst"][0]==(sec_id(10),)


def test_cited_context_outside_stated_span_is_preserved_but_not_counted_inside(store):
    from evidence_verification.tests.conftest import iso
    claim=make_claim(first_utc=iso(0),last_utc=iso(0))
    view=P.build(assess_one(claim,store),A._record,compact=True)
    payload=json.loads(view.messages[1]["content"])
    assert payload["cited_record_indices"]==[0,1,2]
    assert payload["records_in_stated_span"]==[0]
    assert len(payload["records"]["record_ids"])==3
    assert payload["source_computations"]["event_groups"][0]["count"]==1


def test_focused_records_and_grouped_context_together_preserve_all_source_values(store):
    from evidence_verification.tests.conftest import iso
    assessment=assess_one(make_claim(first_utc=iso(0),last_utc=iso(0)),store)
    def builder(event):
        raw=A._record(event);raw["fields"]["host"]="different-source-host";return raw
    view=P.build(assessment,builder,compact="mixed")
    payload=json.loads(view.messages[1]["content"])
    table=payload["records"];restored={eid:{"evidence_id":eid} for eid in table["record_ids"]}
    for field,value,indices in table["facts"].values():
        for i in (range(len(restored)) if indices=="all" else indices):restored[table["record_ids"][i]][field]=value
    for rec in payload["focus_records"]:
        for fid,(field,value) in rec["facts"].items():
            assert view.facts[fid]==(rec["evidence_id"],field,value)
            restored[rec["evidence_id"]][field]=value
    for event in assessment.evidence.context_events():
        raw=builder(event)
        expected={**{k:v for k,v in raw.items() if k!="fields"},**{"event_data."+k:v for k,v in raw["fields"].items()}}
        assert restored[event.evidence_id]==expected
    assert P.read(json.dumps(valid(view)),view).outcome=="supported"
