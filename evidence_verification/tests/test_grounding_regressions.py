import json
import pytest

from event_processing.query import EventStore
from evidence_verification import agent as A
from evidence_verification.tests.conftest import security,assess_one,make_claim,make_reconstruction,sec_id
from evidence_verification.tests.test_agent import ScriptedLLM,reply,decide,GROUNDED
from incident_reconstruction.verification import run_verification


def test_invented_quote_with_one_real_token_cannot_confirm_password_theft(store):
    claim=make_claim(claim_text="Two failed logons were followed by a successful logon for analyst. An attacker stole the account password.")
    llm=ScriptedLLM(reply((claim.claim_text,sec_id(10),"analyst invented-evidence-never-recorded")))
    assert decide(store,llm,claim).verdict=="unverified"


def test_metadata_substrings_and_noncontiguous_words_are_not_quotes(store):
    for quote in ("462","analyst 4625","LAB-A analyst invented"):
        decision=decide(store,ScriptedLLM(reply(("Two failed logons",sec_id(10),quote))))
        assert decision.verdict=="unverified",quote


def test_a_valid_quote_for_one_clause_cannot_hide_an_omitted_embellishment(store):
    claim=make_claim(claim_text=make_claim().claim_text+" An attacker stole the password.")
    decision=decide(store,ScriptedLLM(reply(*GROUNDED)),claim)
    assert decision.verdict=="unverified"
    assert any(c.startswith("verification_incomplete") for c in decision.conflicts)


def test_more_than_fourteen_records_and_long_target_server_fields_are_preserved():
    events=[security(10+i,i,4625,TargetServerName="localhost",TargetInfo="x"*1100) for i in range(18)]
    events.append(security(28,18,4624,TargetServerName="localhost",TargetInfo="x"*1100))
    ids=tuple(e.evidence_id for e in events)
    claim=make_claim(evidence_ids=ids,context_evidence_ids=ids,last_utc=events[-1].timestamp_utc,
                     claim_text="Eighteen failed logons were followed by a successful logon.")
    prompt=A.build_prompt(assess_one(claim,EventStore(events)))
    payload=json.loads(prompt.messages[1]["content"])
    assert len(payload["records"])==19
    assert all(r["fields"]["TargetInfo"]=="x"*1100 for r in payload["records"])
    assert all(r["fields"]["TargetServerName"]=="localhost" for r in payload["records"])


def test_complete_evidence_that_cannot_fit_is_explicitly_unverified(store):
    class Small(ScriptedLLM):
        def metadata(self):
            return {"runtime":"scripted","num_ctx":1024}
    llm=Small(reply(*GROUNDED))
    decision=decide(store,llm)
    assert llm.calls==0
    assert decision.verdict=="unverified"
    assert any(c.startswith("verification_incomplete") for c in decision.conflicts)


def test_verification_reports_do_not_accumulate_previous_scenarios_counts(store):
    verifier=A.AgentVerifier(ScriptedLLM(reply(*GROUNDED)),prompt="v4")
    first=run_verification(verifier,make_reconstruction(make_claim()),store)
    second=run_verification(verifier,make_reconstruction(make_claim()),store)
    assert first.verifier["agent_model_calls"]==second.verifier["agent_model_calls"]==1
    assert verifier.metadata()["agent_model_calls"]==2


def test_exaggerated_plural_failed_logon_count_is_caught_without_model(store):
    claim=make_claim(claim_text="Dozens of failed logons were followed by a successful logon.")
    llm=ScriptedLLM(reply(*GROUNDED))
    decision=decide(store,llm,claim)
    assert decision.verdict=="partially_supported" and llm.calls==0
    assert any("at least 24" in c for c in decision.conflicts)


@pytest.mark.parametrize("duration,verdict", [("ten seconds", "partially_supported"),
                                              ("one second", "confirmed"),
                                              ("1000 milliseconds", "confirmed"),
                                              ("0.5 seconds", "partially_supported")])
def test_explicit_failure_separation_uses_source_timestamps(store, duration, verdict):
    from evidence_verification.tests.conftest import assess_one
    claim=make_claim(claim_text=f"Two failed logons were {duration} apart, followed by a successful logon.")
    assert assess_one(claim,store).verdict==verdict


@pytest.mark.parametrize("text,verdict",[
    ("A successful logon preceded two failed logons.","partially_supported"),
    ("Two failed logons occurred after a successful logon.","partially_supported"),
    ("Two failed logons preceded a successful logon.","confirmed"),
    ("A successful logon occurred after two failed logons.","confirmed"),
])
def test_explicit_authentication_order_in_text_is_checked_independently_of_type(store,text,verdict):
    claim=make_claim(claim_type="authentication_activity",claim_text=text)
    assert assess_one(claim,store).verdict==verdict
