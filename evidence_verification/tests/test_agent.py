"""The Verifier Agent is independent, only ever lowers a verdict, and fails safe."""

from __future__ import annotations

import json

import pytest

from authentication_agent.errors import InvestigationError
from evidence_verification import agent as A
from evidence_verification.verifier import assess
from evidence_verification.tests.conftest import (ClaimEntities, assess_one, iso, make_claim, make_reconstruction,
                                                   sec_id, sys_id)
from incident_reconstruction.verification import load_verifier, run_verification


class ScriptedLLM:
    """Returns a fixed reply, or raises, and counts how often it is consulted."""

    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.calls, self.prompts = reply, error, 0, []

    def metadata(self):
        return {"runtime": "scripted", "model": "test"}

    def complete(self, messages, schema, limits):
        self.calls += 1
        self.prompts.append(messages)
        if self.error:
            raise self.error
        return self.reply if isinstance(self.reply, str) else json.dumps(self.reply)


def judgement(kind, assertions=(), reason="r"):
    return {"judgement": kind, "reason": reason,
            "unsupported_assertions": [{"assertion": a, "why": "not shown"} for a in assertions]}


def decide(store, llm, claim=None):
    claim = claim or make_claim()
    return A.AgentVerifier(llm).verify(make_reconstruction(claim), store)[0]


# ---------------------------------------------------------------- independence of the prompt

def test_the_prompt_never_carries_the_reconstructions_own_reasoning(store):
    claim = make_claim(
        rationale="RATIONALE-SENTINEL the stage looked malicious", assessment="benign_possible",
        uncertainty=("UNCERTAINTY-SENTINEL no agent finding",), detection_ids=("DETECTION-SENTINEL",),
        supporting_finding_ids=("FINDING-SENTINEL",))
    messages = A.build_messages(assess_one(claim, store))
    text = json.dumps(messages)
    for sentinel in ("RATIONALE-SENTINEL", "UNCERTAINTY-SENTINEL", "DETECTION-SENTINEL", "FINDING-SENTINEL",
                     "benign_possible", "requires_review", "verification_status"):
        assert sentinel not in text, sentinel


def test_the_prompt_holds_the_claim_and_the_records_the_verifier_retrieved(store):
    messages = A.build_messages(assess_one(make_claim(), store))
    payload = json.loads(messages[1]["content"])
    assert payload["claim"]["claim_text"].startswith("Two failed logons")
    assert {r["evidence_id"] for r in payload["records"]} == {sec_id(10), sec_id(11), sec_id(12)}
    assert all(r["time_utc"] and r["event_id"] for r in payload["records"])
    assert messages[0]["role"] == "system" and "independent evidence verifier" in messages[0]["content"]


def test_the_prompt_is_bounded(store):
    many = tuple(sec_id(i) for i in (10, 11, 12, 13, 14))
    payload = json.loads(A.build_messages(assess_one(make_claim(context_evidence_ids=many), store))[1]["content"])
    assert payload["records_shown"] <= A.MAX_RECORDS
    assert payload["records_shown"] == len(payload["records"]) == payload["records_available"]
    assert len(json.dumps(payload)) < 12_000


def test_the_system_prompt_forbids_judging_maliciousness():
    assert "Do not judge whether the activity is malicious" in A.SYSTEM_PROMPT


# ---------------------------------------------------------------- the agent can only lower

def test_an_agreeing_agent_leaves_a_confirmed_claim_confirmed(store):
    decision = decide(store, ScriptedLLM(judgement("supported")))
    assert decision.verdict == "confirmed"


def test_an_unsupported_judgement_lowers_confirmed_to_unverified(store):
    decision = decide(store, ScriptedLLM(judgement("unsupported")))
    assert decision.verdict == "unverified"
    assert "verifier agent judged it unsupported" in decision.reason


def test_cannot_tell_lowers_confirmed_to_unverified_not_to_rejected(store):
    assert decide(store, ScriptedLLM(judgement("cannot_tell"))).verdict == "unverified"


def test_a_named_assertion_about_the_claim_lowers_it_to_partially_supported(store):
    decision = decide(store, ScriptedLLM(judgement("partially_supported", ["successful logon for the same account"])))
    assert decision.verdict == "partially_supported"
    assert any(c.startswith("unsupported_assertion") for c in decision.conflicts)


def test_an_assertion_the_claim_never_made_is_not_accepted(store):
    # The model invents a complaint about something the claim does not say; the claim keeps its verdict.
    decision = decide(store, ScriptedLLM(judgement("partially_supported", ["xylophone quarterly revenue forecast"])))
    assert decision.verdict == "confirmed"
    assert "named no assertion the claim makes" in decision.reason


@pytest.mark.parametrize("kind", A.JUDGEMENTS)
def test_the_agent_can_never_reject(store, kind):
    verdict = decide(store, ScriptedLLM(judgement(kind, ["failed logons"]))).verdict
    assert verdict != "rejected"


def test_the_agent_cannot_raise_a_weaker_verdict(store):
    weak = make_claim(entities=ClaimEntities(accounts=("analyst", "mallory")))  # deterministic: partial
    llm = ScriptedLLM(judgement("supported"))
    decision = decide(store, llm, weak)
    assert decision.verdict == "partially_supported"
    assert llm.calls == 0, "a claim the agent cannot change is not sent to it"


def test_a_rejected_claim_is_never_sent_to_the_model(store):
    fabricated = make_claim(evidence_ids=(sec_id(999),), context_evidence_ids=(sec_id(999),))
    llm = ScriptedLLM(judgement("supported"))
    assert decide(store, llm, fabricated).verdict == "rejected"
    assert llm.calls == 0


def test_an_unverified_claim_is_never_sent_to_the_model(store):
    wrong_activity = make_claim(evidence_ids=(sys_id(20),), context_evidence_ids=(sys_id(20),),
                                first_utc=iso(5), last_utc=iso(5))
    llm = ScriptedLLM(judgement("supported"))
    assert decide(store, llm, wrong_activity).verdict == "unverified"
    assert llm.calls == 0


# ---------------------------------------------------------------- failing safe

@pytest.mark.parametrize("llm", [
    ScriptedLLM(error=InvestigationError("model_timeout")),
    ScriptedLLM(error=ConnectionError("down")),
    ScriptedLLM(reply="not json at all"),
    ScriptedLLM(reply={"judgement": "supported"}),                                   # missing fields
    ScriptedLLM(reply={**judgement("supported"), "extra": 1}),                       # extra field
    ScriptedLLM(reply={**judgement("supported"), "judgement": "maybe"}),             # outside the contract
    ScriptedLLM(reply={**judgement("unsupported"), "reason": ""}),                   # empty reason
])
def test_an_unavailable_or_invalid_agent_never_changes_the_verdict(store, llm):
    decision = decide(store, llm)
    assert decision.verdict == "confirmed"
    assert "verifier agent was unavailable" in decision.reason


def test_metadata_counts_what_the_agent_did(store):
    llm = ScriptedLLM(judgement("unsupported"))
    verifier = A.AgentVerifier(llm)
    verifier.verify(make_reconstruction(make_claim()), store)
    meta = verifier.metadata()
    assert meta["mode"] == "deterministic_and_agent" and meta["independent_lookup"] is True
    assert (meta["agent_consulted"], meta["agent_lowered"], meta["agent_failed"]) == (1, 1, 0)
    failing = A.AgentVerifier(ScriptedLLM(error=ConnectionError("x")))
    failing.verify(make_reconstruction(make_claim()), store)
    assert failing.metadata()["agent_failed"] == 1


def test_run_verification_accepts_the_agents_decisions(store):
    reconstruction = make_reconstruction(make_claim())
    report = run_verification(A.AgentVerifier(ScriptedLLM(judgement("unsupported"))), reconstruction, store)
    assert report.integrity_notes == ()
    assert report.verdicts() == {"SYN-V1-CLM-01": "unverified"}
    assert report.verifier["prompt_version"] == A.PROMPT_VERSION


# ---------------------------------------------------------------- the factory

def test_the_factory_refuses_to_pick_a_model_silently(monkeypatch):
    monkeypatch.delenv("MAIR_VERIFIER_LLM", raising=False)
    with pytest.raises(ValueError, match="MAIR_VERIFIER_LLM"):
        A.make_agent_verifier()


def test_the_fake_factory_loads_through_the_orchestrators_loader(monkeypatch, store):
    monkeypatch.setenv("MAIR_VERIFIER_LLM", "fake")
    verifier = load_verifier("evidence_verification.agent:make_agent_verifier")
    assert verifier.metadata()["model"]["runtime"] == "fake"
    assert [d.verdict for d in verifier.verify(make_reconstruction(make_claim()), store)] == ["confirmed"]
