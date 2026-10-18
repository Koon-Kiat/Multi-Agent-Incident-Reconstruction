"""The Verifier Agent is independent, only ever lowers a verdict, decides nothing itself, and fails safe."""

from __future__ import annotations

import json

import pytest

from authentication_agent.errors import InvestigationError
from evidence_verification import agent as A
from evidence_verification.tests.conftest import (ClaimEntities, assess_one, iso, make_claim, make_reconstruction,
                                                   sec_id, sys_id)
from incident_reconstruction.verification import load_verifier, run_verification


class ScriptedLLM:
    """Returns a fixed reply, or raises, and counts how often it is consulted."""

    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.calls, self.schemas = reply, error, 0, []

    def metadata(self):
        return {"runtime": "scripted", "model": "test"}

    def complete(self, messages, schema, limits):
        self.calls += 1
        self.schemas.append(schema)
        if self.error:
            raise self.error
        return self.reply if isinstance(self.reply, str) else json.dumps(self.reply)


def reply(*assertions, reason="r"):
    return {"reason": reason, "assertions": [
        {"assertion": text, "shown_by": by, "quote": quote} for text, by, quote in assertions]}


# The default claim says: two failed logons were followed by a successful logon for the same account.
GROUNDED = (("Two failed logons", sec_id(10), "event_id 4625"),
            ("followed by a successful logon for the same account", sec_id(12), "event_id 4624 analyst"))


def decide(store, llm, claim=None):
    return A.AgentVerifier(llm).verify(make_reconstruction(claim or make_claim()), store)[0]


# ---------------------------------------------------------------- independence of the prompt

def test_the_prompt_never_carries_the_reconstructions_own_reasoning(store):
    claim = make_claim(
        rationale="RATIONALE-SENTINEL the stage looked malicious", assessment="benign_possible",
        uncertainty=("UNCERTAINTY-SENTINEL no agent finding",), detection_ids=("DETECTION-SENTINEL",),
        supporting_finding_ids=("FINDING-SENTINEL",))
    text = json.dumps(A.build_messages(assess_one(claim, store)))
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


def test_the_system_prompt_forbids_judging_maliciousness_and_claim_copied_quotes():
    assert "Do not judge whether the activity is malicious" in A.SYSTEM_PROMPT
    assert "never from the claim" in A.SYSTEM_PROMPT
    assert "Absence of contradiction is NOT support" in A.SYSTEM_PROMPT


def test_the_reply_schema_lets_the_model_cite_only_records_it_was_shown(store):
    llm = ScriptedLLM(reply(*GROUNDED))
    decide(store, llm)
    enum = llm.schemas[0]["properties"]["assertions"]["items"]["properties"]["shown_by"]["enum"]
    assert set(enum) == {sec_id(10), sec_id(11), sec_id(12), "NONE"}


# ---------------------------------------------------------------- the code, not the model, decides

def test_every_assertion_grounded_in_a_record_leaves_a_confirmed_claim_confirmed(store):
    assert decide(store, ScriptedLLM(reply(*GROUNDED))).verdict == "confirmed"


def test_an_assertion_no_record_states_lowers_the_claim_to_partially_supported(store):
    llm = ScriptedLLM(reply(*GROUNDED, ("the user then opened a remote desktop session", "NONE", "")))
    claim = make_claim(claim_text="Two failed logons were followed by a successful logon for the same account, "
                                  "and the user then opened a remote desktop session.")
    decision = decide(store, llm, claim)
    assert decision.verdict == "partially_supported"
    assert any("remote desktop session" in c and c.startswith("unsupported_assertion") for c in decision.conflicts)
    assert "remote desktop" in decision.reason


def test_a_claim_none_of_whose_assertions_is_shown_is_unverified_not_rejected(store):
    llm = ScriptedLLM(reply(("Two failed logons", "NONE", ""),
                            ("followed by a successful logon for the same account", "NONE", "")))
    assert decide(store, llm).verdict == "unverified"


def test_a_quote_that_shares_no_word_with_the_cited_record_is_fabricated_and_does_not_count(store):
    llm = ScriptedLLM(reply(("Two failed logons", sec_id(10), "xylophone quarterly forecast"),
                            ("followed by a successful logon for the same account", sec_id(12), "event_id 4624")))
    decision = decide(store, llm)
    assert decision.verdict == "partially_supported"
    assert "quoted support does not appear in the cited record" in decision.conflicts[0]


def test_a_quote_copied_from_the_claim_but_citing_a_real_record_is_tolerated(store):
    # The prompt forbids it, but the record is cited and shares words with it; only fabrication is vetoed.
    llm = ScriptedLLM(reply(("Two failed logons", sec_id(10), "Two failed logons event 4625"),
                            ("followed by a successful logon for the same account", sec_id(12), "analyst 4624")))
    assert decide(store, llm).verdict == "confirmed"


def test_an_assertion_the_model_added_that_the_claim_never_made_is_ignored(store):
    llm = ScriptedLLM(reply(*GROUNDED, ("the xylophone budget was approved by finance", "NONE", "")))
    assert decide(store, llm).verdict == "confirmed"


def test_a_reply_naming_nothing_about_the_claim_is_unavailable_not_a_downgrade(store):
    llm = ScriptedLLM(reply(("xylophone budget approved", "NONE", "")))
    decision = decide(store, llm)
    assert decision.verdict == "confirmed"
    assert "verifier agent was unavailable" in decision.reason


def test_citing_a_record_that_was_not_shown_does_not_count(store):
    llm = ScriptedLLM(reply(("Two failed logons", sec_id(13), "4648"),
                            ("followed by a successful logon for the same account", sec_id(12), "4624")))
    decision = decide(store, llm)
    assert decision.verdict == "partially_supported"
    assert "not shown" in decision.conflicts[0]


@pytest.mark.parametrize("assertions", [
    GROUNDED,
    (("Two failed logons", "NONE", ""), ("followed by a successful logon for the same account", "NONE", "")),
    (("Two failed logons", sec_id(10), "xylophone"),),
])
def test_the_agent_can_never_reject(store, assertions):
    assert decide(store, ScriptedLLM(reply(*assertions))).verdict != "rejected"


def test_the_agent_cannot_raise_a_weaker_verdict(store):
    weak = make_claim(entities=ClaimEntities(accounts=("analyst", "mallory")))  # deterministic: partial
    llm = ScriptedLLM(reply(*GROUNDED))
    assert decide(store, llm, weak).verdict == "partially_supported"
    assert llm.calls == 0, "a claim the agent cannot change is not sent to it"


def test_a_rejected_claim_is_never_sent_to_the_model(store):
    fabricated = make_claim(evidence_ids=(sec_id(999),), context_evidence_ids=(sec_id(999),))
    llm = ScriptedLLM(reply(*GROUNDED))
    assert decide(store, llm, fabricated).verdict == "rejected"
    assert llm.calls == 0


def test_an_unverified_claim_is_never_sent_to_the_model(store):
    wrong_activity = make_claim(evidence_ids=(sys_id(20),), context_evidence_ids=(sys_id(20),),
                                first_utc=iso(5), last_utc=iso(5))
    llm = ScriptedLLM(reply(*GROUNDED))
    assert decide(store, llm, wrong_activity).verdict == "unverified"
    assert llm.calls == 0


# ---------------------------------------------------------------- failing safe

@pytest.mark.parametrize("llm", [
    ScriptedLLM(error=InvestigationError("model_timeout")),
    ScriptedLLM(error=ConnectionError("down")),
    ScriptedLLM(reply="not json at all"),
    ScriptedLLM(reply={"reason": "r"}),                                            # no assertions
    ScriptedLLM(reply={"reason": "r", "assertions": []}),                          # empty list
    ScriptedLLM(reply={**reply(*GROUNDED), "extra": 1}),                           # extra field
    ScriptedLLM(reply={**reply(*GROUNDED), "reason": ""}),                         # empty reason
    ScriptedLLM(reply=reply(*([("a b c", "NONE", "")] * 7))),                      # over the assertion limit
    ScriptedLLM(reply={"reason": "r", "assertions": [{"assertion": "x", "shown_by": "NONE"}]}),  # missing quote
])
def test_an_unavailable_or_invalid_agent_never_changes_the_verdict(store, llm):
    decision = decide(store, llm)
    assert decision.verdict == "confirmed"
    assert "verifier agent was unavailable" in decision.reason


def test_metadata_counts_what_the_agent_did(store):
    verifier = A.AgentVerifier(ScriptedLLM(reply(("Two failed logons", "NONE", ""),
                                                 ("followed by a successful logon for the same account", "NONE", ""))))
    verifier.verify(make_reconstruction(make_claim()), store)
    meta = verifier.metadata()
    assert meta["mode"] == "deterministic_and_agent" and meta["independent_lookup"] is True
    assert (meta["agent_consulted"], meta["agent_lowered"], meta["agent_failed"]) == (1, 1, 0)
    failing = A.AgentVerifier(ScriptedLLM(error=ConnectionError("x")))
    failing.verify(make_reconstruction(make_claim()), store)
    assert failing.metadata()["agent_failed"] == 1


def test_run_verification_accepts_the_agents_decisions(store):
    llm = ScriptedLLM(reply(("Two failed logons", "NONE", ""),
                            ("followed by a successful logon for the same account", "NONE", "")))
    report = run_verification(A.AgentVerifier(llm), make_reconstruction(make_claim()), store)
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


# ---------------------------------------------------------------- prompt selection (post-hoc revision is opt-in)

def test_v2_stays_the_default_and_is_the_scored_prompt(monkeypatch):
    monkeypatch.setenv("MAIR_VERIFIER_LLM", "fake")
    monkeypatch.delenv("MAIR_VERIFIER_PROMPT", raising=False)
    verifier = A.make_agent_verifier()
    assert verifier.metadata()["prompt_version"] == "evidence-verifier-prompt-v2"
    assert verifier._system_prompt == A.SYSTEM_PROMPT_V2 == A.SYSTEM_PROMPT


def test_v3_is_opt_in_and_differs_only_in_the_rules_block(monkeypatch):
    monkeypatch.setenv("MAIR_VERIFIER_LLM", "fake")
    monkeypatch.setenv("MAIR_VERIFIER_PROMPT", "v3")
    verifier = A.make_agent_verifier()
    assert verifier.metadata()["prompt_version"] == "evidence-verifier-prompt-v3"
    assert "Split the claim into atomic assertions" in verifier._system_prompt
    assert A.SYSTEM_PROMPT_V2.split("Rules:")[0] == A.SYSTEM_PROMPT_V3.split("Rules:")[0], "the framing is unchanged"
    assert "Split the claim into atomic assertions" not in A.SYSTEM_PROMPT_V2


def test_an_unknown_prompt_is_refused(monkeypatch):
    monkeypatch.setenv("MAIR_VERIFIER_LLM", "fake")
    monkeypatch.setenv("MAIR_VERIFIER_PROMPT", "v9")
    with pytest.raises(ValueError, match="unknown prompt"):
        A.make_agent_verifier()
