"""Context regressions use scripted responses, never experimental accuracy claims."""
import json

from authentication_agent.config import Limits
from authentication_agent.errors import InvestigationError
from incident_reconstruction.single_agent import SingleAgentInvestigator, FINAL_TURN, reply_schema
from .test_run_modes import Scripted, NULLS, finish, claim, single


class BoundedScripted(Scripted):
    def __init__(self, respond, counter):
        super().__init__(respond)
        self.counter, self.calls = counter, []

    def metadata(self):
        return {"runtime": "scripted", "num_ctx": 8192}

    def input_token_upper_bound(self, messages):
        return self.counter(messages)

    def complete(self, messages, schema, limits):
        assert self.input_token_upper_bound(messages) + limits.max_output_tokens <= 8192
        self.calls.append((messages.copy(), limits))
        return super().complete(messages, schema, limits)


def test_large_initial_input_gets_tool_budget_and_fitting_final_budget(store, engine):
    llm = BoundedScripted(lambda *_: finish(), lambda _: 5800)
    result = single(store, engine, llm)
    assert [limits.max_output_tokens for _, limits in llm.calls] == [1024, 2392]
    assert result.model_calls == 2
    assert not any("failed" in gap for gap in result.investigation_gaps)
    assert result.llm["context_admissions"][-1]["input_token_upper_bound"] == 5800


def test_repeated_tool_results_retain_each_original_record_once(store, engine):
    def respond(turn, messages, schema):
        if turn <= 3:
            return {"action": "query_authentication", "arguments": NULLS, "claims": []}
        facts = json.loads(messages[1]["content"])["trigger_events"]
        repeats = []
        for message in messages[2:]:
            body = json.loads(message["content"])
            facts += body.get("events", [])
            repeats += body.get("previously_shown_evidence_ids", [])
        ids = [fact["evidence_id"] for fact in facts]
        assert len(ids) == len(set(ids))
        assert repeats and set(repeats) <= set(ids)
        return finish()
    result = single(store, engine, Scripted(respond))
    assert result.model_calls == 5
    assert result.investigation_gaps == ("tool calls used: 3 of 16",)


def test_capacity_overflow_keeps_prefix_and_excludes_unshown_citations(store):
    llm = BoundedScripted(lambda *_: finish(), lambda messages: sum(len(m["content"]) for m in messages))
    agent = SingleAgentInvestigator(store, llm)
    first = {"evidence_id": "SYN-ORCH-SEC-100", "fields": {"value": "unchanged"}}
    huge = {"evidence_id": "SYN-ORCH-SEC-101", "fields": {"value": "x" * 7000}}
    later = {"evidence_id": "SYN-ORCH-SEC-102", "fields": {"value": "later"}}
    candidates = {event["evidence_id"]: object() for event in (first, huge, later)}
    conversation, shown, overflow, omitted = agent._bounded_result(
        [{"role": "system", "content": "read telemetry"}],
        {"action": "query_authentication", "arguments": NULLS, "claims": []},
        {"tool": "query_authentication", "truncated": False, "events": [first, huge, later]}, {}, candidates)
    body = json.loads(conversation[-1]["content"])
    assert overflow and omitted == body["context_omitted_events"] == 2
    assert body["events"] == [first]  # exact fields; no cherry-picking past the oversized record
    assert set(shown) == {first["evidence_id"]}
    assert len(candidates) == 3
    assert agent._call_limits(conversation + [{"role": "user", "content": FINAL_TURN}],
                              reply_schema(tuple(shown), finish_only=True), final=True) is not None


def test_overflow_finishes_with_gap_and_rejects_fetched_but_unseen_record(store, engine, events, monkeypatch):
    unseen = events["process_parent"].evidence_id
    llm = BoundedScripted(
        lambda turn, *_: {"action": "query_endpoint", "arguments": NULLS, "claims": []} if turn == 1
        else finish(claim([unseen])),
        lambda messages: 8000 if "overflow-marker" in json.dumps(messages) else 3000)
    agent = SingleAgentInvestigator(store, llm)
    def tool(action, arguments, scenario, window, retrieved):
        retrieved[unseen] = events["process_parent"]
        return {"tool": action, "events": [{"evidence_id": unseen, "fields": {"value": "overflow-marker"}}]}
    monkeypatch.setattr(agent, "_run_tool", tool)
    result = agent.investigate("SYN-ORCH", engine.triggers_for("SYN-ORCH"), corpus_manifest_sha256="0" * 64)
    assert result.model_calls == 2 and not result.claims
    assert any("context capacity reached; 1" in gap for gap in result.investigation_gaps)
    assert any("cited_evidence_ids" in gap for gap in result.investigation_gaps)


def test_oversized_initial_context_never_reaches_transport(store, engine):
    llm = BoundedScripted(lambda *_: finish(), lambda _: 8000)
    result = single(store, engine, llm)
    assert not llm.calls and result.model_calls == 0
    assert any("context_size_limit" in gap for gap in result.investigation_gaps)


def test_output_length_failure_is_preserved_without_retry(store, engine):
    llm = BoundedScripted(lambda turn, *_: finish() if turn == 1
                          else InvestigationError("incomplete_model_response"), lambda _: 5800)
    result = single(store, engine, llm)
    assert len(llm.calls) == 2 and not result.claims
    assert any("incomplete_model_response" in gap for gap in result.investigation_gaps)


def test_explicit_lower_output_limit_and_schema_byte_guard_are_preserved(store):
    llm = BoundedScripted(lambda *_: finish(), lambda _: 100)
    agent = SingleAgentInvestigator(store, llm, model_limits=Limits(max_output_tokens=512, max_context_bytes=4096))
    assert agent._call_limits([], {}, final=True).max_output_tokens == 512
    assert agent._call_limits([], {"description": "x" * 4096}, final=True) is None


def test_cli_reports_context_limited_timeline_as_incomplete(tmp_path):
    from types import SimpleNamespace
    from incident_reconstruction.__main__ import _report
    summary = SimpleNamespace(phases=(), scenario_id="SYN", mode="single-agent", detections=1,
                              claims=0, model_calls=2, latency_seconds=0.0, verdicts=None)
    reconstruction = SimpleNamespace(claims=(), investigation_gaps=(
        "context capacity reached; 1 new tool-result records were not shown; investigation ended early",))
    output = SimpleNamespace(summary=summary, reconstruction=reconstruction, orchestration=None, verification=None)
    assert _report(output, tmp_path) is True
