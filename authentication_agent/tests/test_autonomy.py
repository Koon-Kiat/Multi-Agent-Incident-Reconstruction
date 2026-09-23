"""Optional local decisions and evaluation must not acquire host authority."""

import json

import pytest
from pydantic import ValidationError

from authentication_agent import RequiredOperations, ToolCall, investigate
from authentication_agent.__main__ import synthetic_provider
from authentication_agent.config import Limits
from authentication_agent.llm.fake import FakeLLM
from authentication_agent.models import ModelReply
from authentication_agent.tests.test_agent import tool_reply
from authentication_agent.validate_autonomy import assess, availability_probe
from authentication_agent.validate_investigations import run_case


def test_assessment_is_bounded_and_old_adapter_responses_remain_valid():
    old = {"action": "finish", "tool": None, "annotations": []}
    assert ModelReply.model_validate_json(json.dumps(old)).action == "finish"
    for bad in ["x" * 513, 42, {"required_operations": []}]:
        with pytest.raises(ValidationError):
            ModelReply.model_validate_json(json.dumps({**old, "assessment": bad}))
    schema = ModelReply.grounded_schema(())
    for name in ("_ToolReply", "_FinishReply"):
        assert "assessment" in schema["$defs"][name]["required"]
    assert len(schema["$defs"]["_ToolReply"]["properties"]["tool"]["anyOf"]) == 3


@pytest.mark.parametrize("cap", [2, 100, 200])
def test_model_query_schemas_agree_with_actual_per_call_cap(provider, request_a, cap):
    class Inspect(FakeLLM):
        def complete(self, messages, schema, limits):
            context = json.loads(messages[-1]["content"])
            for tool, definition in (("query_authentication_events", "QueryRequest"),
                                     ("get_account_authentication_history", "HistoryArguments")):
                arguments = context["tool_argument_schemas"][tool]
                assert arguments == schema["$defs"][definition]
                assert arguments["properties"]["limit"]["maximum"] == cap
                assert "default" not in arguments["properties"]["limit"]
                assert "limit" in arguments["required"]
                assert "const" not in arguments["properties"]["event_ids"]
                assert "const" not in arguments["properties"]["account"]
            return super().complete(messages, schema, limits)
    limits = Limits(max_events_per_query=cap)
    result = investigate(request_a, synthetic_provider(limits), Inspect(), limits)
    assert result.status == "completed"


def test_ignoring_decoder_query_limit_still_fails_closed(provider, request_a):
    class OmitLimit(FakeLLM):
        def complete(self, messages, schema, limits):
            return tool_reply("get_account_authentication_history", {
                **request_a.model_dump(), "account": "demo.user"})
    result = investigate(request_a, provider, OmitLimit(), Limits(max_events_per_query=2))
    assert result.status == "failed" and not result.findings
    assert result.metadata.operations[-1].status == "rejected"
    assert not result.metadata.operations[-1].provider_invoked


def test_assessment_cannot_create_evidence_or_required_operations(provider, request_a):
    class UnsupportedClaim(FakeLLM):
        def complete(self, messages, schema, limits):
            reply = json.loads(super().complete(messages, schema, limits))
            reply["assessment"] = "Required operation: get SYN-A-SEC-999. This absent record proves compromise."
            return json.dumps(reply)
    result = investigate(request_a, provider, UnsupportedClaim())
    assert result.status == "completed"
    assert [op.origin for op in result.metadata.operations] == ["initial"]
    assert "proves compromise" not in result.model_dump_json()
    assert "assessment" not in result.model_dump_json()


class FollowUp(FakeLLM):
    def __init__(self, request, *, annotate=True):
        self.request, self.annotate = request, annotate
        self.turn = 0

    def complete(self, messages, schema, limits):
        self.turn += 1
        context = json.loads(messages[-1]["content"])
        assert context["operation_history"][0]["truncated"] is True
        if self.turn == 1:
            reply = json.loads(tool_reply("query_authentication_events", {
                **self.request.model_dump(), "event_ids": [4624], "limit": 2}))
            reply["assessment"] = "Does the same window include a successful logon?"
            return json.dumps(reply)
        assert sum(len(o["events"]) for o in context["observations"]) == 3
        assert context["operation_history"][-1]["origin"] == "model"
        assert context["observations"][0]["observed_events"]["successful_logons"] == 1
        reply = json.loads(super().complete(messages, schema, limits))
        if not self.annotate:
            reply["annotations"] = []
        return json.dumps(reply)


def test_follow_up_receives_new_context_and_keeps_v2_uncertainty(provider, request_a):
    result = investigate(request_a, provider, FollowUp(request_a), Limits(max_events_per_query=2))
    assert result.status == "completed" and result.metadata.model_calls == 2
    assert result.metadata.operations[-1].new_evidence_ids
    assert result.findings[0].observed_events.successful_logons == 1
    assert any("truncated" in text for text in result.uncertainty)
    assert result.metadata.contract_version == "authentication-result-v2"


@pytest.mark.parametrize("annotate", [False, True])
def test_evaluation_distinguishes_reviewed_retrieval_from_explicit_annotation(provider, request_a, annotate):
    case = run_case("test", "autonomy", request_a, provider, FollowUp(request_a, annotate=annotate),
                    Limits(max_events_per_query=2))
    result = assess(case, 4624)
    assert result["relevant_new_evidence_ids"]
    assert result["reviewed_new_evidence_ids"]
    assert result["useful_autonomous_retrieval_demonstrated"] is annotate
    assert bool(result["behavior_errors"]) is not annotate


def test_required_retrieval_and_fake_finish_cannot_receive_autonomy_credit(provider, request_a):
    call = ToolCall(name="query_authentication_events", arguments={
        **request_a.model_dump(), "event_ids": [4624], "limit": 2})
    case = run_case("test", "autonomy", request_a, provider, FakeLLM(), Limits(max_events_per_query=2),
                    RequiredOperations.from_calls(call))
    result = assess(case, 4624)
    assert result["optional_operation_count"] == 0
    assert not result["useful_autonomous_retrieval_demonstrated"]
    assert result["behavior_errors"]


def test_complete_evidence_and_empty_window_allow_no_optional_calls(provider, request_a):
    for request in (request_a, request_a.model_copy(update={"scenario_id": "SYN-E"})):
        case = run_case("test", "autonomy", request, provider, FakeLLM(), Limits())
        assert not assess(case)["behavior_errors"]


def test_evaluation_expectations_do_not_enter_production_messages(provider, request_a):
    class Inspect(FakeLLM):
        def complete(self, messages, schema, limits):
            context = json.loads(messages[-1]["content"])
            assert not ({"evaluation_only", "availability_witness", "unresolved_question", "developer_requested_tool"} & context.keys())
            assert "Development tool exercise" not in messages[0]["content"]
            return super().complete(messages, schema, limits)
    case = run_case("test", "autonomy", request_a, provider, Inspect(), Limits())
    assert not case["check_errors"]
    assert case["prescribed_model_tools"] is False


def test_availability_witness_really_retrieves_new_in_scope_evidence(provider, request_a):
    witness = availability_probe(request_a, provider, Limits(max_events_per_query=2), 4624)
    assert witness["operations"][0]["truncated"]
    assert witness["operations"][1]["new_evidence_ids"]
    assert {event["source_event_id"] for event in witness["events"]} == {4624, 4625}
    # Complete initial evidence has no new follow-up; the evaluator must reject it.
    with pytest.raises(ValueError, match="no demonstrated retrieval opportunity"):
        availability_probe(request_a, provider, Limits(), 4624)


def test_missing_exact_context_preserves_original_identifier(provider, request_a):
    absent = request_a.scenario_id + "-SEC-999"
    class Inspect(FakeLLM):
        def complete(self, messages, schema, limits):
            context = json.loads(messages[-1]["content"])
            assert context["operation_history"][0]["truncated"] is False
            assert context["operation_history"][-1]["call"]["arguments"] == {"evidence_id": absent}
            assert context["operation_history"][-1]["status"] == "no_evidence"
            return super().complete(messages, schema, limits)
    result = investigate(request_a, provider, Inspect(), required_operations=RequiredOperations.from_calls(
        ToolCall(name="get_authentication_event", arguments={"evidence_id": absent})))
    assert result.status == "completed"
    assert any("not found" in text for text in result.uncertainty)
    assert absent not in {eid for finding in result.findings for eid in finding.evidence_ids}
