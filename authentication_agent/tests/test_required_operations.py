"""Caller requirements and optional exploration share the same evidence boundary."""

import json

import pytest
from pydantic import ValidationError

from authentication_agent import RequiredOperations, ToolCall, investigate
from authentication_agent.config import Limits
from authentication_agent.errors import InvestigationError
from authentication_agent.llm.fake import FakeLLM
from authentication_agent.models import InvestigationRequest, ModelReply
from authentication_agent.queries.tools import AuthenticationTools
from authentication_agent.validate_synthetic import RecordedProvider
from authentication_agent.tests.test_agent import ReplyLLM, tool_reply


def lookup(evidence_id="SYN-A-SEC-999"):
    return ToolCall(name="get_authentication_event", arguments={"evidence_id": evidence_id})


def query(request, **changes):
    return ToolCall(name="query_authentication_events", arguments={**request.model_dump(), **changes})


def test_required_missing_filtered_and_history_run_before_model(provider, request_a):
    calls = (lookup(), query(request_a, event_ids=[4624]),
             ToolCall(name="get_account_authentication_history", arguments={**request_a.model_dump(), "account": "demo.user"}))
    recorded = RecordedProvider(Limits(), provider)
    class InspectingModel(FakeLLM):
        def complete(self, messages, schema, limits):
            context = json.loads(messages[-1]["content"])
            operations = context["operation_history"]
            assert [op["origin"] for op in operations] == ["initial", "required", "required", "required"]
            assert operations[1]["call"] == calls[0].model_dump(mode="json")
            assert operations[1]["status"] == "no_evidence"
            assert operations[2]["evidence_ids"] == ["SYN-A-SEC-4"]
            assert sum(len(observation["events"]) for observation in context["observations"]) == 4
            return super().complete(messages, schema, limits)
    result = investigate(request_a, recorded, InspectingModel(), required_operations=RequiredOperations.from_calls(*calls))
    assert result.status == "completed" and result.metadata.model_calls == 1
    assert result.metadata.tool_calls == 4 and result.metadata.evidence_readbacks == 4
    assert tuple(op.call for op in result.metadata.operations[1:]) == calls
    assert any("not found" in text for text in result.uncertainty)
    assert not any("SYN-A-SEC-999" in f.evidence_ids for f in result.findings)
    assert [c["evidence_id"] for c in recorded.calls if c["operation"] == "get_event"].count("SYN-A-SEC-999") == 1


def test_required_does_not_disable_optional_model_choice(provider, request_a):
    class Explore(FakeLLM):
        calls = 0
        def complete(self, messages, schema, limits):
            self.calls += 1
            context = json.loads(messages[-1]["content"])
            if self.calls == 1:
                assert context["operation_history"][-1]["origin"] == "required"
                return tool_reply("query_authentication_events", {**request_a.model_dump(), "event_ids": [4624], "limit": 2})
            assert context["last_tool_result"]["evidence_ids"] == ["SYN-A-SEC-4"]
            assert context["operation_history"][-1]["new_evidence_ids"] == ["SYN-A-SEC-4"]
            assert context["observations"][0]["events"][-1]["event_id"] == 4624
            return super().complete(messages, schema, limits)
    result = investigate(request_a, provider, Explore(), Limits(max_events_per_query=2),
                         required_operations=RequiredOperations.from_calls(lookup()))
    assert result.status == "completed"
    assert [op.origin for op in result.metadata.operations] == ["initial", "required", "model"]
    assert any("truncated" in text for text in result.uncertainty)
    assert result.findings[0].observed_events.successful_logons == 1


def test_required_budget_failure_records_omitted_steps_without_partial_findings(provider, request_a):
    result = investigate(request_a, provider, FakeLLM(), Limits(max_tool_calls=1),
                         required_operations=RequiredOperations.from_calls(lookup(), lookup("SYN-A-SEC-1")))
    assert result.status == "failed" and result.error_code == "tool_budget_exhausted"
    assert not result.findings and result.metadata.model_calls == 0
    assert result.metadata.tool_calls == 1 and result.metadata.evidence_readbacks == 0
    assert [op.status for op in result.metadata.operations] == ["completed", "rejected", "not_run"]
    assert [op.required_index for op in result.metadata.operations] == [None, 0, 1]
    assert not any(op.provider_invoked for op in result.metadata.operations[1:])


def test_shared_budget_counts_required_optional_and_duplicates(provider, request_a):
    result = investigate(request_a, provider, ReplyLLM(tool_reply("get_authentication_event", {"evidence_id": "SYN-A-SEC-999"})),
                         Limits(max_tool_calls=3), required_operations=RequiredOperations.from_calls(lookup()))
    assert result.error_code == "tool_budget_exhausted" and not result.findings
    assert result.metadata.tool_calls == 3 and result.metadata.model_calls == 2
    assert [op.provider_invoked for op in result.metadata.operations] == [True, True, False, False]
    assert result.metadata.operations[2].reused_from == 1


@pytest.mark.parametrize("error,code", [(TimeoutError("private detail"), "provider_timeout"),
    (ConnectionError("private detail"), "provider_connection_failed"), (RuntimeError("private detail"), "provider_failure")])
@pytest.mark.parametrize("stage", ["initial", "required", "readback"])
def test_provider_errors_are_distinct_from_missing_and_model_failures(provider, request_a, error, code, stage):
    class FailingProvider:
        def query(self, request):
            if stage == "initial": raise error
            return provider.query(request)
        def get_event(self, evidence_id): raise error
    result = investigate(request_a, FailingProvider(), FakeLLM(),
                         required_operations=None if stage == "readback" else RequiredOperations.from_calls(lookup(), lookup()))
    assert result.status == "failed" and result.error_code == code and not result.findings
    assert "private detail" not in result.model_dump_json()
    assert not any("not found" in text for text in result.uncertainty)
    if stage != "readback":
        failed = next(op for op in result.metadata.operations if op.status == "failed")
        assert failed.origin == stage and failed.provider_invoked
        assert result.metadata.operations[-1].status == "not_run"
    else:
        assert result.metadata.evidence_readbacks == 1


def test_duplicate_empty_queries_are_cached_but_narrower_queries_remain_available(provider, request_a):
    request = request_a.model_copy(update={"scenario_id": "SYN-E"})
    recorded = RecordedProvider(Limits(), provider)
    tools = AuthenticationTools(request, recorded, Limits())
    first = tools.execute(query(request, limit=100), origin="initial")
    assert first == {"evidence_ids": [], "truncated": False}
    equivalent = query(request, event_ids=[4625, 4624, 4624], account=None, host=None,
                       start_utc="2026-01-10T00:00:00.0000000+00:00")
    assert tools.execute(equivalent) == first
    assert len(recorded.calls) == 1 and tools.operations[-1].reused_from == 0
    for call in [query(request, event_ids=[4624]), query(request, account="demo.user"),
                 query(request, host="LAB-A"), query(request, limit=2),
                 query(request, start_utc="2026-01-10T00:00:10Z")]:
        tools.execute(call)
    assert len(recorded.calls) == 6


def test_duplicate_required_operations_execute_once_and_receipts_keep_exact_args(provider, request_a):
    first = query(request_a, account="demo.user")
    history = ToolCall(name="get_account_authentication_history", arguments={**request_a.model_dump(), "account": "demo.user", "limit": 100})
    result = investigate(request_a, provider, FakeLLM(), required_operations=RequiredOperations.from_calls(first, history, lookup(), lookup()))
    assert result.status == "completed"
    assert result.metadata.operations[2].reused_from == 1
    assert result.metadata.operations[2].call == history
    assert result.metadata.operations[-1].reused_from == 3
    assert result.metadata.tool_calls == 5


def test_cached_result_is_detached_and_final_readback_still_detects_changes(provider, request_a):
    tools = AuthenticationTools(request_a, provider, Limits())
    call = query(request_a)
    output = tools.execute(call)
    output["evidence_ids"].clear()
    assert len(tools.execute(call)["evidence_ids"]) == 4
    original_get = provider.get_event
    provider.get_event = lambda eid: original_get(eid).model_copy(update={"host": "changed"})
    with pytest.raises(InvestigationError, match="evidence_changed"):
        tools.validate_references()


@pytest.mark.parametrize("evidence_id", ["42", "SYN-A-SYS-1", "SYN-A-SEC-0", "SYN-A-SEC-01", "SYN-A-SEC--1", "SYN-A-SEC-1\n"])
def test_malformed_ids_rejected_by_typed_reply_required_plan_and_dispatch(provider, request_a, evidence_id):
    call = lookup(evidence_id)
    with pytest.raises(ValidationError): RequiredOperations.from_calls(call)
    with pytest.raises(ValidationError): ModelReply.model_validate_json(tool_reply(call.name, call.arguments))
    recorded = RecordedProvider(Limits(), provider)
    with pytest.raises(InvestigationError): AuthenticationTools(request_a, recorded, Limits()).execute(call)
    assert recorded.calls == []


@pytest.mark.parametrize("call", [
    ToolCall(name="get_authentication_event", arguments={"account": "demo.user"}),
    ToolCall(name="get_account_authentication_history", arguments={"evidence_id": "SYN-A-SEC-1"}),
    ToolCall(name="query_authentication_events", arguments={"command": "unsupported"}),
])
def test_cross_tool_arguments_rejected_independently(provider, request_a, call):
    with pytest.raises(ValidationError): RequiredOperations.from_calls(call)
    recorded = RecordedProvider(Limits(), provider)
    with pytest.raises(InvestigationError): AuthenticationTools(request_a, recorded, Limits()).execute(call)
    assert not recorded.calls


@pytest.mark.parametrize("change", [{"event_ids": [4688]}, {"event_ids": [1]}, {"event_ids": []}, {"limit": 101},
    {"scenario_id": "SYN-B"}, {"end_utc": "2026-01-10T00:02:00Z"}])
def test_dispatch_rechecks_scope_type_and_limits(provider, request_a, change):
    recorded = RecordedProvider(Limits(), provider)
    with pytest.raises(InvestigationError): AuthenticationTools(request_a, recorded, Limits()).execute(query(request_a, **change))
    assert not recorded.calls


def test_absent_cross_scenario_lookup_is_rejected_before_provider(provider, request_a):
    recorded = RecordedProvider(Limits(), provider)
    result = investigate(request_a, recorded, FakeLLM(), required_operations=RequiredOperations.from_calls(lookup("OTHER-SEC-999")))
    assert result.error_code == "provider_scope_violation" and not result.findings
    assert result.metadata.operations[-1].status == "rejected"
    assert not any(call["operation"] == "get_event" for call in recorded.calls)


def test_required_list_has_explicit_bound_and_is_revalidated(provider, request_a):
    with pytest.raises(ValidationError): RequiredOperations.from_calls(*([lookup()] * 100))
    plan = RequiredOperations.from_calls(lookup())
    forged = RequiredOperations.model_construct(operations=plan.operations * 100)
    result = investigate(request_a, provider, FakeLLM(), required_operations=forged)
    assert result.error_code == "invalid_contract_or_model_response"
    assert result.metadata.tool_calls == result.metadata.model_calls == 0


def test_unsupported_name_rejected_even_when_constructed_without_validation(provider, request_a):
    call = ToolCall.model_construct(name="shell", arguments={"command": "unsupported"})
    recorded = RecordedProvider(Limits(), provider)
    with pytest.raises(ValidationError): AuthenticationTools(request_a, recorded, Limits()).execute(call)
    assert not recorded.calls
