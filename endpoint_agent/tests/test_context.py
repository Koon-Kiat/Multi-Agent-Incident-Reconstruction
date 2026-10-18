"""Evidence coverage, cross-batch grounding and bounded failure regressions."""

import json

import pytest

from endpoint_agent import investigate
from endpoint_agent.config import Limits
from endpoint_agent.llm.fake import FakeLLM
from endpoint_agent.models import InvestigationRequest, InvestigationResult
from endpoint_agent.observations import BASE_UNCERTAINTY
from endpoint_agent.tests.conftest import ROOT, endpoint_event
from event_processing.adapters.endpoint_provider import CorpusEndpointProvider
from event_processing.query import EventStore


class ReviewingLLM(FakeLLM):
    def __init__(self, num_ctx=8192):
        self.num_ctx = num_ctx
        self.contexts = []

    def metadata(self):
        return {**super().metadata(), "num_ctx": self.num_ctx}

    def complete(self, messages, schema, limits):
        context = json.loads(messages[-1]["content"])
        self.contexts.append(context)
        # The decoder is grounded to just the visible batch, including parent citations.
        allowed = schema["$defs"]["Annotation"]["anyOf"]
        assert [x["properties"]["observation_id"]["const"] for x in allowed] == [
            f["finding_id"] for f in context["observations"]]
        assert len(json.dumps({"messages": messages, "schema": schema},
                              ensure_ascii=False, separators=(",", ":")).encode()) <= limits.max_context_bytes
        return json.dumps({"action": "finish", "tool": None, "annotations": [
            {"observation_id": f["finding_id"], "evidence_ids": f["evidence_ids"],
             "interpretation": "context_required"} for f in context["observations"]]})


def test_dense_equal_time_records_and_cross_batch_links_survive(investigation):
    events = [endpoint_event(1, ProcessGuid=ROOT, ProcessId="1", Image="explorer.exe")]
    events += [endpoint_event(i, second=i // 3, ProcessGuid=f"{{{i:08x}-aaaa-bbbb-cccc-000000000001}}",
        ProcessId=str(i), Image="inventory.exe", ParentProcessGuid=ROOT,
        ParentProcessId="1", ParentImage="explorer.exe",
        CommandLine="inventory.exe " + "\u8bc1\u636e" * 80) for i in range(2, 151)]
    store = EventStore(reversed(events))
    llm = ReviewingLLM()
    result = investigate(investigation, CorpusEndpointProvider(store), llm)
    assert result.status == "completed", result.error_code
    assert len(result.findings) == len(events) == result.metadata.evidence_readbacks
    assert result.metadata.window_coverage_complete and not result.metadata.truncated
    assert result.metadata.window_total_matched == len(events)
    assert any(op.origin == "coverage" for op in result.metadata.operations)
    assert any(op.truncated for op in result.metadata.operations)  # original audit is preserved
    assert len(llm.contexts) > 1
    viewed = [f for c in llm.contexts for f in c["observations"]]
    assert [f["finding_id"] for f in viewed] == [f.finding_id for f in result.findings]
    assert all(f.interpretation is not None for f in result.findings)
    for row, finding in zip(viewed, result.findings):
        # Lossless reconstruction of the presentation projection.
        expected = finding.model_dump(mode="json", exclude_none=True,
            exclude={"agent_type", "scenario_id", "interpretation"})
        expected["uncertainty"] = [s for s in finding.uncertainty if s not in BASE_UNCERTAINTY]
        assert row == expected
    parent = result.findings[0]
    last = result.findings[-1]
    assert last.observed_events.relationships[0].source_evidence_id == parent.observed_events.evidence_id
    assert parent.finding_id not in {f["finding_id"] for f in llm.contexts[-1]["observations"]}
    assert all(b.input_token_upper_bound + 2048 <= 8192 for b in result.metadata.context_batches)
    assert len(result.metadata.context_batches) == result.metadata.model_calls
    assert InvestigationResult.model_validate_json(result.model_dump_json()) == result


def test_many_exact_seeds_do_not_repeat_the_whole_audit_in_context(investigation):
    events = [endpoint_event(i, ProcessGuid=ROOT, Image="admin.exe") for i in range(1, 100)]
    request = InvestigationRequest(**investigation.window(), seed_evidence_ids=tuple(e.evidence_id for e in events))
    llm = ReviewingLLM()
    limits = Limits(max_tool_calls=100)
    result = investigate(request, CorpusEndpointProvider(EventStore(events), limits), llm, limits)
    assert result.status == "completed", result.error_code
    assert len(result.metadata.operations) == 100 and len(result.findings) == 99
    assert all(len(c["operation_history"]) == 1 for c in llm.contexts)
    assert all(c["tool_calls_remaining"] == 0 for c in llm.contexts)


def test_annotation_from_another_batch_is_rejected(provider, investigation):
    first = None

    class CrossBatch(ReviewingLLM):
        def complete(self, messages, schema, limits):
            nonlocal first
            reply = json.loads(super().complete(messages, schema, limits))
            if first is None:
                first = reply["annotations"][0]
            else:
                reply["annotations"] = [first]
            return json.dumps(reply)

    result = investigate(investigation, provider, CrossBatch(), Limits(max_context_bytes=9000))
    assert result.error_code == "invalid_evidence_reference" and not result.findings


def test_late_tool_rebuilds_global_links_and_invalidates_earlier_annotations(investigation):
    events = [endpoint_event(i, second=i, Image="admin.exe") for i in range(1, 6)]
    parent = endpoint_event(6, second=0, ProcessGuid=ROOT, Image="explorer.exe")
    events[0].event_data.update(ParentProcessGuid=ROOT,
        ProcessGuid="{00000002-aaaa-bbbb-cccc-000000000001}", ParentImage="explorer.exe")
    # The provider supplies an incomplete initial query, but exact lookup can
    # recover the parent. The final readback still checks every source record.
    class Provider:
        def query(self, query):
            from endpoint_agent.models import QueryResult
            if query.start_utc != investigation.start_utc:
                return QueryResult(events=(events[-1],), truncated=False, total_matched=1)
            return QueryResult(events=tuple(events), truncated=True, total_matched=6)
        def get_event(self, eid):
            return next((e for e in [*events, parent] if e.evidence_id == eid), None)

    class LateLookup(ReviewingLLM):
        called = False
        def complete(self, messages, schema, limits):
            context = json.loads(messages[-1]["content"])
            if not self.called and context["batch"]["offset"] > 0:
                self.called = True
                return json.dumps({"action": "tool", "annotations": [], "tool": {
                    "name": "get_endpoint_event", "arguments": {"evidence_id": parent.evidence_id}}})
            return super().complete(messages, schema, limits)

    llm = LateLookup()
    result = investigate(investigation, Provider(), llm, Limits(max_context_bytes=9000))
    assert result.status == "completed", result.error_code
    assert llm.called and result.metadata.window_coverage_complete
    assert len(result.findings) == 6
    assert all(f.interpretation is not None for f in result.findings)
    child = next(f for f in result.findings if f.observed_events.evidence_id == events[0].evidence_id)
    assert child.observed_events.relationships[0].source_evidence_id == parent.evidence_id
    final_revision = result.metadata.tool_calls
    reviewed = [fid for b in result.metadata.context_batches if b.revision == final_revision for fid in b.observation_ids]
    assert reviewed == [f.finding_id for f in result.findings]


def test_failure_in_a_later_batch_never_returns_partial_findings(provider, investigation):
    class TimeoutLater(ReviewingLLM):
        def complete(self, messages, schema, limits):
            if self.contexts:
                raise TimeoutError("private")
            return super().complete(messages, schema, limits)
    result = investigate(investigation, provider, TimeoutLater(), Limits(max_context_bytes=9000))
    assert result.error_code == "model_timeout" and not result.findings
    assert result.metadata.model_calls == 2 and result.metadata.evidence_readbacks == 0


@pytest.mark.parametrize("num_ctx,context_bytes", [(4096, 262144), (8192, 4096)])
def test_unfit_single_observation_fails_without_clipping(provider, investigation, num_ctx, context_bytes):
    llm = ReviewingLLM(num_ctx)
    result = investigate(investigation, provider, llm, Limits(max_context_bytes=context_bytes))
    assert result.error_code == "context_size_limit" and not result.findings
    assert result.metadata.model_calls == 0 and not llm.contexts


def test_no_progress_at_one_tick_or_exhausted_budget_stays_incomplete(investigation):
    events = [endpoint_event(i, Image="admin.exe") for i in range(1, 8)]
    limits = Limits(max_events_per_query=2, max_tool_calls=3)
    result = investigate(investigation, CorpusEndpointProvider(EventStore(events), limits), FakeLLM(), limits)
    assert result.status == "completed" and result.metadata.truncated
    assert not result.metadata.window_coverage_complete and result.metadata.retrieved_events == 2
    assert result.metadata.window_total_matched == 7
    assert result.metadata.tool_calls <= 3 and result.uncertainty
    assert all(f.uncertainty for f in result.findings)


def test_late_seeds_do_not_skip_intervening_records(investigation):
    events = [endpoint_event(i, second=i, Image="admin.exe") for i in range(1, 10)]
    request = InvestigationRequest(**investigation.window(), seed_evidence_ids=(events[-1].evidence_id,))
    limits = Limits(max_events_per_query=3)
    result = investigate(request, CorpusEndpointProvider(EventStore(events), limits), FakeLLM(), limits)
    assert result.status == "completed" and result.metadata.window_coverage_complete
    assert {f.observed_events.evidence_id for f in result.findings} == {e.evidence_id for e in events}


def test_recovery_advances_through_pages_already_covered_by_seeds(investigation):
    events = [endpoint_event(i, second=i, Image="admin.exe") for i in range(1, 8)]
    request = InvestigationRequest(**investigation.window(), seed_evidence_ids=tuple(
        e.evidence_id for e in events[2:5]))
    limits = Limits(max_events_per_query=3)
    result = investigate(request, CorpusEndpointProvider(EventStore(events), limits), FakeLLM(), limits)
    assert result.status == "completed" and result.metadata.window_coverage_complete
    assert len(result.findings) == 7


def test_historical_results_still_parse_with_explicit_old_strategy(provider, investigation):
    payload = investigate(investigation, provider, FakeLLM()).model_dump(mode="json")
    for field in ("context_strategy", "context_batches", "window_total_matched", "window_coverage_complete"):
        payload["metadata"].pop(field)
    old = InvestigationResult.model_validate_json(json.dumps(payload))
    assert old.metadata.context_strategy == "single-context-v1" and not old.metadata.context_batches


def test_provider_cannot_understate_whole_window_count(events, investigation):
    from endpoint_agent.models import QueryResult

    class Understated:
        def query(self, query):
            return QueryResult(events=(events[0],), total_matched=1, truncated=False)
        def get_event(self, eid):
            return next((e for e in events if e.evidence_id == eid), None)

    request = InvestigationRequest(**investigation.window(), seed_evidence_ids=(events[1].evidence_id,))
    result = investigate(request, Understated(), FakeLLM())
    assert result.error_code == "provider_contract_violation" and not result.findings
    assert result.metadata.model_calls == 0
