"""Actual public Sysmon evidence and the endpoint call boundary; no answer keys."""

from collections import Counter

import pytest

from endpoint_agent import InvestigationRequest, InvestigationResult, investigate
from endpoint_agent.config import Limits
from endpoint_agent.llm.fake import FakeLLM
from endpoint_agent.models import ENDPOINT_EVENT_IDS, QueryRequest, SYSMON_CHANNEL
from event_processing.adapters.endpoint_provider import CorpusEndpointProvider
from event_processing.corpus import normalise_datasets
from event_processing.manifest import load_scenario
from event_processing.query import EventStore
from event_processing.tests.conftest import real_datasets
from event_processing.timeutil import iso_to_ticks, ticks_to_iso


@pytest.fixture(scope="session")
def endpoint_corpus(tmp_path_factory):
    datasets = real_datasets()
    output = tmp_path_factory.mktemp("endpoint-corpus")
    normalise_datasets(datasets, output)
    return datasets, EventStore.load(output)


def public_request(datasets, scenario):
    info = load_scenario(datasets / scenario)
    # Capture metadata is inclusive; all query bounds are half-open, at 100 ns precision.
    return InvestigationRequest(scenario_id=scenario,
        start_utc=ticks_to_iso(info.window_start_ticks), end_utc=ticks_to_iso(info.window_end_ticks + 1))


@pytest.mark.parametrize("scenario", ["S01", "S02", "S03"])
def test_real_retrieval_facts_and_relationships_resolve_exactly(endpoint_corpus, scenario):
    datasets, store = endpoint_corpus
    request = public_request(datasets, scenario)
    provider = CorpusEndpointProvider(store)
    response = provider.query(QueryRequest(**request.window()))
    expected = store.query(scenario, request.start_utc, request.end_utc,
                           channels=(SYSMON_CHANNEL,), event_ids=ENDPOINT_EVENT_IDS)
    assert response.events == expected.events
    assert (response.total_matched, response.truncated) == (expected.total_matched, expected.truncated)
    assert response.events
    result = investigate(request, provider, FakeLLM())
    assert result.status == "completed", result.error_code
    assert result.metadata.window_total_matched == expected.total_matched
    assert result.metadata.window_coverage_complete == (len(result.findings) == expected.total_matched)
    assert result.metadata.truncated == (len(result.findings) < expected.total_matched)
    assert {e.evidence_id for e in response.events} <= {f.observed_events.evidence_id for f in result.findings}
    assert result.metadata.evidence_readbacks == len(result.findings)
    assert InvestigationResult.model_validate_json(result.model_dump_json()) == result
    for finding in result.findings:
        observed = finding.observed_events
        anchor = store.lookup(observed.evidence_id).event
        assert anchor.source_type == "sysmon" and anchor.source_event_id == observed.source_event_id
        assert observed.timestamp_utc == anchor.timestamp_utc
        assert finding.entities.host == anchor.host and finding.entities.account == anchor.user
        facts = observed.process
        assert facts.process_guid == anchor.event_data.get("SourceProcessGUID" if anchor.source_event_id == 10 else "ProcessGuid")
        assert facts.image == anchor.event_data.get("SourceImage" if anchor.source_event_id == 10 else "Image")
        evidence = [store.lookup(eid).event for eid in finding.evidence_ids]
        assert all(e is not None and e.scenario_id == scenario and e.channel == SYSMON_CHANNEL for e in evidence)
        assert finding.timestamps.first_utc == evidence[0].timestamp_utc
        assert finding.timestamps.last_utc == evidence[-1].timestamp_utc
        for relationship in observed.relationships:
            source = store.lookup(relationship.source_evidence_id).event
            target = store.lookup(relationship.target_evidence_id).event
            assert source.source_event_id == 1
            assert source.host == target.host == anchor.host
            assert source.timestamp_ticks <= target.timestamp_ticks
            field = "ParentProcessGuid" if relationship.kind == "parent_child" else (
                "SourceProcessGUID" if target.source_event_id == 10 else "ProcessGuid")
            assert source.event_data["ProcessGuid"] == target.event_data[field]
            assert {source.evidence_id, target.evidence_id} <= set(finding.evidence_ids)
        assert iso_to_ticks(request.start_utc) <= anchor.timestamp_ticks < iso_to_ticks(request.end_utc)


def test_real_sysmon_record_number_collision_keeps_scenarios_distinct(endpoint_corpus):
    _, store = endpoint_corpus
    provider = CorpusEndpointProvider(store)
    first = {e.record_id: e for e in store.scenario_events("S02") if e.channel == SYSMON_CHANNEL}
    second = {e.record_id: e for e in store.scenario_events("S03") if e.channel == SYSMON_CHANNEL}
    record = next(iter(first.keys() & second.keys()))
    assert provider.get_event(f"S02-SYS-{record}") == first[record]
    assert provider.get_event(f"S03-SYS-{record}") == second[record]
    assert first[record].evidence_id != second[record].evidence_id


def test_real_exact_seed_can_retrieve_beyond_a_capped_prefix(endpoint_corpus):
    datasets, store = endpoint_corpus
    request = public_request(datasets, "S02")
    events = store.query("S02", request.start_utc, request.end_utc, channels=(SYSMON_CHANNEL,),
                         event_ids=(1,), limit=1000).events
    assert len(events) > 1
    seed = events[-1].evidence_id
    request = InvestigationRequest(**request.window(), seed_evidence_ids=(seed,))
    limits = Limits(max_events_per_query=1)
    result = investigate(request, CorpusEndpointProvider(store, limits), FakeLLM(), limits)
    assert result.status == "completed" and result.metadata.truncated
    assert seed in result.metadata.operations[1].new_evidence_ids
    assert any(f.observed_events.evidence_id == seed for f in result.findings)


@pytest.mark.parametrize("scenario", ["S01", "S02", "S03"])
def test_all_planned_endpoint_windows_recover_complete_evidence_without_time_splitting(endpoint_corpus, scenario):
    from event_processing.detection.engine import DetectionEngine
    from incident_reconstruction.orchestrator import IncidentOrchestrator, task_limits

    _, store = endpoint_corpus
    engine = DetectionEngine(store, corpus_manifest_sha256="test-only")
    plans = [p for p in IncidentOrchestrator(store, engine, {}).plan(scenario) if p.agent_type == "endpoint"]
    assert plans
    for plan in plans:
        limits = task_limits(Limits(), plan)
        request = InvestigationRequest(scenario_id=scenario, start_utc=plan.start_utc,
            end_utc=plan.end_utc, seed_evidence_ids=plan.seed_evidence_ids)
        result = investigate(request, CorpusEndpointProvider(store, limits), FakeLLM(), limits)
        assert result.status == "completed", (plan.task_id, result.error_code)
        expected = store.query(scenario, plan.start_utc, plan.end_utc,
            channels=(SYSMON_CHANNEL,), event_ids=ENDPOINT_EVENT_IDS, limit=1000)
        assert not expected.truncated
        assert [f.observed_events.evidence_id for f in result.findings] == [e.evidence_id for e in expected.events]
        assert result.metadata.window_coverage_complete and not result.metadata.truncated
        viewed = [fid for b in result.metadata.context_batches for fid in b.observation_ids]
        assert viewed == [f.finding_id for f in result.findings]


@pytest.mark.parametrize("scenario,start,end,count", [
    ("S02", "2026-09-21T02:07:26.6017385Z", "2026-09-21T02:07:35.2471628Z", 125),
    ("S03", "2026-09-21T02:26:50.1893142Z", "2026-09-21T02:26:56.3601178Z", 117),
])
def test_formerly_unresolved_windows_fit_shared_8192_profile(endpoint_corpus, scenario, start, end, count):
    from endpoint_agent.tests.test_context import ReviewingLLM

    _, store = endpoint_corpus
    llm = ReviewingLLM()
    request = InvestigationRequest(scenario_id=scenario, start_utc=start, end_utc=end)
    result = investigate(request, CorpusEndpointProvider(store), llm)
    assert result.status == "completed", result.error_code
    assert len(result.findings) == count == result.metadata.evidence_readbacks
    assert result.metadata.window_coverage_complete and not result.metadata.truncated
    expected = store.query(scenario, start, end, channels=(SYSMON_CHANNEL,), event_ids=ENDPOINT_EVENT_IDS, limit=1000)
    assert [f.observed_events.evidence_id for f in result.findings] == [e.evidence_id for e in expected.events]
    assert all(b.input_token_upper_bound + 2048 <= 8192 for b in result.metadata.context_batches)
