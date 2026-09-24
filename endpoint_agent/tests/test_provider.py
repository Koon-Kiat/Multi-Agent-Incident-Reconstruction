import pytest
from pydantic import ValidationError

from endpoint_agent.config import Limits
from endpoint_agent.models import InvestigationRequest, QueryRequest
from endpoint_agent.tests.conftest import BASE, CHILD, HOST, ROOT, USER, endpoint_event
from event_processing.adapters.endpoint_provider import CorpusEndpointProvider
from event_processing.query import EventStore, QueryLimits
from event_processing.tests.synthetic import make_event
from event_processing.timeutil import ticks_to_iso


def test_provider_retains_every_source_field_and_detaches_copies(events, provider, investigation):
    result = provider.query(QueryRequest(**investigation.window()))
    assert result.events == tuple(events)
    assert (result.total_matched, result.truncated) == (5, False)
    for original in events:
        returned = provider.get_event(original.evidence_id)
        assert returned == original
        returned.event_data["Image"] = "caller change"
        assert provider.get_event(original.evidence_id) == original


def test_filtering_precedes_limiting_and_matches_process_access_source(provider, investigation):
    result = provider.query(QueryRequest(**investigation.window(), process_guid=CHILD, limit=2))
    assert [e.record_id for e in result.events] == [2, 3]
    assert (result.total_matched, result.truncated) == (4, True)
    access = provider.query(QueryRequest(**investigation.window(), process_guid=CHILD, event_ids=(10,)))
    assert [e.record_id for e in access.events] == [4]
    assert [e.record_id for e in provider.query(QueryRequest(**investigation.window(), parent_process_guid=ROOT)).events] == [2]


@pytest.mark.parametrize("filters,expected", [
    ({"host": HOST}, 5), ({"host": HOST.lower()}, 0), ({"account": USER}, 5),
    ({"account": USER.lower()}, 0), ({"process_guid": CHILD.upper()}, 0),
    ({"event_ids": (1,)}, 2), ({"account": ""}, 0), ({"host": ""}, 0),
])
def test_exact_filter_semantics(provider, investigation, filters, expected):
    assert provider.query(QueryRequest(**investigation.window(), **filters)).total_matched == expected


def test_half_open_ticks_ties_and_scenario_collisions(investigation):
    records = [endpoint_event(2, ProcessGuid=ROOT), endpoint_event(1, ProcessGuid=CHILD),
               endpoint_event(1, scenario="OTHER", ProcessGuid=ROOT)]
    provider = CorpusEndpointProvider(EventStore(records))
    request = QueryRequest(**{**investigation.window(), "start_utc": ticks_to_iso(BASE),
                             "end_utc": ticks_to_iso(BASE + 1)})
    assert [e.evidence_id for e in provider.query(request).events] == ["SYN-ENDPOINT-SYS-1", "SYN-ENDPOINT-SYS-2"]
    assert provider.get_event("OTHER-SYS-1").scenario_id == "OTHER"
    before = request.model_copy(update={"start_utc": ticks_to_iso(BASE - 1), "end_utc": ticks_to_iso(BASE)})
    assert not provider.query(before).events


def test_exact_lookup_semantics_and_channel_boundary(events, investigation):
    other_type = endpoint_event(77, event_id=3, ProcessGuid=ROOT)
    security = make_event(scenario_id=investigation.scenario_id, record_id=99, event_id=4624)
    provider = CorpusEndpointProvider(EventStore([*events, other_type, security]))
    assert provider.get_event(other_type.evidence_id) == other_type
    assert provider.get_event(security.evidence_id) is None
    assert provider.get_event("SYN-ENDPOINT-SYS-999") is None
    assert provider.get_event("SYN-ENDPOINT-SYS-01") is None
    assert {e.source_event_id for e in provider.query(QueryRequest(**investigation.window())).events} == {1, 10, 11, 13}


def test_empty_and_null_values_remain_distinct(investigation):
    provider = CorpusEndpointProvider(EventStore([endpoint_event(1, user="", host=""),
                                                 endpoint_event(2, user=None, host=None)]))
    assert len(provider.query(QueryRequest(**investigation.window())).events) == 2
    assert [e.record_id for e in provider.query(QueryRequest(**investigation.window(), account="", host="")).events] == [1]


def test_both_provider_and_store_limits_apply(events, investigation):
    query = QueryRequest(**investigation.window(), limit=2)
    for provider in (CorpusEndpointProvider(EventStore(events), Limits(max_events_per_query=1)),
                     CorpusEndpointProvider(EventStore(events, limits=QueryLimits(max_limit=1))),
                     CorpusEndpointProvider(EventStore(events), Limits(max_window_seconds=1)),
                     CorpusEndpointProvider(EventStore(events, limits=QueryLimits(max_window_seconds=1)))):
        with pytest.raises(ValueError):
            provider.query(query)


@pytest.mark.parametrize("changes", [
    {"event_ids": (4624,)}, {"event_ids": ()}, {"event_ids": (True,)}, {"event_ids": (1.0,)},
    {"limit": 0}, {"limit": True},
    {"start_utc": "2026-09-21T02:05:00+08:00"}, {"end_utc": "2026-09-21T02:05:00Z"},
    {"start_utc": "2026-09-21T02:05:00.12345678Z"}, {"extra": "typo"},
])
def test_invalid_query_contracts_fail(investigation, changes):
    with pytest.raises(ValidationError):
        QueryRequest(**{**investigation.window(), **changes})


@pytest.mark.parametrize("ids", [("OTHER-SYS-1",), ("SYN-ENDPOINT-SEC-1",),
                                ("SYN-ENDPOINT-SYS-01",), ("SYN-ENDPOINT-SYS-1",) * 2])
def test_seed_contract(investigation, ids):
    with pytest.raises(ValidationError):
        InvestigationRequest(**investigation.window(), seed_evidence_ids=ids)
