import pytest
from pydantic import ValidationError

from m3.config import Limits
from m3.models import QueryRequest, ToolCall
from m3.queries.in_memory import InMemoryAuthenticationEventProvider
from m3.queries.tools import AuthenticationTools


def test_authentication_filtering(provider, query_a):
    assert [e.source_event_id for e in provider.query(query_a).events] == [4625, 4625, 4625, 4624]
    only_success = QueryRequest(**{**query_a.model_dump(), "event_ids": (4624,)})
    assert [e.evidence_id for e in provider.query(only_success).events] == ["SYN-A-SEC-4"]


def test_account_host_filters(provider, query_a):
    assert len(provider.query(QueryRequest(**{**query_a.model_dump(), "account": "demo.user", "host": "LAB-A"})).events) == 4
    for field, value in [("account", "DEMO.USER"), ("host", "LAB-B"), ("account", "")]:
        assert not provider.query(QueryRequest(**{**query_a.model_dump(), field: value})).events


def test_window_is_half_open(provider, query_a):
    result = provider.query(QueryRequest(**{**query_a.model_dump(), "start_utc": "2026-01-10T00:00:02.0000001Z", "end_utc": "2026-01-10T00:00:03.0000001Z"}))
    assert [e.record_id for e in result.events] == [2]


def test_submillisecond_order(provider, query_a):
    result = provider.query(QueryRequest(**{**query_a.model_dump(), "scenario_id": "SYN-I"}))
    assert [e.record_id for e in result.events] == [3, 2, 1]


def test_ties_use_evidence_id_and_input_order_is_irrelevant(provider, query_a):
    events = [e.model_copy(update={"timestamp_utc": "2026-01-10T00:00:01Z"}) for e in provider.query(query_a).events]
    first = InMemoryAuthenticationEventProvider(reversed(events)).query(query_a)
    second = InMemoryAuthenticationEventProvider(events).query(query_a)
    assert first == second
    assert [e.evidence_id for e in first.events] == sorted(e.evidence_id for e in events)


def test_id_uniqueness_and_not_found(provider):
    assert provider.get_event("SYN-H1-SEC-42").source_event_id == 4625
    assert provider.get_event("SYN-H2-SEC-42").source_event_id == 4624
    for unknown in ("42", "SYN-H1-SEC-43", "syn-h1-sec-42", "SYN-G-SEC-999"):
        assert provider.get_event(unknown) is None
    event = provider.get_event("SYN-H1-SEC-42")
    with pytest.raises(ValueError, match="duplicate"):
        InMemoryAuthenticationEventProvider([event, event])


def test_empty_window(provider, query_a):
    assert provider.query(QueryRequest(**{**query_a.model_dump(), "scenario_id": "SYN-E"})).events == ()


def test_result_limit_and_time_limit(provider, query_a):
    result = provider.query(QueryRequest(**{**query_a.model_dump(), "limit": 2}))
    assert len(result.events) == 2 and result.truncated
    with pytest.raises(ValueError):
        provider.query(QueryRequest(**{**query_a.model_dump(), "limit": 101}))
    with pytest.raises(ValueError):
        provider.query(QueryRequest(**{**query_a.model_dump(), "end_utc": "2026-01-10T02:00:00Z"}))


def test_queries_require_scope_and_auth_ids(query_a):
    with pytest.raises(ValidationError):
        QueryRequest(start_utc=query_a.start_utc, end_utc=query_a.end_utc)
    with pytest.raises(ValidationError):
        QueryRequest(**{**query_a.model_dump(), "event_ids": (4688,)})


def test_read_only_deep_copies(provider, query_a):
    event = provider.get_event("SYN-A-SEC-1")
    event.event_data["nested"] = {"value": [1]}
    isolated = InMemoryAuthenticationEventProvider([event])
    event.event_data["nested"]["value"].append(2)
    returned = isolated.query(query_a).events[0]
    returned.event_data["nested"]["value"].append(3)
    assert isolated.get_event(event.evidence_id).event_data["nested"] == {"value": [1]}
    assert "nested" not in provider.get_event(event.evidence_id).event_data


def test_account_history_and_unknown_tool_lookup(provider, request_a):
    tools = AuthenticationTools(request_a, provider, Limits())
    output = tools.execute(ToolCall(name="get_account_authentication_history", arguments={**request_a.model_dump(), "account": "demo.user"}))
    assert len(output["evidence_ids"]) == 4
    assert tools.execute(ToolCall(name="get_authentication_event", arguments={"evidence_id": "SYN-A-SEC-999"})) == {"found": False, "evidence_id": "SYN-A-SEC-999"}
