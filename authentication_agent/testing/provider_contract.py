"""Reusable pytest contract for an isolated provider loaded with synthetic events.

Subclass AuthenticationProviderContract and provide a ``provider_factory`` fixture
accepting (events, limits). The factory must create an isolated test store; never
point these mutation-isolation checks at a production or public evidence index.
"""

from importlib.resources import files

import pytest
from pydantic import TypeAdapter

from authentication_agent.config import Limits
from authentication_agent.models import AuthenticationEvent, QueryRequest, utc_ticks


def synthetic_contract_events() -> tuple[AuthenticationEvent, ...]:
    return TypeAdapter(tuple[AuthenticationEvent, ...]).validate_json(
        files("authentication_agent").joinpath("fixtures/synthetic_events.json").read_text(encoding="utf-8")
    )


def contract_query(**changes) -> QueryRequest:
    return QueryRequest(**{
        "scenario_id": "SYN-A", "start_utc": "2026-01-10T00:00:00Z",
        "end_utc": "2026-01-10T00:01:00Z", **changes,
    })


class AuthenticationProviderContract:
    """AUTH-facing semantics only; Event Processing & Detection Engine may adapt its agreed schema internally."""

    @pytest.fixture
    def contract_provider(self, provider_factory):
        return provider_factory(synthetic_contract_events(), Limits())

    def test_exact_lookup_preserves_every_original_field(self, contract_provider):
        for original in synthetic_contract_events():
            returned = contract_provider.get_event(original.evidence_id)
            assert returned is not None
            assert returned.model_dump(mode="json") == original.model_dump(mode="json")

    def test_unknown_ids_never_fuzzy_match(self, contract_provider):
        for evidence_id in ("42", "SYN-A-SEC-999", "syn-a-sec-1", "SYN-A-SYS-1"):
            assert contract_provider.get_event(evidence_id) is None

    def test_scope_and_authentication_filter(self, contract_provider):
        events = contract_provider.query(contract_query()).events
        assert [event.evidence_id for event in events] == [f"SYN-A-SEC-{i}" for i in range(1, 5)]
        assert all(event.scenario_id == "SYN-A" and event.channel == "Security" for event in events)
        successes = contract_provider.query(contract_query(event_ids=(4624,))).events
        assert [event.evidence_id for event in successes] == ["SYN-A-SEC-4"]

    def test_account_and_host_filters_are_exact(self, contract_provider):
        events = contract_provider.query(contract_query(account="demo.user", host="LAB-A")).events
        assert len(events) == 4
        assert not contract_provider.query(contract_query(account="DEMO.USER")).events
        assert not contract_provider.query(contract_query(host="LAB-B")).events
        empty_account = contract_provider.query(contract_query(scenario_id="SYN-F", account="")).events
        assert [event.evidence_id for event in empty_account] == ["SYN-F-SEC-2"]

    def test_window_is_half_open_at_full_precision(self, contract_provider):
        result = contract_provider.query(contract_query(
            scenario_id="SYN-I", start_utc="2026-01-10T00:00:01.1234567Z",
            end_utc="2026-01-10T00:00:01.1234568Z"))
        assert [event.evidence_id for event in result.events] == ["SYN-I-SEC-2"]

    def test_same_record_id_in_different_scenarios(self, contract_provider):
        first = contract_provider.get_event("SYN-H1-SEC-42")
        second = contract_provider.get_event("SYN-H2-SEC-42")
        assert first.record_id == second.record_id == 42
        assert first.evidence_id != second.evidence_id
        assert first.source_event_id == 4625 and second.source_event_id == 4624

    def test_deterministic_submillisecond_order(self, contract_provider):
        query = contract_query(scenario_id="SYN-I")
        first = contract_provider.query(query)
        assert first == contract_provider.query(query)
        assert [event.record_id for event in first.events] == [3, 2, 1]
        assert utc_ticks(first.events[2].timestamp_utc) - utc_ticks(first.events[1].timestamp_utc) == 1

    def test_equal_timestamps_use_evidence_id(self, provider_factory):
        events = [event.model_copy(update={"timestamp_utc": "2026-01-10T00:00:01Z"})
                  for event in synthetic_contract_events() if event.scenario_id == "SYN-A"]
        provider = provider_factory(tuple(reversed(events)), Limits())
        ids = [event.evidence_id for event in provider.query(contract_query()).events]
        assert ids == sorted(ids)

    def test_empty_results_and_explicit_truncation(self, contract_provider):
        empty = contract_provider.query(contract_query(scenario_id="SYN-E"))
        assert empty.events == () and empty.truncated is False
        short = contract_provider.query(contract_query(limit=2))
        assert len(short.events) == 2 and short.truncated is True
        complete = contract_provider.query(contract_query(limit=4))
        assert len(complete.events) == 4 and complete.truncated is False

    def test_provider_enforces_configured_limits(self, provider_factory):
        provider = provider_factory(synthetic_contract_events(), Limits(max_events_per_query=2, max_window_seconds=60))
        assert len(provider.query(contract_query(limit=2)).events) == 2
        with pytest.raises(ValueError):
            provider.query(contract_query(limit=3))
        with pytest.raises(ValueError):
            provider.query(contract_query(limit=2, end_utc="2026-01-10T00:01:00.0000001Z"))

    def test_input_and_returned_records_cannot_mutate_store(self, provider_factory):
        original = synthetic_contract_events()[0]
        original.event_data["contract_nested"] = {"values": [1]}
        provider = provider_factory((original,), Limits())
        original.event_data["contract_nested"]["values"].append(2)
        returned = provider.get_event(original.evidence_id)
        returned.event_data["contract_nested"]["values"].append(3)
        queried = provider.query(contract_query()).events[0]
        queried.event_data["contract_nested"]["values"].append(4)
        assert provider.get_event(original.evidence_id).event_data["contract_nested"] == {"values": [1]}

    def test_missing_and_empty_fields_are_preserved(self, contract_provider):
        missing = contract_provider.get_event("SYN-F-SEC-1")
        empty = contract_provider.get_event("SYN-F-SEC-2")
        assert missing.user is None and missing.host is None and missing.event_data == {}
        assert empty.user == "" and empty.host == ""
