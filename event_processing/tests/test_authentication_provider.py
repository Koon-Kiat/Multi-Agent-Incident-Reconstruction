"""T2.3: the Event Processing & Detection Engine -> Authentication Investigation Agent provider adapter.

The synthetic half runs in CI. The last test needs the real S02 export and skips in CI.
Nothing here judges what Authentication Investigation Agent concludes: the assertions are about the adapter's mapping, scope
and Authentication Investigation Agent's own bounds.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.manifest import load_scenario
from event_processing.query import EventStore
from event_processing.schema import NormalisedEvent
from event_processing.tests.conftest import real_datasets
from event_processing.tests.synthetic import SYSMON, make_event
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks, ticks_to_iso

from authentication_agent import InvestigationRequest, investigate
from authentication_agent.config import Limits
from authentication_agent.llm.fake import FakeLLM
from authentication_agent.models import AUTH_EVENT_IDS, AuthenticationEvent, InvestigationResult, QueryRequest, QueryResult, evidence_id_for
from authentication_agent.queries.interface import AuthenticationEventProvider

BASE = iso_to_ticks("2026-09-21T02:05:30.0000000Z")
SCENARIO = "SYN-B"


def at(seconds: int) -> str:
    return ticks_to_iso(BASE + seconds * TICKS_PER_SECOND)


def events() -> tuple[NormalisedEvent, ...]:
    """Three authentication events, an unrelated Security event and a Sysmon event."""
    return (
        make_event(
            record_id=1,
            event_id=4624,
            timestamp_ticks=BASE,
            user="alice",
            host="LAB-A",
            event_data={"TargetUserName": "alice", "LogonType": "10", "IpAddress": "10.0.0.5"},
        ),
        make_event(
            record_id=2,
            event_id=4625,
            timestamp_ticks=BASE + 10 * TICKS_PER_SECOND,
            user="bob",
            host="LAB-A",
            event_data={"TargetUserName": "bob"},
        ),
        make_event(
            record_id=3,
            event_id=4624,
            timestamp_ticks=BASE + 20 * TICKS_PER_SECOND,
            user="alice",
            host="LAB-B",
            event_data={"TargetUserName": "alice"},
        ),
        make_event(record_id=4, event_id=4688, timestamp_ticks=BASE + 30 * TICKS_PER_SECOND, event_data={}),
        make_event(record_id=5, channel=SYSMON, event_id=1, timestamp_ticks=BASE + 40 * TICKS_PER_SECOND),
    )


@pytest.fixture
def provider() -> CorpusAuthenticationProvider:
    return CorpusAuthenticationProvider(EventStore(events()))


def request(**overrides) -> QueryRequest:
    fields = {"scenario_id": SCENARIO, "start_utc": at(0), "end_utc": at(60)}
    fields.update(overrides)
    return QueryRequest(**fields)


def test_get_event_maps_every_field_exactly(provider: CorpusAuthenticationProvider):
    event = provider.get_event("SYN-B-SEC-1")
    assert event is not None
    assert (event.evidence_id, event.record_id, event.source_event_id) == ("SYN-B-SEC-1", 1, 4624)
    assert (event.scenario_id, event.source_type, event.channel) == ("SYN-B", "windows_security", "Security")
    assert event.timestamp_utc == at(0)
    assert (event.host, event.user) == ("LAB-A", "alice")
    assert event.event_data == {"TargetUserName": "alice", "LogonType": "10", "IpAddress": "10.0.0.5"}
    assert event.raw_reference == "evtx://datasets/SYN-B/raw/Security.evtx#EventRecordID=1"
    assert event.evidence_id == evidence_id_for("SYN-B", 1)


def test_get_event_preserves_any_security_record_and_refuses_other_channels(provider: CorpusAuthenticationProvider):
    # B15 corrected this expectation: Authentication Investigation Agent's contract fixture looks up a Security 4634 and requires
    # it back unchanged, so exact lookup preserves any Security record (the Event ID is not
    # filtered); `query`, below, stays restricted to 4624/4625.
    assert provider.get_event("SYN-B-SEC-99") is None  # well formed, absent
    assert provider.get_event("not-an-id") is None  # malformed
    preserved = provider.get_event("SYN-B-SEC-4")  # Security 4688
    assert preserved is not None and preserved.source_event_id == 4688
    assert provider.get_event("SYN-B-SYS-5") is None  # Sysmon 1 is outside Authentication Investigation Agent's Security-only model
    assert provider.get_event("SYN-A-SEC-1") is None  # another scenario


def test_query_returns_only_authentication_events_in_authentication_order(provider: CorpusAuthenticationProvider):
    result = provider.query(request())
    assert [event.evidence_id for event in result.events] == ["SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3"]
    assert isinstance(result, QueryResult)
    assert result.truncated is False
    assert all(isinstance(event, AuthenticationEvent) for event in result.events)


def test_query_filters_on_account_event_ids_host_and_limit(provider: CorpusAuthenticationProvider):
    assert [e.evidence_id for e in provider.query(request(account="alice")).events] == ["SYN-B-SEC-1", "SYN-B-SEC-3"]
    assert [e.evidence_id for e in provider.query(request(event_ids=(4625,))).events] == ["SYN-B-SEC-2"]
    assert [e.evidence_id for e in provider.query(request(host="LAB-B")).events] == ["SYN-B-SEC-3"]
    limited = provider.query(request(limit=2))
    assert [e.evidence_id for e in limited.events] == ["SYN-B-SEC-1", "SYN-B-SEC-2"]
    assert limited.truncated is True


def test_query_uses_authentication_bounds_instead_of_clamping(provider: CorpusAuthenticationProvider):
    with pytest.raises(ValueError, match="maximum time window"):
        provider.query(request(start_utc=at(0), end_utc=at(7200)))
    with pytest.raises(ValueError, match="maximum result count"):
        provider.query(request(limit=101))


def test_query_honours_configured_limits():
    tight = CorpusAuthenticationProvider(EventStore(events()), Limits(max_events_per_query=1))
    result = tight.query(request(limit=1))
    assert [event.evidence_id for event in result.events] == ["SYN-B-SEC-1"]
    assert result.truncated is True
    with pytest.raises(ValueError, match="maximum result count"):
        tight.query(request(limit=2))


def test_an_unknown_scenario_is_an_empty_result(provider: CorpusAuthenticationProvider):
    result = provider.query(request(scenario_id="SYN-Z"))
    assert result.events == ()
    assert result.truncated is False


def test_returned_events_do_not_share_state_with_the_store(provider: CorpusAuthenticationProvider):
    event = provider.get_event("SYN-B-SEC-1")
    assert event is not None
    event.event_data["TargetUserName"] = "mallory"
    assert provider.get_event("SYN-B-SEC-1").event_data["TargetUserName"] == "alice"


def test_the_adapter_satisfies_the_authentication_provider_protocol(provider: CorpusAuthenticationProvider):
    def consume(candidate: AuthenticationEventProvider) -> tuple[AuthenticationEvent | None, QueryResult]:
        return candidate.get_event("SYN-B-SEC-1"), candidate.query(request())

    event, result = consume(provider)
    assert event is not None and event.evidence_id == "SYN-B-SEC-1"
    assert result.events[0].evidence_id == "SYN-B-SEC-1"


# --- real evidence ------------------------------------------------------------------


def test_the_real_s02_window_runs_through_authentication(real_corpus_dir: Path):
    """A real window from S02's own metadata drives a full Authentication Investigation Agent investigation."""
    datasets = real_datasets()
    info = load_scenario(datasets / "S02")
    store = EventStore.load(real_corpus_dir)
    investigation = InvestigationRequest(
        scenario_id="S02",
        start_utc=ticks_to_iso(info.window_start_ticks),
        end_utc=ticks_to_iso(info.window_end_ticks),
    )

    result = investigate(investigation, CorpusAuthenticationProvider(store), FakeLLM())

    # Validates the exact envelope Incident Reconstruction Orchestrator will consume, without asserting what Authentication Investigation Agent concluded.
    assert InvestigationResult.model_validate_json(result.model_dump_json()) == result
    assert result.status == "completed"
    for finding in result.findings:
        assert finding.evidence_ids
        for evidence_id in finding.evidence_ids:
            found = store.lookup(evidence_id)
            assert found.status == "found"
            assert found.event.scenario_id == "S02"
            assert info.window_start_ticks <= found.event.timestamp_ticks <= info.window_end_ticks
    # The provider can only ever offer authentication events it really holds.
    provider = CorpusAuthenticationProvider(store)
    logon = provider.get_event("S02-SEC-43584")
    assert logon is not None and logon.source_event_id == 4624

    # And it must really offer the window's authentication events: a provider whose real-data
    # query regressed to nothing would still let the investigation above finish with no findings.
    window = (ticks_to_iso(info.window_start_ticks), ticks_to_iso(info.window_end_ticks))
    offered = provider.query(QueryRequest(scenario_id="S02", start_utc=window[0], end_utc=window[1]))
    expected = store.query("S02", *window, channels=("Security",), event_ids=(4624, 4625), limit=store.limits.max_limit)
    assert offered.events
    assert [event.evidence_id for event in offered.events] == [event.evidence_id for event in expected.events]
    assert all(event.source_event_id in AUTH_EVENT_IDS for event in offered.events)
