"""B15: Authentication Investigation Agent's reusable provider contract, run against :class:`CorpusAuthenticationProvider`.

``authentication_agent.testing.provider_contract.AuthenticationProviderContract`` is Authentication Investigation Agent's own backend-independent
conformance suite. This module supplies the one fixture it needs — a factory that turns the
supplied ``AuthenticationEvent`` tuple into an isolated in-memory :class:`~event_processing.query.EventStore`
wrapped in Event Processing & Detection Engine's adapter — so the same twelve checks that guard Authentication Investigation Agent's in-memory provider also guard
the adapter Authentication Investigation Agent will actually use.

The factory never touches ``datasets/`` or a written corpus: it builds the store from exactly the
events it is handed, so the check stays a pure interface test. Authentication Investigation Agent's fixture carries event values
that are not strings (an integer ``LogonType``, a ``null`` and a nested object), which Event Processing & Detection Engine's
``event_data: dict[str, str]`` cannot represent for a real EVTX record but must still pass through
the adapter unchanged. The store is therefore built with ``model_construct`` — the events are
created from Authentication Investigation Agent's own already-validated models, not from untrusted JSON, and the adapter contract
is about mapping, not about re-validating Event Processing & Detection Engine's schema.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from authentication_agent.config import Limits
from authentication_agent.models import AuthenticationEvent
from authentication_agent.testing.provider_contract import AuthenticationProviderContract

from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.query import EventStore
from event_processing.schema import CHANNEL_SOURCE_TYPES, NormalisedEvent
from event_processing.timeutil import iso_to_ticks

_SOURCE_SHA256 = "D396CE599723189331D440EDD55CC055C28EB4B6AD45A421D07A8E83A2F0EBA7"


def _normalised(event: AuthenticationEvent) -> NormalisedEvent:
    """The Event Processing & Detection Engine view of one Authentication Investigation Agent fixture event, for the isolated test store only."""
    return NormalisedEvent.model_construct(
        evidence_id=event.evidence_id,
        scenario_id=event.scenario_id,
        channel=event.channel,
        source_type=CHANNEL_SOURCE_TYPES[event.channel],
        record_id=event.record_id,
        source_event_id=event.source_event_id,
        timestamp_utc=event.timestamp_utc,
        timestamp_ticks=iso_to_ticks(event.timestamp_utc),
        host=event.host,
        user=event.user,
        event_data=dict(event.event_data),
        raw_reference=event.raw_reference,
        source_sha256=_SOURCE_SHA256,
        raw_xml="<Event><System><EventID>0</EventID></System></Event>",
        in_scenario_window=True,
        parse_warnings=(),
    )


def make_processing_test_adapter(
    events: Iterable[AuthenticationEvent], limits: Limits
) -> CorpusAuthenticationProvider:
    """An Event Processing & Detection Engine adapter over an isolated store holding only ``events`` and honouring ``limits``."""
    return CorpusAuthenticationProvider(EventStore(_normalised(event) for event in events), limits)


class TestCorpusAuthenticationProviderContract(AuthenticationProviderContract):
    """Event Processing & Detection Engine's adapter must satisfy every check Authentication Investigation Agent's in-memory provider satisfies."""

    @pytest.fixture
    def provider_factory(self):
        return make_processing_test_adapter


def test_the_contract_fixture_is_not_empty_and_covers_a_non_authentication_event():
    # Guards the module itself: if Authentication Investigation Agent's fixture lost these, the suite above could pass vacuously.
    from authentication_agent.testing.provider_contract import synthetic_contract_events

    events = synthetic_contract_events()
    assert len(events) >= 12
    assert any(event.source_event_id not in (4624, 4625) for event in events)
