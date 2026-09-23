"""B15: M3's reusable provider contract, run against :class:`M2AuthenticationProvider`.

``m3.testing.provider_contract.AuthenticationProviderContract`` is M3's own backend-independent
conformance suite. This module supplies the one fixture it needs — a factory that turns the
supplied ``AuthenticationEvent`` tuple into an isolated in-memory :class:`~m2.query.EventStore`
wrapped in M2's adapter — so the same twelve checks that guard M3's in-memory provider also guard
the adapter M3 will actually use.

The factory never touches ``datasets/`` or a written corpus: it builds the store from exactly the
events it is handed, so the check stays a pure interface test. M3's fixture carries event values
that are not strings (an integer ``LogonType``, a ``null`` and a nested object), which M2's
``event_data: dict[str, str]`` cannot represent for a real EVTX record but must still pass through
the adapter unchanged. The store is therefore built with ``model_construct`` — the events are
created from M3's own already-validated models, not from untrusted JSON, and the adapter contract
is about mapping, not about re-validating M2's schema.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from m3.config import Limits
from m3.models import AuthenticationEvent
from m3.testing.provider_contract import AuthenticationProviderContract

from m2.adapters.m3_provider import M2AuthenticationProvider
from m2.query import EventStore
from m2.schema import CHANNEL_SOURCE_TYPES, NormalisedEvent
from m2.timeutil import iso_to_ticks

_SOURCE_SHA256 = "D396CE599723189331D440EDD55CC055C28EB4B6AD45A421D07A8E83A2F0EBA7"


def _normalised(event: AuthenticationEvent) -> NormalisedEvent:
    """The M2 view of one M3 fixture event, for the isolated test store only."""
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


def make_m2_test_adapter(
    events: Iterable[AuthenticationEvent], limits: Limits
) -> M2AuthenticationProvider:
    """An M2 adapter over an isolated store holding only ``events`` and honouring ``limits``."""
    return M2AuthenticationProvider(EventStore(_normalised(event) for event in events), limits)


class TestM2AuthenticationProviderContract(AuthenticationProviderContract):
    """M2's adapter must satisfy every check M3's in-memory provider satisfies."""

    @pytest.fixture
    def provider_factory(self):
        return make_m2_test_adapter


def test_the_contract_fixture_is_not_empty_and_covers_a_non_authentication_event():
    # Guards the module itself: if M3's fixture lost these, the suite above could pass vacuously.
    from m3.testing.provider_contract import synthetic_contract_events

    events = synthetic_contract_events()
    assert len(events) >= 12
    assert any(event.source_event_id not in (4624, 4625) for event in events)
