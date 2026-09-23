"""Unchanged generic provider contract, explicitly invoked as a compatibility diagnostic.

This intentionally probes a wider domain than the EVTX schema accepts. Generic
fixtures contain integer/null/nested fields, noncanonical timestamp strings and
a non-logon Security event. Unchecked *test-only* NormalisedEvent construction
lets the original assertions reach the actual EventStore/adapter, without
coercing fixtures, filtering cases, or weakening assertions. It is NOT a way to
load a production corpus. Supported-schema/real-corpus tests live in
tests/test_authentication_corpus.py. PR #10 resolved the original lookup and
constructor-ownership failures; this diagnostic retains the original assertions.
"""

from copy import deepcopy

import pytest

from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.query import EventStore
from event_processing.schema import NormalisedEvent
from event_processing.tests.synthetic import make_event
from authentication_agent.models import utc_ticks
from authentication_agent.testing.provider_contract import AuthenticationProviderContract


class TestProcessingProviderContract(AuthenticationProviderContract):
    @pytest.fixture
    def provider_factory(self):
        def build(events, limits):
            records = [NormalisedEvent.model_construct(
                **deepcopy(event.model_dump()), timestamp_ticks=utc_ticks(event.timestamp_utc),
                source_sha256="0" * 64, raw_xml="<test-only/>", in_scenario_window=True,
            ) for event in events]
            return CorpusAuthenticationProvider(EventStore(records), limits)
        return build


def test_constructor_snapshot_detaches_supported_input():
    """Regression for the constructor ownership fix inherited from PR #10."""
    original = make_event(event_id=4624, event_data={"TargetUserName": "original"})
    store = EventStore([original])
    original.event_data["TargetUserName"] = "caller mutation"
    assert store.lookup(original.evidence_id).event.event_data["TargetUserName"] == "original"
