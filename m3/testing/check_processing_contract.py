"""Unchanged generic provider contract, explicitly invoked as a compatibility diagnostic.

This intentionally probes a wider domain than the EVTX schema accepts. Generic
fixtures contain integer/null/nested fields, noncanonical timestamp strings and
a non-logon Security event. Unchecked *test-only* NormalisedEvent construction
lets the original assertions reach the actual EventStore/adapter, without
coercing fixtures, filtering cases, or weakening assertions. It is NOT a way to
load a production corpus. Supported-schema/real-corpus tests live in
tests/test_authentication_corpus.py. Known failures remain failures here.
"""

from copy import deepcopy

import pytest

from m2.adapters.m3_provider import M2AuthenticationProvider
from m2.query import EventStore
from m2.schema import NormalisedEvent
from m2.tests.synthetic import make_event
from m3.models import utc_ticks
from m3.testing.provider_contract import AuthenticationProviderContract


class TestProcessingProviderContract(AuthenticationProviderContract):
    @pytest.fixture
    def provider_factory(self):
        def build(events, limits):
            records = [NormalisedEvent.model_construct(
                **deepcopy(event.model_dump()), timestamp_ticks=utc_ticks(event.timestamp_utc),
                source_sha256="0" * 64, raw_xml="<test-only/>", in_scenario_window=True,
            ) for event in events]
            return M2AuthenticationProvider(EventStore(records), limits)
        return build


def test_constructor_snapshot_detaches_supported_input():
    """Focused regression proposal: constructor callers retain a mutable dict."""
    original = make_event(event_id=4624, event_data={"TargetUserName": "original"})
    store = EventStore([original])
    original.event_data["TargetUserName"] = "caller mutation"
    assert store.lookup(original.evidence_id).event.event_data["TargetUserName"] == "original"
