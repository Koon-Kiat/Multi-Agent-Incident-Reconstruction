import pytest

from endpoint_agent import InvestigationRequest
from endpoint_agent.config import Limits
from event_processing.adapters.endpoint_provider import CorpusEndpointProvider
from event_processing.query import EventStore
from event_processing.tests.synthetic import SYSMON, make_event
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks

BASE = iso_to_ticks("2026-09-21T02:05:00.0000000Z")
ROOT = "{00000001-aaaa-bbbb-cccc-000000000001}"
CHILD = "{00000002-aaaa-bbbb-cccc-000000000002}"
MISSING = "{00000003-aaaa-bbbb-cccc-000000000003}"
TARGET = "{00000004-aaaa-bbbb-cccc-000000000004}"
HOST = "LAB-A"
USER = "LAB-A\\analyst"


def endpoint_event(record_id, *, second=0, event_id=1, scenario="SYN-ENDPOINT", host=HOST, user=USER, **data):
    return make_event(scenario_id=scenario, channel=SYSMON, record_id=record_id,
        event_id=event_id, timestamp_ticks=BASE + second * TICKS_PER_SECOND,
        host=host, user=user, event_data=data)


@pytest.fixture
def events():
    return [
        endpoint_event(1, ProcessGuid=ROOT, ProcessId="100", Image="C:\\Windows\\explorer.exe", User=USER),
        endpoint_event(2, second=1, ProcessGuid=CHILD, ProcessId="200",
            Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            CommandLine="powershell.exe -File inventory.ps1", User=USER,
            ParentProcessGuid=ROOT, ParentProcessId="100", ParentImage="C:\\Windows\\explorer.exe"),
        endpoint_event(3, second=2, event_id=11, ProcessGuid=CHILD, ProcessId="200",
            Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            TargetFilename="C:\\Users\\analyst\\inventory.txt", User=USER),
        endpoint_event(4, second=3, event_id=10, SourceProcessGUID=CHILD, SourceProcessId="200",
            SourceImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            TargetProcessGUID=TARGET, TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x1010"),
        endpoint_event(5, second=4, event_id=13, ProcessGuid=CHILD, ProcessId="200",
            Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            TargetObject="HKCU\\Software\\Example\\Value", Details="test", User=USER),
    ]


@pytest.fixture
def investigation():
    return InvestigationRequest(scenario_id="SYN-ENDPOINT", start_utc="2026-09-21T02:05:00Z",
                                end_utc="2026-09-21T02:06:00Z")


@pytest.fixture
def provider(events):
    return CorpusEndpointProvider(EventStore(events), Limits())
