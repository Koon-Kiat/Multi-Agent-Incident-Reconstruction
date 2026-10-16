import pytest

from authentication_agent.config import Limits
from authentication_agent.llm.fake import FakeLLM as AuthenticationFake
from endpoint_agent.llm.fake import FakeLLM as EndpointFake
from event_processing.detection.rules import RULES
from event_processing.detection.schema import Detection, make_detection_id
from event_processing.query import EventStore
from event_processing.tests.synthetic import SECURITY, SYSMON, make_event
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks, ticks_to_iso
from incident_reconstruction.orchestrator import corpus_investigators

SCENARIO = "SYN-ORCH"
BASE = iso_to_ticks("2026-09-21T02:05:00.0000000Z")
HOST = "LAB-A"
USER = "LAB-A\\analyst"
ROOT = "{00000001-aaaa-bbbb-cccc-000000000001}"
CHILD = "{00000002-aaaa-bbbb-cccc-000000000002}"


def at(second: float) -> int:
    return BASE + int(second * TICKS_PER_SECOND)


def security(record_id, second, event_id, **data):
    return make_event(scenario_id=SCENARIO, channel=SECURITY, record_id=record_id, event_id=event_id,
                      timestamp_ticks=at(second), host=HOST, user=USER,
                      event_data={"TargetUserName": "analyst", "LogonType": "3", **data})


def sysmon(record_id, second, event_id=1, **data):
    return make_event(scenario_id=SCENARIO, channel=SYSMON, record_id=record_id, event_id=event_id,
                      timestamp_ticks=at(second), host=HOST, user=USER, event_data=data)


RULE_TECHNIQUES = {rule.spec.rule_id: rule.spec.attack_technique for rule in RULES}


def detection(rule_id, *events, severity="low"):
    ordered = sorted(events, key=lambda event: (event.timestamp_ticks, event.evidence_id))
    return Detection(
        attack_technique=RULE_TECHNIQUES.get(rule_id),
        detection_id=make_detection_id(SCENARIO, rule_id, ordered[-1].evidence_id),
        rule_id=rule_id, rule_version="1", scenario_id=SCENARIO,
        trigger_evidence_ids=tuple(event.evidence_id for event in ordered),
        window_start_utc=ticks_to_iso(ordered[0].timestamp_ticks),
        window_end_utc=ticks_to_iso(ordered[-1].timestamp_ticks),
        severity=severity, rationale="synthetic",
    )


class StubEngine:
    """The two members of DetectionEngine the orchestrator uses, over fixed detections."""

    corpus_manifest_sha256 = "0" * 64

    def __init__(self, detections):
        self._detections = tuple(detections)

    def triggers_for(self, scenario_id):
        return tuple(sorted((d for d in self._detections if d.scenario_id == scenario_id),
                            key=lambda d: (d.window_start_utc, d.detection_id)))


@pytest.fixture
def events():
    return {
        "fail1": security(10, 0, 4625),
        "fail2": security(11, 1, 4625),
        "success": security(12, 2, 4624),
        "explicit": security(13, 3, 4648),
        "process_parent": sysmon(20, 4, ProcessGuid=ROOT, ProcessId="100", Image="C:\\Windows\\explorer.exe", User=USER),
        "process_child": sysmon(21, 5, ProcessGuid=CHILD, ProcessId="200", User=USER,
                                Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd.exe /c whoami",
                                ParentProcessGuid=ROOT, ParentProcessId="100", ParentImage="C:\\Windows\\explorer.exe"),
        "file": sysmon(22, 6, event_id=11, ProcessGuid=CHILD, ProcessId="200", Image="C:\\Windows\\System32\\cmd.exe",
                       TargetFilename="C:\\Users\\analyst\\AppData\\Local\\Temp\\a.ps1", User=USER),
        "late_process": sysmon(30, 900, ProcessGuid=CHILD, ProcessId="300", Image="C:\\Windows\\System32\\whoami.exe", User=USER),
    }


@pytest.fixture
def store(events):
    return EventStore(events.values())


@pytest.fixture
def detections(events):
    return (
        detection("R-AUTH-01", events["fail1"], events["fail2"], events["success"], severity="high"),
        detection("R-AUTH-03", events["explicit"]),
        detection("R-EXEC-01", events["process_child"]),
        detection("R-FILE-01", events["file"], severity="medium"),
        detection("R-EXEC-01", events["late_process"]),
    )


@pytest.fixture
def engine(detections):
    return StubEngine(detections)


@pytest.fixture
def investigators(store):
    return corpus_investigators(store, authentication_llm=AuthenticationFake(), endpoint_llm=EndpointFake(),
                                limits=Limits())
