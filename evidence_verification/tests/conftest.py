"""Synthetic scenarios and claim builders. Nothing here is real evidence or an answer key."""

from __future__ import annotations

import pytest

from event_processing.query import EventStore
from event_processing.tests.synthetic import SECURITY, SYSMON, make_event
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks, ticks_to_iso
from evidence_verification.verifier import assess
from incident_reconstruction.claims import AttackMapping, Claim, ClaimEntities, ClaimLink, Reconstruction

SCENARIO = "SYN-V1"
OTHER = "SYN-V2"
BASE = iso_to_ticks("2026-09-21T02:05:00.0000000Z")
HOST = "LAB-A"
USER = "LAB-A\\analyst"
GUID_PARENT = "{00000001-aaaa-bbbb-cccc-000000000001}"
GUID_CHILD = "{00000002-aaaa-bbbb-cccc-000000000002}"


def at(second: float) -> int:
    return BASE + int(second * TICKS_PER_SECOND)


def iso(second: float) -> str:
    return ticks_to_iso(at(second))


def security(record_id, second, event_id, *, scenario=SCENARIO, host=HOST, user=USER, **data):
    return make_event(scenario_id=scenario, channel=SECURITY, record_id=record_id, event_id=event_id,
                      timestamp_ticks=at(second), host=host, user=user,
                      event_data={"TargetUserName": "analyst", **data})


def sysmon(record_id, second, event_id=1, *, scenario=SCENARIO, host=HOST, user=USER, **data):
    return make_event(scenario_id=scenario, channel=SYSMON, record_id=record_id, event_id=event_id,
                      timestamp_ticks=at(second), host=host, user=user, event_data=data)


def sys_id(record_id, scenario=SCENARIO):
    return f"{scenario}-SYS-{record_id}"


def sec_id(record_id, scenario=SCENARIO):
    return f"{scenario}-SEC-{record_id}"


def corpus_events():
    """Two scenarios that deliberately reuse record numbers 10-12 for different events."""
    return [
        security(10, 0, 4625), security(11, 1, 4625), security(12, 2, 4624),   # failed, failed, success
        security(13, 3, 4648),
        security(14, 4, 1102, user="LAB-A\\analyst"),
        sysmon(20, 5, 1, ProcessGuid=GUID_CHILD, ParentProcessGuid=GUID_PARENT, User=USER,
               Image="C:\\Windows\\System32\\whoami.exe", CommandLine="whoami.exe",
               ParentImage="C:\\Windows\\explorer.exe"),
        sysmon(21, 6, 11, ProcessGuid=GUID_CHILD, User=USER, Image="C:\\Windows\\System32\\cmd.exe",
               TargetFilename="C:\\Users\\analyst\\AppData\\Local\\Temp\\payload.ps1"),
        sysmon(22, 7, 10, SourceProcessGUID=GUID_CHILD, SourceImage="C:\\x\\a.exe",
               TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x1410", SourceUser=USER),
        sysmon(23, 8, 1, ProcessGuid="{00000003-aaaa-bbbb-cccc-000000000003}", User="LAB-A\\other",
               Image="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd.exe /c dir",
               ParentImage="C:\\Program Files\\Microsoft Office\\winword.exe"),
        sysmon(24, 9, 13, TargetObject="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x", Image="C:\\x.exe"),
        # The same record numbers in another scenario, as in the real S02/S03 collision.
        security(10, 0, 4688, scenario=OTHER, NewProcessName="C:\\Windows\\System32\\dllhost.exe"),
        security(11, 1, 4688, scenario=OTHER, NewProcessName="C:\\Windows\\System32\\sppsvc.exe"),
        security(12, 2, 4688, scenario=OTHER, NewProcessName="C:\\Windows\\System32\\svchost.exe"),
    ]


@pytest.fixture
def store():
    return EventStore(corpus_events())


def make_claim(**overrides) -> Claim:
    """A fully supported failed-then-success claim over records 10-12; override fields to break it."""
    fields = dict(
        claim_id=f"{SCENARIO}-CLM-01", position=1, claim_type="failed_logons_then_success",
        claim_text="Two failed logons were followed by a successful logon for the same account.",
        rationale="synthetic", assessment="requires_review", first_utc=iso(0), last_utc=iso(2),
        entities=ClaimEntities(accounts=("analyst",), hosts=(HOST,)),
        evidence_ids=(sec_id(10), sec_id(11), sec_id(12)),
        context_evidence_ids=(sec_id(10), sec_id(11), sec_id(12)),
        narrative_source="template",
    )
    fields.update(overrides)
    return Claim(**fields)


def make_reconstruction(*claims: Claim, scenario: str = SCENARIO) -> Reconstruction:
    return Reconstruction(
        prompt_version="synthetic", scenario_id=scenario, corpus_manifest_sha256="0" * 64, llm={"runtime": "none"},
        claims=tuple(claims), unlinked_findings={}, investigation_gaps=(), model_calls=0, latency_seconds=0.0)


def assess_one(claim: Claim, store: EventStore, scenario: str = SCENARIO):
    return assess(make_reconstruction(claim, scenario=scenario), store)[0]


def failed_names(assessment) -> set[str]:
    return {check.name for check in assessment.failed}


__all__ = ["AttackMapping", "ClaimEntities", "ClaimLink", "assess_one", "failed_names", "iso", "make_claim",
           "make_reconstruction", "sec_id", "sys_id", "SCENARIO", "OTHER", "HOST", "USER"]
