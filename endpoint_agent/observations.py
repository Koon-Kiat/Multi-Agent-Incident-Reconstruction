"""Derive citable Sysmon facts and conservative GUID links from retrieved records."""

from collections import defaultdict
from collections.abc import Iterable
import hashlib
import json
import re
from uuid import UUID

from endpoint_agent.models import Entities, Finding, ObservedEvents, ProcessFacts, Relationship, TimePeriod
from endpoint_agent.queries.semantics import event_order, process_guid
from event_processing.schema import NormalisedEvent

DESCRIPTIONS = {
    1: "Sysmon recorded process creation with the reported process and parent fields.",
    10: "Sysmon recorded a process-access event with the reported source, target and access mask.",
    11: "Sysmon recorded file creation with the reported process and target filename.",
    13: "Sysmon recorded a registry value set with the reported process, target and details.",
}
BASE_UNCERTAINTY = (
    "Endpoint observations do not establish malicious intent, successful compromise or a common actor.",
    "Findings describe only retrieved supported Sysmon records within the authorized window.",
)


def usable_guid(value: str | None) -> bool:
    if value is None or re.fullmatch(r"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}", value) is None:
        return False
    return UUID(value).int != 0


def process_facts(event: NormalisedEvent) -> ProcessFacts:
    data = event.event_data
    access = event.source_event_id == 10
    return ProcessFacts(
        process_guid=process_guid(event),
        process_id=data.get("SourceProcessId" if access else "ProcessId"),
        image=data.get("SourceImage" if access else "Image"),
        command_line=data.get("CommandLine"),
        parent_process_guid=data.get("ParentProcessGuid"), parent_process_id=data.get("ParentProcessId"),
        parent_image=data.get("ParentImage"), parent_command_line=data.get("ParentCommandLine"),
        target_process_guid=data.get("TargetProcessGUID"), target_process_id=data.get("TargetProcessId"),
        target_image=data.get("TargetImage"),
        access_mask=data.get("GrantedAccess"), target_filename=data.get("TargetFilename"),
        registry_target=data.get("TargetObject"), registry_details=data.get("Details"))


def _cycle(event: NormalisedEvent, creates: dict) -> bool:
    seen = set()
    current = event
    while current is not None:
        guid = current.event_data.get("ProcessGuid")
        if not usable_guid(guid):
            return False
        if guid in seen:
            return True
        seen.add(guid)
        candidates = creates.get((current.scenario_id, current.host, current.event_data.get("ParentProcessGuid")), ())
        current = candidates[0] if len(candidates) == 1 else None
    return False


def _link(event: NormalisedEvent, facts: ProcessFacts, creates: dict, issues: list[str]) -> NormalisedEvent | None:
    is_creation = event.source_event_id == 1
    guid = facts.parent_process_guid if is_creation else facts.process_guid
    subject = "Parent" if is_creation else "Originating"
    if event.host in (None, "", "-") or not usable_guid(guid) or not usable_guid(facts.process_guid):
        issues.append(f"{subject} process linkage is unavailable: host or process GUID is missing/invalid.")
        return None
    candidates = creates.get((event.scenario_id, event.host, guid), ())
    if not candidates:
        issues.append(f"{subject} process creation was not retrieved within the authorized window; reported fields remain uncorroborated.")
        return None
    if len(candidates) != 1:
        issues.append(f"{subject} ProcessGuid resolves to multiple creation records; no relationship asserted.")
        return None
    source = candidates[0]
    own_creates = creates.get((event.scenario_id, event.host, facts.process_guid), ())
    if (is_creation and len(own_creates) != 1) or _cycle(source, creates) or (is_creation and _cycle(event, creates)):
        issues.append("Conflicting or cyclic process identity; no relationship asserted.")
        return None
    if source.timestamp_ticks > event.timestamp_ticks:
        issues.append(f"{subject} creation is later than this event; no relationship asserted.")
        return None
    comparisons = ((facts.parent_image, source.event_data.get("Image")),
                   (facts.parent_process_id, source.event_data.get("ProcessId"))) if is_creation else (
                       (facts.image, source.event_data.get("Image")),
                       (facts.process_id, source.event_data.get("ProcessId")))
    if any(left not in (None, "", "-") and right not in (None, "", "-") and left != right
           for left, right in comparisons):
        issues.append(f"{subject} GUID matches but reported image/PID conflicts; no relationship asserted.")
        return None
    if source.timestamp_ticks == event.timestamp_ticks:
        issues.append("Linked records have equal timestamps; GUID evidence links them but does not establish temporal precedence.")
    return source


def build_observations(events: Iterable[NormalisedEvent], truncated: bool) -> tuple[Finding, ...]:
    records = sorted(events, key=event_order)
    creates = defaultdict(list)
    for event in records:
        if event.source_event_id == 1:
            creates[(event.scenario_id, event.host, process_guid(event))].append(event)
    findings = []
    for event in records:
        facts = process_facts(event)
        issues = list(BASE_UNCERTAINTY)
        for name, value in (("host", event.host), ("user", event.user), ("image", facts.image)):
            if value in (None, "", "-"):
                issues.append(f"Missing or unavailable {name} in the source record.")
        reported_user = event.event_data.get("SourceUser" if event.source_event_id == 10 else "User")
        if event.user is not None and reported_user is not None and event.user != reported_user:
            issues.append("Normalized user and reported user differ; no actor identity is inferred.")
        if event.parse_warnings:
            issues.append("The shared normalizer reported parse warnings; inspect the original record.")
        if truncated:
            issues.append("At least one query was truncated; process chains and event coverage may be incomplete.")
        if event.source_event_id == 10:
            issues.append("A process-access record does not establish credential extraction or subsequent use.")
        elif event.source_event_id == 11:
            issues.append("File creation does not establish execution of that file.")
        elif event.source_event_id == 13:
            issues.append("A registry write does not establish that an autostart entry executed.")
        linked = _link(event, facts, creates, issues)
        evidence = sorted([event, linked] if linked is not None else [event], key=event_order)
        ids = tuple(item.evidence_id for item in evidence)
        relations = ()
        if linked is not None:
            relations = (Relationship(kind="parent_child" if event.source_event_id == 1 else "process_activity",
                source_evidence_id=linked.evidence_id, target_evidence_id=event.evidence_id,
                source_process_guid=process_guid(linked), target_process_guid=facts.process_guid),)
        # Include the anchor, not only the evidence set: a parent and an activity are distinct findings.
        digest = hashlib.sha256(json.dumps([event.evidence_id, ids]).encode()).hexdigest()[:24]
        findings.append(Finding(finding_id=f"ENDPOINT-{digest}", scenario_id=event.scenario_id,
            observed_events=ObservedEvents(description=DESCRIPTIONS[event.source_event_id],
                evidence_id=event.evidence_id, source_event_id=event.source_event_id,
                timestamp_utc=event.timestamp_utc, process=facts, relationships=relations),
            timestamps=TimePeriod(first_utc=evidence[0].timestamp_utc, last_utc=evidence[-1].timestamp_utc),
            entities=Entities(account=event.user, reported_account=reported_user,
                target_account=event.event_data.get("TargetUser") if event.source_event_id == 10 else None,
                host=event.host), evidence_ids=ids, uncertainty=tuple(issues)))
    return tuple(findings)
