"""Deterministic stage building: group detections, link agent findings, correlate stages.

Python decides what a stage contains, its time span, entities and links; the local model only
narrates a stage it is given (see :mod:`incident_reconstruction.narrative`). Every rule here is
mechanical, so the same orchestration run always yields the same stages.

* **Grouping.** Detections in time order; consecutive detections of the same rule whose spans are
  at most :data:`STAGE_GAP_SECONDS` apart form one stage. A different rule in between starts a new
  stage, so interleaved activity keeps its order.
* **Linking.** A finding joins a stage when it cites a trigger; when it is the same process as a
  Sysmon trigger, that process's creation record or a child it created; when it is the Sysmon
  creation of a Security 4688 trigger's process (same image, within two seconds: the
  cross-source join); or, for authentication findings, when it names a non-system account
  involved in the stage. Indirect links must fall near the stage in time.
* **Correlation.** Stages are linked when they share a non-system account or a process, or when
  a process in one was started by a process in another.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PureWindowsPath

from authentication_agent.models import Finding as AuthenticationFinding
from endpoint_agent.models import Finding as EndpointFinding
from event_processing.detection.rules import RULES
from event_processing.detection.schema import Detection
from event_processing.query import EventStore
from event_processing.schema import NormalisedEvent
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks

from .attack import candidates_for
from .claims import ClaimEntities, ClaimLink
from .models import OrchestrationRun

STAGE_GAP_SECONDS = 120
ENDPOINT_LINK_SECONDS = 60
ACCOUNT_LINK_SECONDS = 120
CROSS_SOURCE_SECONDS = 2
MAX_STAGE_FINDINGS = 25
MAX_FINDING_EVIDENCE = 10
MAX_CONTEXT_EVIDENCE = 60

Finding = AuthenticationFinding | EndpointFinding

RULE_DESCRIPTIONS = {rule.spec.rule_id: rule.spec.description for rule in RULES}
CLAIM_TYPES = {
    "R-AUTH-01": "failed_logons_then_success",
    "R-AUTH-02": "repeated_failed_logons",
    "R-AUTH-03": "explicit_credential_logon",
    "R-CRED-01": "lsass_access",
    "R-EXEC-01": "discovery_commands",
    "R-EXEC-02": "suspicious_powershell",
    "R-EXEC-03": "unusual_parent_shell",
    "R-FILE-01": "payload_written",
    "R-LOG-01": "audit_log_cleared",
    "R-PERSIST-01": "service_installed",
    "R-PERSIST-02": "scheduled_task_created",
    "R-PERSIST-03": "run_key_set",
}
# Fields worth showing for a trigger event, in display order; absent fields are skipped.
TRIGGER_FIELDS = (
    "TargetUserName", "TargetDomainName", "SubjectUserName", "LogonType", "IpAddress", "WorkstationName",
    "TargetServerName", "ProcessName", "NewProcessName", "ParentProcessName", "Image", "ParentImage",
    "CommandLine", "User", "SourceImage", "TargetImage", "GrantedAccess", "TargetFilename",
    "TargetObject", "Details", "ServiceName", "ServiceFileName", "TaskName",
)
ACCOUNT_FIELDS = ("TargetUserName", "SubjectUserName", "User")
_SYSTEM_ACCOUNT = re.compile(r"^(system|local service|network service|anonymous logon|-|(dwm|umfd)-\d+|.*\$)$", re.I)


def account_key(value: str | None) -> str | None:
    """Comparable account name: domain prefix removed, case-folded; ``None`` for system identities."""
    if not value:
        return None
    name = value.rsplit("\\", 1)[-1].strip()
    if not name or _SYSTEM_ACCOUNT.match(name):
        return None
    return name.casefold()


@dataclass
class Stage:
    position: int
    rule_id: str
    detections: list[Detection]
    first_ticks: int
    last_ticks: int
    trigger_events: list[NormalisedEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    direct_finding_ids: set[str] = field(default_factory=set)
    links: list[ClaimLink] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    @property
    def claim_id(self) -> str:
        return f"{self.detections[0].scenario_id}-CLM-{self.position:02d}"

    @property
    def claim_type(self) -> str:
        return CLAIM_TYPES.get(self.rule_id, "detected_activity")

    @property
    def trigger_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(eid for d in self.detections for eid in d.trigger_evidence_ids))

    @property
    def candidate_techniques(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(t for d in self.detections for t in candidates_for(d.rule_id, d.attack_technique)))

    @property
    def context_evidence_ids(self) -> tuple[str, ...]:
        ids = list(self.trigger_ids)
        for finding in self.findings:
            ids.extend(finding.evidence_ids[:MAX_FINDING_EVIDENCE])
        return tuple(dict.fromkeys(ids))[:max(MAX_CONTEXT_EVIDENCE, len(self.trigger_ids))]

    def own_process_guids(self) -> set[str]:
        guids = {_guid(event) for event in self.trigger_events} - {None}
        for finding in self.findings:
            if finding.agent_type == "endpoint" and finding.finding_id in self.direct_finding_ids:
                guids.add(finding.observed_events.process.process_guid)
        return guids - {None}

    def parent_process_guids(self) -> set[str]:
        parents = {event.event_data.get("ParentProcessGuid") for event in self.trigger_events}
        for finding in self.findings:
            if finding.agent_type == "endpoint":
                parents.add(finding.observed_events.process.parent_process_guid)
        return parents - {None}

    def accounts(self) -> set[str]:
        keys = {account_key(value) for event in self.trigger_events
                for value in (event.user, *(event.event_data.get(name) for name in ACCOUNT_FIELDS))}
        keys |= {account_key(finding.entities.account) for finding in self.findings
                 if finding.finding_id in self.direct_finding_ids}
        return keys - {None}

    def entities(self) -> ClaimEntities:
        accounts, hosts, processes, guids, files = [], [], [], [], []
        for event in self.trigger_events:
            hosts.append(event.host)
            accounts.extend([event.user, *(event.event_data.get(name) for name in ACCOUNT_FIELDS)])
            processes.extend(event.event_data.get(name) for name in ("Image", "NewProcessName", "SourceImage", "ProcessName"))
            guids.append(_guid(event))
            files.append(event.event_data.get("TargetFilename"))
        for finding in self.findings:
            hosts.append(finding.entities.host)
            accounts.append(finding.entities.account)
            if finding.agent_type == "endpoint":
                process = finding.observed_events.process
                processes.append(process.image)
                guids.append(process.process_guid)
                files.append(process.target_filename)
        clean = lambda values: tuple(dict.fromkeys(v for v in values if v and v != "-"))
        return ClaimEntities(accounts=clean(accounts), hosts=clean(hosts), processes=clean(processes),
                             process_guids=clean(guids), files=clean(files))


def build_stages(run: OrchestrationRun, store: EventStore) -> list[Stage]:
    stages = _group(run.detections)
    findings = run.findings()
    for stage in stages:
        stage.trigger_events = [store.lookup(eid).event for eid in stage.trigger_ids if store.lookup(eid).event]
        _link_direct(stage, findings)
    # A finding that cites another stage's triggers belongs to that stage; the relationship
    # between the two stages is expressed as a link, not by repeating its evidence here.
    owned = {finding_id for stage in stages for finding_id in stage.direct_finding_ids}
    unowned = tuple(f for f in findings if f.finding_id not in owned)
    related = {stage.position: _related(stage, unowned) for stage in stages}
    # An indirectly related finding joins only the nearest stage it qualifies for (earlier on ties).
    nearest: dict[str, tuple[int, int]] = {}
    for position, candidates in related.items():
        for finding in candidates:
            key = (_distance(finding, stages[position - 1]), position)
            nearest[finding.finding_id] = min(nearest.get(finding.finding_id, key), key)
    for stage in stages:
        mine = [f for f in related[stage.position] if nearest[f.finding_id][1] == stage.position]
        _attach(stage, mine)
        stage.gaps = _gaps(stage, run)
    _correlate(stages)
    return stages


def unlinked_counts(run: OrchestrationRun, stages: list[Stage]) -> dict[str, int]:
    linked = {finding.finding_id for stage in stages for finding in stage.findings}
    counts = {"authentication": 0, "endpoint": 0}
    for finding in run.findings():
        if finding.finding_id not in linked:
            counts[finding.agent_type] += 1
    return counts


def _group(detections) -> list[Stage]:
    ordered = sorted(detections, key=lambda d: (d.window_start_utc, d.detection_id))
    stages: list[Stage] = []
    for detection in ordered:
        start, end = iso_to_ticks(detection.window_start_utc), iso_to_ticks(detection.window_end_utc)
        current = stages[-1] if stages else None
        if current and current.rule_id == detection.rule_id and start - current.last_ticks <= STAGE_GAP_SECONDS * TICKS_PER_SECOND:
            current.detections.append(detection)
            current.last_ticks = max(current.last_ticks, end)
            continue
        stages.append(Stage(position=len(stages) + 1, rule_id=detection.rule_id, detections=[detection],
                            first_ticks=start, last_ticks=end))
    return stages


def _link_direct(stage: Stage, findings: tuple[Finding, ...]) -> None:
    triggers = set(stage.trigger_ids)
    direct = [f for f in findings if triggers & set(f.evidence_ids)]
    direct += [f for f in findings if f not in direct and _same_security_process(f, stage.trigger_events)]
    stage.findings = list(direct)
    stage.direct_finding_ids = {f.finding_id for f in direct}


def _related(stage: Stage, findings: tuple[Finding, ...]) -> list[Finding]:
    """Findings that share the stage's process, lineage or non-system account, near it in time."""
    own, accounts = stage.own_process_guids(), stage.accounts()
    parents = {event.event_data.get("ParentProcessGuid") for event in stage.trigger_events}
    nearby: list[Finding] = []
    for finding in findings:
        distance = _distance(finding, stage)
        if finding.agent_type == "endpoint" and distance <= ENDPOINT_LINK_SECONDS * TICKS_PER_SECOND:
            process = finding.observed_events.process
            creation = finding.observed_events.source_event_id == 1
            if (process.process_guid in own
                    or (creation and process.parent_process_guid in own)
                    or (creation and process.process_guid in parents)):
                nearby.append(finding)
        elif finding.agent_type == "authentication" and distance <= ACCOUNT_LINK_SECONDS * TICKS_PER_SECOND:
            if account_key(finding.entities.account) in accounts:
                nearby.append(finding)
    return nearby


def _attach(stage: Stage, nearby: list[Finding]) -> None:
    nearby = sorted(nearby, key=lambda f: (_distance(f, stage), f.finding_id))
    room = max(0, MAX_STAGE_FINDINGS - len(stage.findings))
    if len(nearby) > room:
        stage.gaps.append(f"{len(nearby) - room} further linked findings were omitted to keep the stage bounded")
    stage.findings.extend(nearby[:room])
    stage.findings.sort(key=lambda f: (iso_to_ticks(f.timestamps.first_utc), f.finding_id))


def _same_security_process(finding: Finding, triggers: list[NormalisedEvent]) -> bool:
    """Sysmon creation of the process a Security 4688 trigger recorded: same image, within 2 s."""
    if finding.agent_type != "endpoint" or finding.observed_events.source_event_id != 1:
        return False
    image = (finding.observed_events.process.image or "").casefold()
    ticks = iso_to_ticks(finding.observed_events.timestamp_utc)
    return any(
        event.source_event_id == 4688 and image
        and (event.event_data.get("NewProcessName") or "").casefold() == image
        and abs(event.timestamp_ticks - ticks) <= CROSS_SOURCE_SECONDS * TICKS_PER_SECOND
        for event in triggers
    )


def _gaps(stage: Stage, run: OrchestrationRun) -> list[str]:
    gaps = list(stage.gaps)
    ids = {d.detection_id for d in stage.detections}
    uninvestigated = sorted(ids & set(run.uninvestigated_detection_ids()))
    if uninvestigated:
        gaps.append(f"no completed agent investigation covered {', '.join(uninvestigated)}")
    for task in run.tasks:
        if not ids & set(task.plan.detection_ids):
            continue
        if not task.resolved:
            gaps.append(f"{task.plan.agent_type} investigation {task.plan.task_id} did not complete ({task.error_code})")
        elif task.status == "completed" and task.plan.agent_type == "endpoint" and task.endpoint_result.metadata.truncated:
            gaps.append(f"endpoint investigation {task.plan.task_id} was truncated; its inventory is incomplete")
    if not stage.findings:
        gaps.append("no agent finding cites or links to this stage's triggers; the stage rests on detection evidence only")
    return list(dict.fromkeys(gaps))


def _correlate(stages: list[Stage]) -> None:
    for i, earlier in enumerate(stages):
        for later in stages[i + 1:]:
            reasons = []
            shared_accounts = sorted(earlier.accounts() & later.accounts())
            if shared_accounts:
                reasons.append(f"shared account {', '.join(shared_accounts)}")
            if earlier.own_process_guids() & later.own_process_guids():
                reasons.append("same process")
            if later.parent_process_guids() & earlier.own_process_guids():
                reasons.append("a process in the later stage was started by a process in the earlier stage")
            if reasons:
                reason = "; ".join(reasons)
                earlier.links.append(ClaimLink(claim_id=later.claim_id, reason=reason))
                later.links.append(ClaimLink(claim_id=earlier.claim_id, reason=reason))


def _distance(finding: Finding, stage: Stage) -> int:
    first, last = iso_to_ticks(finding.timestamps.first_utc), iso_to_ticks(finding.timestamps.last_utc)
    if last < stage.first_ticks:
        return stage.first_ticks - last
    if first > stage.last_ticks:
        return first - stage.last_ticks
    return 0


def _guid(event: NormalisedEvent) -> str | None:
    return event.event_data.get("SourceProcessGUID" if event.source_event_id == 10 else "ProcessGuid")


def short_image(path: str | None) -> str | None:
    return PureWindowsPath(path).name if path else None
