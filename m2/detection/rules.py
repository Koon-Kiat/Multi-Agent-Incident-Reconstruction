"""The conventional (non-LLM) detection rules.

Contract
--------

A rule is a **pure function** ``(events) -> tuple[Detection, ...]`` over one scenario's
normalised events, in ``(timestamp_ticks, evidence_id)`` ascending order. It reads no file,
holds no state, calls no network and never mutates an event. :data:`RULES` pairs each function
with its :class:`RuleSpec`, which carries the identity, description, ATT&CK technique,
severity and the **exact parameter values** the rule was run with.

Every rule partitions the events it fires on: two detections of the same rule in the same
scenario never share a trigger event, so their deterministic ``detection_id`` values
(``<scenario>-<rule_id>-<first trigger id>``) cannot collide. Case is folded **inside these
rules only** — a basename, a key path and a command line are detection heuristics, not query
API behaviour, which stays exact and case-sensitive.

Blind design (task_plan.md phase 3)
-----------------------------------

The rule logic comes from generic Windows logging and ATT&CK knowledge. Every threshold and
vocabulary below was declared **before** the first run over real data and is **not** tuned
after seeing real output. If a value looks wrong after a real run, that is a STUCK entry and a
planner decision, not an edit here.

Declared thresholds and vocabularies
------------------------------------

======================================= ==========================================================
``FAILED_LOGON_MIN_EVENTS`` = 3         R-AUTH-01/02: three failed logons is a burst, not a typo.
``FAILED_LOGON_WINDOW_SECONDS`` = 300   R-AUTH-01/02: five minutes is the usual interactive retry span.
``DISCOVERY_MIN_BINARIES`` = 3          R-EXEC-01: three *distinct* discovery tools is enumeration.
``DISCOVERY_WINDOW_SECONDS`` = 120      R-EXEC-01: two minutes for one enumeration burst.
``DISCOVERY_BINARIES``                  R-EXEC-01: built-in discovery binaries (T1033/T1082/T1016).
``SUSPICIOUS_PARENT_IMAGES``            R-EXEC-03: document/browser/WMI hosts that should not spawn a shell.
``SHELL_IMAGES``                        R-EXEC-03: the scripting and proxy-execution children.
``ENCODED_COMMAND_PATTERNS``            R-EXEC-02: encoded/hidden/downloader PowerShell markers.
``POWERSHELL_COMMAND_MARKERS``          R-EXEC-02: the command line must actually be a PowerShell one.
``LSASS_ACCESS_MASKS``                  R-CRED-01: documented PROCESS_VM_READ / ALL_ACCESS combos.
``FILE_DROP_EXTENSIONS``                R-FILE-01: executable and script payload types.
``FILE_DROP_LOCATION_MARKERS``          R-FILE-01: user-writable drop locations.
``RUN_KEY_MARKERS``                     R-PERSIST-03: Run / RunOnce autostart keys.
======================================= ==========================================================

Known gaps, stated here rather than discovered later:

* The corpus holds only the ``Security`` and ``Microsoft-Windows-Sysmon/Operational`` channels,
  and ``NormalisedEvent.channel`` is a two-value literal, so the System-channel service-install
  ID 7045 can neither occur nor be represented. R-PERSIST-01 therefore matches Security 4697 on
  the Security channel **only**: matching 7045 on any channel would fire on whichever channel
  happened to carry that number. Adding a System export is a schema change for phase 5, not a
  rule edit now.
* Rules only see fields the normaliser preserved. Security 4688 carries ``CommandLine`` and
  ``ParentProcessName`` only when the audit policy that collected it logged them.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from m2.corpus import event_sort_key
from m2.detection.schema import Detection, RuleRecord, Severity, make_detection_id
from m2.query import SECURITY_CHANNEL, SYSMON_CHANNEL
from m2.schema import NormalisedEvent
from m2.timeutil import TICKS_PER_SECOND

# --------------------------------------------------------------------------------------------------
# Windows Event IDs used by these rules.
# --------------------------------------------------------------------------------------------------

SECURITY_PROCESS_CREATED = 4688
SECURITY_SUCCESSFUL_LOGON = 4624
SECURITY_FAILED_LOGON = 4625
SECURITY_EXPLICIT_CREDENTIAL_LOGON = 4648
SECURITY_AUDIT_LOG_CLEARED = 1102
SECURITY_SERVICE_INSTALLED = 4697
SECURITY_SCHEDULED_TASK_CREATED = 4698
SYSMON_PROCESS_CREATE = 1
SYSMON_PROCESS_ACCESS = 10
SYSMON_FILE_CREATE = 11
SYSMON_REGISTRY_SET_VALUE = 13

# --------------------------------------------------------------------------------------------------
# Declared thresholds (see the module docstring: declared before the first real-data run).
# --------------------------------------------------------------------------------------------------

FAILED_LOGON_MIN_EVENTS = 3
FAILED_LOGON_WINDOW_SECONDS = 300
DISCOVERY_MIN_BINARIES = 3
DISCOVERY_WINDOW_SECONDS = 120

DISCOVERY_BINARIES = frozenset(
    {
        "whoami",
        "net",
        "net1",
        "nltest",
        "systeminfo",
        "ipconfig",
        "quser",
        "qwinsta",
        "tasklist",
        "dsquery",
        "arp",
        "route",
    }
)

SUSPICIOUS_PARENT_IMAGES = frozenset(
    {"winword", "excel", "powerpnt", "outlook", "msedge", "chrome", "firefox", "wmiprvse", "mshta"}
)

SHELL_IMAGES = frozenset({"cmd", "powershell", "pwsh", "wscript", "cscript", "rundll32", "regsvr32"})

# ``-enc``/``-EncodedCommand`` is matched as a parameter token, so ``-Encoding`` never matches.
ENCODED_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("-enc/-EncodedCommand", re.compile(r"(?i)(?:^|[\s\"'])-e(?:nc|ncodedcommand)(?=[\s\"']|$)")),
    ("FromBase64String", re.compile(r"(?i)frombase64string")),
    ("-w/-WindowStyle hidden", re.compile(r"(?i)-\s*w(?:indowstyle)?\s+hidden")),
    ("IEX/Invoke-Expression", re.compile(r"(?i)(?:\biex\b|invoke-expression)")),
    ("DownloadString", re.compile(r"(?i)downloadstring")),
)

POWERSHELL_COMMAND_MARKERS = ("powershell", "pwsh")

LSASS_ACCESS_MASKS = frozenset({0x1010, 0x1410, 0x1418, 0x1438, 0x143A, 0x1F0FFF, 0x1FFFFF})

FILE_DROP_EXTENSIONS = frozenset({".exe", ".dll", ".ps1", ".bat", ".vbs", ".js"})
FILE_DROP_USER_APP_DATA_MARKERS = ("\\users\\", "\\appdata\\")
FILE_DROP_LOCATION_MARKERS = ("\\temp\\", "\\downloads\\", "\\programdata\\")

RUN_KEY_MARKERS = ("\\currentversion\\run", "\\currentversion\\runonce")

LSASS_IMAGE_STEM = "lsass"


class RuleSpec(BaseModel):
    """One rule's identity and the thresholds it runs with; the function is held by :class:`Rule`."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    rule_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    attack_technique: str | None = None
    severity: Severity
    params: dict[str, int | str] = Field(default_factory=dict)

    def record(self) -> RuleRecord:
        """The serialisable form stored in a :class:`~m2.detection.schema.DetectionRun`."""
        return RuleRecord(rule_id=self.rule_id, version=self.version, params=dict(self.params))


RuleFunction = Callable[[Sequence[NormalisedEvent]], tuple[Detection, ...]]


@dataclass(frozen=True)
class Rule:
    """A rule's declared identity plus the pure function that implements it."""

    spec: RuleSpec
    fn: RuleFunction


# --------------------------------------------------------------------------------------------------
# R-AUTH: authentication.
# --------------------------------------------------------------------------------------------------


def detect_failed_logon_then_success(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-AUTH-01: a failed-logon burst followed by a success for the same account (T1110)."""
    return _failed_logon_detections(events, _SPEC_BY_ID["R-AUTH-01"], requires_success=True)


def detect_failed_logon_burst(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-AUTH-02: the same burst with no successful logon in its window (T1110)."""
    return _failed_logon_detections(events, _SPEC_BY_ID["R-AUTH-02"], requires_success=False)


def _failed_logon_detections(
    events: Sequence[NormalisedEvent], spec: RuleSpec, *, requires_success: bool
) -> tuple[Detection, ...]:
    failures = [event for event in events if _matches_event_id(event, SECURITY_CHANNEL, SECURITY_FAILED_LOGON)]
    successes = [event for event in events if _matches_event_id(event, SECURITY_CHANNEL, SECURITY_SUCCESSFUL_LOGON)]
    detections: list[Detection] = []
    for account in sorted({_account(event) for event in failures}, key=_account_sort_key):
        group = [event for event in failures if _account(event) == account]
        for cluster in _clusters(group, FAILED_LOGON_WINDOW_SECONDS):
            if len(cluster) < FAILED_LOGON_MIN_EVENTS:
                continue
            deadline = cluster[0].timestamp_ticks + FAILED_LOGON_WINDOW_SECONDS * TICKS_PER_SECOND
            confirmations = [
                event
                for event in successes
                if _account(event) == account and cluster[-1].timestamp_ticks <= event.timestamp_ticks <= deadline
            ]
            if requires_success != bool(confirmations):
                continue
            triggers = (*cluster, *confirmations[:1])
            outcome = (
                "followed by a successful logon for the same account"
                if requires_success
                else "with no successful logon for the same account afterwards"
            )
            detections.append(
                _detection(
                    spec,
                    triggers,
                    rationale=(
                        f"{len(cluster)} failed logons for {_describe_account(*account)} inside "
                        f"{FAILED_LOGON_WINDOW_SECONDS}s, {outcome}"
                    ),
                )
            )
    return _ordered(detections)


def detect_explicit_credential_logon(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-AUTH-03: an explicit-credential logon (4648) is worth review on its own (T1078)."""
    spec = _SPEC_BY_ID["R-AUTH-03"]
    return _ordered(
        [
            _detection(
                spec,
                (event,),
                rationale=(
                    f"explicit-credential logon by {_describe_account(event.user, event.host)}"
                    f" using credentials for {event.event_data.get('TargetUserName')!r}"
                ),
            )
            for event in events
            if _matches_event_id(event, SECURITY_CHANNEL, SECURITY_EXPLICIT_CREDENTIAL_LOGON)
        ]
    )


# --------------------------------------------------------------------------------------------------
# R-LOG: audit log integrity.
# --------------------------------------------------------------------------------------------------


def detect_audit_log_cleared(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-LOG-01: Security audit log cleared, 1102 (T1070.001)."""
    spec = _SPEC_BY_ID["R-LOG-01"]
    return _ordered(
        [
            _detection(spec, (event,), rationale="Security audit log was cleared (Security 1102)")
            for event in events
            if _matches_event_id(event, SECURITY_CHANNEL, SECURITY_AUDIT_LOG_CLEARED)
        ]
    )


# --------------------------------------------------------------------------------------------------
# R-PERSIST: persistence.
# --------------------------------------------------------------------------------------------------


def detect_service_install(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-PERSIST-01: a service was installed, Security 4697 (T1543.003).

    System-channel 7045 is documented as out of reach in the module docstring: no channel in
    this corpus can carry it, and matching the number on any channel would not be the rule.
    """
    spec = _SPEC_BY_ID["R-PERSIST-01"]
    return _ordered(
        [
            _detection(
                spec,
                (event,),
                rationale=(
                    f"service installed: {event.event_data.get('ServiceName')!r} "
                    f"({event.event_data.get('ServiceFileName')!r})"
                ),
            )
            for event in events
            if _matches_event_id(event, SECURITY_CHANNEL, SECURITY_SERVICE_INSTALLED)
        ]
    )


def detect_scheduled_task_created(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-PERSIST-02: a scheduled task was created, 4698 (T1053.005)."""
    spec = _SPEC_BY_ID["R-PERSIST-02"]
    return _ordered(
        [
            _detection(
                spec,
                (event,),
                rationale=f"scheduled task created: {event.event_data.get('TaskName')!r}",
            )
            for event in events
            if _matches_event_id(event, SECURITY_CHANNEL, SECURITY_SCHEDULED_TASK_CREATED)
        ]
    )


def detect_run_key_set(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-PERSIST-03: a Run/RunOnce registry value was set (Sysmon 13) (T1547.001)."""
    spec = _SPEC_BY_ID["R-PERSIST-03"]
    return _ordered(
        [
            _detection(
                spec,
                (event,),
                rationale=f"Run/RunOnce value set: {event.event_data.get('TargetObject')!r}",
            )
            for event in events
            if _matches_event_id(event, SYSMON_CHANNEL, SYSMON_REGISTRY_SET_VALUE)
            and _is_run_key(event.event_data.get("TargetObject"))
        ]
    )


# --------------------------------------------------------------------------------------------------
# R-EXEC: execution and discovery.
# --------------------------------------------------------------------------------------------------


def detect_discovery_binaries(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-EXEC-01: discovery tooling, as a burst (medium) and as single hits (low).

    The rule partitions the matching events: an event inside a burst is reported by the burst
    detection only, an event outside every burst is reported as its own low-severity hit.
    """
    spec = _SPEC_BY_ID["R-EXEC-01"]
    candidates = [
        event
        for event in events
        if _process_image_stem(event) in DISCOVERY_BINARIES and _is_process_creation(event)
    ]
    detections: list[Detection] = []
    in_a_burst: set[str] = set()
    for account in sorted({_account(event) for event in candidates}, key=_account_sort_key):
        group = [event for event in candidates if _account(event) == account]
        for cluster in _clusters(group, DISCOVERY_WINDOW_SECONDS):
            binaries = sorted({_process_image_stem(event) for event in cluster})
            if len(binaries) < DISCOVERY_MIN_BINARIES:
                continue
            in_a_burst.update(event.evidence_id for event in cluster)
            detections.append(
                _detection(
                    spec,
                    cluster,
                    severity="medium",
                    rationale=(
                        f"{len(binaries)} distinct discovery binaries ({', '.join(binaries)}) run by "
                        f"{_describe_account(*account)} inside {DISCOVERY_WINDOW_SECONDS}s"
                    ),
                )
            )
    detections.extend(
        _detection(
            spec,
            (event,),
            severity="low",
            rationale=(
                f"discovery binary {_process_image_stem(event)!r} run by "
                f"{_describe_account(event.user, event.host)} outside any enumeration burst"
            ),
        )
        for event in candidates
        if event.evidence_id not in in_a_burst
    )
    return _ordered(detections)


def detect_encoded_powershell(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-EXEC-02: a PowerShell command line carrying an encoded/hidden/downloader marker (T1059.001)."""
    spec = _SPEC_BY_ID["R-EXEC-02"]
    detections: list[Detection] = []
    for event in events:
        if not _is_process_creation(event):
            continue
        command_line = event.event_data.get("CommandLine")
        if not command_line or not _is_powershell_command_line(command_line):
            continue
        markers = [name for name, pattern in ENCODED_COMMAND_PATTERNS if pattern.search(command_line)]
        if not markers:
            continue
        detections.append(
            _detection(
                spec,
                (event,),
                rationale=f"PowerShell command line carries {', '.join(markers)}",
            )
        )
    return _ordered(detections)


def detect_suspicious_parent_shell(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-EXEC-03: a document/browser/WMI host spawning a shell or script engine (T1204/T1059)."""
    spec = _SPEC_BY_ID["R-EXEC-03"]
    detections: list[Detection] = []
    for event in events:
        if not _is_process_creation(event):
            continue
        parent_image = event.event_data.get("ParentImage") or event.event_data.get("ParentProcessName")
        parent = _stem(parent_image)
        child = _process_image_stem(event)
        if parent in SUSPICIOUS_PARENT_IMAGES and child in SHELL_IMAGES:
            detections.append(
                _detection(
                    spec,
                    (event,),
                    rationale=f"parent image {parent_image!r} spawned {child!r}",
                )
            )
    return _ordered(detections)


# --------------------------------------------------------------------------------------------------
# R-CRED: credential access.
# --------------------------------------------------------------------------------------------------


def detect_lsass_access(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-CRED-01: Sysmon 10 opened lsass.exe with a documented suspicious access mask (T1003.001)."""
    spec = _SPEC_BY_ID["R-CRED-01"]
    detections: list[Detection] = []
    for event in events:
        if not _matches_event_id(event, SYSMON_CHANNEL, SYSMON_PROCESS_ACCESS):
            continue
        if _stem(event.event_data.get("TargetImage")) != LSASS_IMAGE_STEM:
            continue
        mask = _granted_access_mask(event.event_data.get("GrantedAccess"))
        if mask not in LSASS_ACCESS_MASKS:
            continue
        detections.append(
            _detection(
                spec,
                (event,),
                rationale=(
                    f"{event.event_data.get('SourceImage')!r} opened lsass.exe with GrantedAccess "
                    f"{event.event_data.get('GrantedAccess')!r}"
                ),
            )
        )
    return _ordered(detections)


# --------------------------------------------------------------------------------------------------
# R-FILE: file creation.
# --------------------------------------------------------------------------------------------------


def detect_file_drop(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-FILE-01: an executable or script written to a user-writable location (T1105)."""
    spec = _SPEC_BY_ID["R-FILE-01"]
    detections: list[Detection] = []
    for event in events:
        if not _matches_event_id(event, SYSMON_CHANNEL, SYSMON_FILE_CREATE):
            continue
        target = event.event_data.get("TargetFilename")
        if not target or not _looks_like_drop(target):
            continue
        detections.append(
            _detection(spec, (event,), rationale=f"executable payload written to {target!r}")
        )
    return _ordered(detections)


# --------------------------------------------------------------------------------------------------
# Field helpers. Everything below treats log content as untrusted data: it is compared,
# never executed, and a missing field simply means the rule cannot fire.
# --------------------------------------------------------------------------------------------------


def _matches_event_id(event: NormalisedEvent, channel: str, source_event_id: int) -> bool:
    return event.channel == channel and event.source_event_id == source_event_id


def _is_process_creation(event: NormalisedEvent) -> bool:
    return _matches_event_id(event, SECURITY_CHANNEL, SECURITY_PROCESS_CREATED) or _matches_event_id(
        event, SYSMON_CHANNEL, SYSMON_PROCESS_CREATE
    )


def _process_image(event: NormalisedEvent) -> str | None:
    """The created process image: ``NewProcessName`` for Security 4688, ``Image`` for Sysmon 1."""
    if event.channel == SYSMON_CHANNEL:
        return event.event_data.get("Image")
    return event.event_data.get("NewProcessName")


def _process_image_stem(event: NormalisedEvent) -> str:
    return _stem(_process_image(event))


def _stem(value: str | None) -> str:
    """Lower-cased basename of a Windows path, without an ``.exe`` suffix.

    Detection-only normalisation: the query API stays exact and case-sensitive.
    """
    if not value:
        return ""
    basename = value.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return basename[: -len(".exe")] if basename.endswith(".exe") else basename


def _account(event: NormalisedEvent) -> tuple[str | None, str | None]:
    return (event.user, event.host)


def _account_sort_key(account: tuple[str | None, str | None]) -> tuple[bool, str, bool, str]:
    """A total order that keeps ``None``, ``""`` and a real value distinct."""
    user, host = account
    return (user is None, user or "", host is None, host or "")


def _describe_account(user: str | None, host: str | None) -> str:
    return f"account {user!r} on host {host!r}"


def _clusters(events: Sequence[NormalisedEvent], window_seconds: int) -> tuple[tuple[NormalisedEvent, ...], ...]:
    """Split events into non-overlapping clusters, each anchored at its first event.

    A cluster holds every following event within ``window_seconds`` of the **anchor**, so the
    clusters are disjoint and every cluster has a distinct first event. That is what keeps the
    derived ``detection_id`` unique per rule and scenario.
    """
    ordered = sorted(events, key=event_sort_key)
    span = window_seconds * TICKS_PER_SECOND
    clusters: list[tuple[NormalisedEvent, ...]] = []
    current: list[NormalisedEvent] = []
    for event in ordered:
        if current and event.timestamp_ticks - current[0].timestamp_ticks > span:
            clusters.append(tuple(current))
            current = []
        current.append(event)
    if current:
        clusters.append(tuple(current))
    return tuple(clusters)


def _is_powershell_command_line(command_line: str) -> bool:
    lowered = command_line.lower()
    return any(marker in lowered for marker in POWERSHELL_COMMAND_MARKERS)


def _is_run_key(target_object: str | None) -> bool:
    """True when a registry path names a Run/RunOnce value (or the key itself)."""
    if not target_object:
        return False
    lowered = target_object.lower()
    for marker in RUN_KEY_MARKERS:
        index = lowered.find(marker)
        while index != -1:
            following = lowered[index + len(marker) : index + len(marker) + 1]
            if following in ("", "\\"):
                return True
            index = lowered.find(marker, index + 1)
    return False


def _granted_access_mask(value: str | None) -> int | None:
    """Parse Sysmon's ``GrantedAccess``; the documented rendering is 0x-prefixed hex."""
    if not value:
        return None
    text = value.strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text, 10)
    except ValueError:
        return None


def _looks_like_drop(target_filename: str) -> bool:
    lowered = target_filename.lower().replace("/", "\\")
    if not lowered.endswith(tuple(FILE_DROP_EXTENSIONS)):
        return False
    if all(marker in lowered for marker in FILE_DROP_USER_APP_DATA_MARKERS):
        return True
    return any(marker in lowered for marker in FILE_DROP_LOCATION_MARKERS)


def _detection(
    spec: RuleSpec,
    events: Sequence[NormalisedEvent],
    *,
    rationale: str,
    severity: Severity | None = None,
    attack_technique: str | None = None,
) -> Detection:
    """Build one detection from its trigger events, ordered canonically."""
    ordered = sorted(events, key=event_sort_key)
    triggers = tuple(event.evidence_id for event in ordered)
    return Detection(
        detection_id=make_detection_id(ordered[0].scenario_id, spec.rule_id, triggers[0]),
        rule_id=spec.rule_id,
        rule_version=spec.version,
        scenario_id=ordered[0].scenario_id,
        trigger_evidence_ids=triggers,
        window_start_utc=ordered[0].timestamp_utc,
        window_end_utc=ordered[-1].timestamp_utc,
        attack_technique=spec.attack_technique if attack_technique is None else attack_technique,
        severity=spec.severity if severity is None else severity,
        rationale=rationale,
    )


def _ordered(detections: Sequence[Detection]) -> tuple[Detection, ...]:
    """One deterministic order for a rule's output, independent of iteration order."""
    return tuple(sorted(detections, key=lambda detection: detection.detection_id))


_SPECS: tuple[RuleSpec, ...] = (
    RuleSpec(
        rule_id="R-AUTH-01",
        version="1",
        description="Failed-logon burst followed by a successful logon for the same account and host",
        attack_technique="T1110",
        severity="high",
        params={
            "min_failures": FAILED_LOGON_MIN_EVENTS,
            "window_seconds": FAILED_LOGON_WINDOW_SECONDS,
            "variant": "burst_then_success",
        },
    ),
    RuleSpec(
        rule_id="R-AUTH-02",
        version="1",
        description="Failed-logon burst for the same account and host with no successful logon",
        attack_technique="T1110",
        severity="medium",
        params={
            "min_failures": FAILED_LOGON_MIN_EVENTS,
            "window_seconds": FAILED_LOGON_WINDOW_SECONDS,
            "variant": "burst_only",
        },
    ),
    RuleSpec(
        rule_id="R-AUTH-03",
        version="1",
        description="Explicit-credential logon (Security 4648)",
        attack_technique="T1078",
        severity="low",
        params={"event_ids": str(SECURITY_EXPLICIT_CREDENTIAL_LOGON)},
    ),
    RuleSpec(
        rule_id="R-CRED-01",
        version="1",
        description="Sysmon 10 access to lsass.exe with a documented suspicious access mask",
        attack_technique="T1003.001",
        severity="high",
        params={
            "target_image_stem": LSASS_IMAGE_STEM,
            "masks": ",".join(f"0x{mask:06x}" for mask in sorted(LSASS_ACCESS_MASKS)),
        },
    ),
    RuleSpec(
        rule_id="R-EXEC-01",
        version="1",
        description="Discovery tooling: an enumeration burst, plus single hits",
        attack_technique="T1033",
        severity="low",
        params={
            "min_distinct_binaries": DISCOVERY_MIN_BINARIES,
            "window_seconds": DISCOVERY_WINDOW_SECONDS,
            "binaries": ",".join(sorted(DISCOVERY_BINARIES)),
            "burst_severity": "medium",
            "single_hit_severity": "low",
        },
    ),
    RuleSpec(
        rule_id="R-EXEC-02",
        version="1",
        description="PowerShell command line with an encoded, hidden-window or downloader marker",
        attack_technique="T1059.001",
        severity="high",
        params={
            "patterns": ",".join(name for name, _ in ENCODED_COMMAND_PATTERNS),
            "shell_markers": ",".join(POWERSHELL_COMMAND_MARKERS),
        },
    ),
    RuleSpec(
        rule_id="R-EXEC-03",
        version="1",
        description="Document, browser or WMI host spawning a shell or script engine",
        attack_technique="T1059",
        severity="high",
        params={
            "parents": ",".join(sorted(SUSPICIOUS_PARENT_IMAGES)),
            "children": ",".join(sorted(SHELL_IMAGES)),
        },
    ),
    RuleSpec(
        rule_id="R-FILE-01",
        version="1",
        description="Executable or script payload written under a user-writable directory (Sysmon 11)",
        attack_technique="T1105",
        severity="medium",
        params={
            "extensions": ",".join(sorted(FILE_DROP_EXTENSIONS)),
            "locations": "|".join(("\\Users\\*\\AppData\\", *FILE_DROP_LOCATION_MARKERS)),
        },
    ),
    RuleSpec(
        rule_id="R-LOG-01",
        version="1",
        description="Security audit log cleared (Security 1102)",
        attack_technique="T1070.001",
        severity="high",
        params={"event_ids": str(SECURITY_AUDIT_LOG_CLEARED)},
    ),
    RuleSpec(
        rule_id="R-PERSIST-01",
        version="1",
        description="Service installed (Security 4697)",
        attack_technique="T1543.003",
        severity="medium",
        params={"event_ids": str(SECURITY_SERVICE_INSTALLED)},
    ),
    RuleSpec(
        rule_id="R-PERSIST-02",
        version="1",
        description="Scheduled task created (Security 4698)",
        attack_technique="T1053.005",
        severity="medium",
        params={"event_ids": str(SECURITY_SCHEDULED_TASK_CREATED)},
    ),
    RuleSpec(
        rule_id="R-PERSIST-03",
        version="1",
        description="Run/RunOnce registry value set (Sysmon 13)",
        attack_technique="T1547.001",
        severity="medium",
        params={
            "event_ids": str(SYSMON_REGISTRY_SET_VALUE),
            "target_objects": ",".join(RUN_KEY_MARKERS),
        },
    ),
)

_SPEC_BY_ID: dict[str, RuleSpec] = {spec.rule_id: spec for spec in _SPECS}

RULES: tuple[Rule, ...] = tuple(
    sorted(
        (
            Rule(spec=_SPEC_BY_ID["R-AUTH-01"], fn=detect_failed_logon_then_success),
            Rule(spec=_SPEC_BY_ID["R-AUTH-02"], fn=detect_failed_logon_burst),
            Rule(spec=_SPEC_BY_ID["R-AUTH-03"], fn=detect_explicit_credential_logon),
            Rule(spec=_SPEC_BY_ID["R-CRED-01"], fn=detect_lsass_access),
            Rule(spec=_SPEC_BY_ID["R-EXEC-01"], fn=detect_discovery_binaries),
            Rule(spec=_SPEC_BY_ID["R-EXEC-02"], fn=detect_encoded_powershell),
            Rule(spec=_SPEC_BY_ID["R-EXEC-03"], fn=detect_suspicious_parent_shell),
            Rule(spec=_SPEC_BY_ID["R-FILE-01"], fn=detect_file_drop),
            Rule(spec=_SPEC_BY_ID["R-LOG-01"], fn=detect_audit_log_cleared),
            Rule(spec=_SPEC_BY_ID["R-PERSIST-01"], fn=detect_service_install),
            Rule(spec=_SPEC_BY_ID["R-PERSIST-02"], fn=detect_scheduled_task_created),
            Rule(spec=_SPEC_BY_ID["R-PERSIST-03"], fn=detect_run_key_set),
        ),
        key=lambda rule: rule.spec.rule_id,
    )
)
