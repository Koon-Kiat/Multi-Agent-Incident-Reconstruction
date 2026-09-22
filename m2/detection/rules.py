"""The conventional (non-LLM) detection rules.

Contract
--------

A rule is a **pure function** ``(events) -> tuple[Detection, ...]`` over one scenario's
normalised events, in ``(timestamp_ticks, evidence_id)`` ascending order. It reads no file,
holds no state, calls no network and never mutates an event. :data:`RULES` pairs each function
with its :class:`RuleSpec`, which carries the identity, description, ATT&CK technique,
severity and the **exact parameter values** the rule was run with.

**A detection's ``detection_id`` names its closing trigger** — the last of its triggers in
``(timestamp_ticks, evidence_id)`` order: ``<scenario>-<rule_id>-<last trigger id>``. Every rule
partitions the events it fires on **except R-AUTH-01**, which is anchored on each success and may
therefore report the failures that confirmed two close successes twice (task_plan.md T3.2,
"planner-fixed semantics", allows overlapping detections). The first trigger is not unique for
such a pair, the closing trigger is: the success for R-AUTH-01, the last failure of a burst for
R-AUTH-02, the last binary of a burst for R-EXEC-01. R-AUTH-01 and R-AUTH-02 never share a
failure. Case is folded **inside these rules only** — a basename, a key path and a command line
are detection heuristics, not query API behaviour, which stays exact and case-sensitive.

Failed-logon rules (R-AUTH-01/02)
---------------------------------

Both rules evaluate each ``(user, host)`` group independently, over that group's events in
``(timestamp_ticks, evidence_id)`` order, with ``W`` = :data:`FAILED_LOGON_WINDOW_SECONDS`.
R-AUTH-01 is evaluated first and R-AUTH-02 is defined as its complement over that group's
failures, so the two rules are **disjoint**: no failure is a trigger of both.

* **R-AUTH-01 is anchored on each success.** For every 4624 ``S`` of the group, ``F(S)`` is the
  4625s of the group with ``t(S) - W <= t(F) < t(S)``: the failures inside the W seconds that end
  at ``S``, half-open at both ends, so a failure logged at exactly ``t(S)`` (a concurrent
  attempt in the same 100 ns tick) does not count. When ``len(F(S)) >= FAILED_LOGON_MIN_EVENTS``,
  ``S`` yields one detection whose triggers are ``F(S)`` followed by ``S`` and whose window is
  ``[min t(F(S)), t(S)]``. Failures *after* ``S`` are none of this detection's business.
* **R-AUTH-02 is anchored on the failure burst**, over the group's **uncovered** failures only:
  the failures that are not a trigger of any R-AUTH-01 detection in the group. A burst starts at
  each uncovered failure ``t_i`` and covers the uncovered failures in ``[t_i, t_i + W)``; it
  qualifies with at least ``FAILED_LOGON_MIN_EVENTS`` of them, and overlapping qualifying bursts
  merge into one detection holding every uncovered failure of the merged segment. So the rule's
  claim — ``FAILED_LOGON_MIN_EVENTS`` failed logons not followed by a qualifying successful
  logon — is true of every detection it emits, and a burst no success can confirm is reported
  even when an unrelated 4624 sits nearby.

Neither decision depends on where a grouping window happened to start. A failure and a success
logged in the same 100 ns tick are not an ordered pair: R-AUTH-01's ``F(S)`` excludes the failure
because it is not strictly before ``S``, so that failure is uncovered and R-AUTH-02 judges it on
its own (three such failures are a burst). That is accepted and documented rather than
special-cased.

Windowed rule (``_windows``, used by R-EXEC-01)
-----------------------------------------------

R-EXEC-01 asks "do at least N qualifying events fall inside one window of W seconds". The scan is
greedy and sliding: it starts a candidate at the first event it has not consumed, takes every
following event within W seconds of that anchor, and keeps the window only when the candidate
meets the rule's count. A rejected candidate advances the scan by **one** event, so a stray early
binary can never hide a burst that starts after it, and a qualifying window is found wherever it
occurs. Accepted windows consume their events, so R-EXEC-01's windows never overlap and one
event triggers at most one burst detection.

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
``DISCOVERY_TECHNIQUES``                R-EXEC-01: the ATT&CK technique each discovery binary is attributed to.
``SUSPICIOUS_PARENT_IMAGES``            R-EXEC-03: document/browser/WMI hosts that should not spawn a shell.
``SHELL_IMAGES``                        R-EXEC-03: the scripting and proxy-execution children.
``SUSPICIOUS_PARENT_TECHNIQUE`` = T1204 R-EXEC-03: the artefact's technique field (user execution).
``SUSPICIOUS_PARENT_SECONDARY_TECHNIQUE`` = T1059
                                        R-EXEC-03: the spawned interpreter, named in the rationale.
``ENCODED_COMMAND_PATTERNS``            R-EXEC-02: encoded/hidden/downloader PowerShell markers.
``POWERSHELL_COMMAND_MARKERS``          R-EXEC-02: shell names; ``POWERSHELL_EXECUTABLES`` derives
                                        the whole-basename match from them, so a lookalike binary
                                        such as ``notpowershell.exe`` is not PowerShell (B6).
``LSASS_ACCESS_MASKS``                  R-CRED-01: documented PROCESS_VM_READ / ALL_ACCESS combos.
``FILE_DROP_EXTENSIONS``                R-FILE-01: executable and script payload types.
``FILE_DROP_USER_APP_DATA_MARKERS``     R-FILE-01: a path segment pair, so ``\\Users\\<x>\\AppData\\`` holds both.
``FILE_DROP_LOCATION_MARKERS``          R-FILE-01: the remaining user-writable drop locations.
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

# R-EXEC-01's ATT&CK attribution, one technique per discovery binary, so a detection is tagged
# with the technique of the binary that actually ran instead of one rule-wide label. The plan
# named T1033/T1082/T1016; the remaining names are the standard ATT&CK techniques for those
# tools, mapped here rather than mislabelled. A tool that covers several kinds of discovery gets
# the technique ATT&CK lists for its dominant use (``net view`` enumerates network shares).
DISCOVERY_TECHNIQUES: dict[str, str] = {
    "whoami": "T1033",  # System Owner/User Discovery
    "quser": "T1033",
    "qwinsta": "T1033",
    "systeminfo": "T1082",  # System Information Discovery
    "tasklist": "T1057",  # Process Discovery
    "ipconfig": "T1016",  # System Network Configuration Discovery
    "arp": "T1016",
    "route": "T1016",
    "net": "T1135",  # Network Share Discovery
    "net1": "T1135",
    "nltest": "T1482",  # Domain Trust Discovery
    "dsquery": "T1087.002",  # Domain Account Discovery
}

SUSPICIOUS_PARENT_IMAGES = frozenset(
    {"winword", "excel", "powerpnt", "outlook", "msedge", "chrome", "firefox", "wmiprvse", "mshta"}
)

SHELL_IMAGES = frozenset({"cmd", "powershell", "pwsh", "wscript", "cscript", "rundll32", "regsvr32"})

# R-EXEC-03 is user execution (T1204) that reaches a command/scripting interpreter (T1059). The
# artefact's ``attack_technique`` field carries one technique, so it carries the primary T1204,
# and the rationale names both. Both values are also recorded in the rule's ``params``.
SUSPICIOUS_PARENT_TECHNIQUE = "T1204"
SUSPICIOUS_PARENT_SECONDARY_TECHNIQUE = "T1059"

# ``-enc``/``-EncodedCommand`` is matched as a parameter token, so ``-Encoding`` never matches.
ENCODED_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("-enc/-EncodedCommand", re.compile(r"(?i)(?:^|[\s\"'])-e(?:nc|ncodedcommand)(?=[\s\"']|$)")),
    ("FromBase64String", re.compile(r"(?i)frombase64string")),
    ("-w/-WindowStyle hidden", re.compile(r"(?i)-\s*w(?:indowstyle)?\s+hidden")),
    ("IEX/Invoke-Expression", re.compile(r"(?i)(?:\biex\b|invoke-expression)")),
    ("DownloadString", re.compile(r"(?i)downloadstring")),
)

POWERSHELL_COMMAND_MARKERS = ("powershell", "pwsh")

# R-EXEC-02 applies only to a real PowerShell process. The shell names are matched as whole
# executable basenames (the image's, or a command-line token's), not as substrings: a substring
# match fired on `notpowershell.exe` and `pwshish`, which are not PowerShell at all. Derived from
# the marker vocabulary above, so no new shell name is introduced here.
POWERSHELL_EXECUTABLES = frozenset(f"{marker}.exe" for marker in POWERSHELL_COMMAND_MARKERS)

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
    """R-AUTH-01: every successful logon with a failed-logon burst in front of it (T1110).

    Anchored on each success, per task_plan.md T3.2 (see the module docstring): the confirming
    failures are the 4625s of the same ``(user, host)`` group in ``[t(S) - W, t(S))``. Two close
    successes can confirm the same failures, and each still yields its own detection with its own
    ``detection_id`` (named after its success). The failures these detections trigger on are
    exactly the complement R-AUTH-02 works from (amendment A1).
    """
    spec = _SPEC_BY_ID["R-AUTH-01"]
    detections: list[Detection] = []
    for account in _failed_logon_accounts(events):
        failures, successes = _failed_logon_group(events, account)
        for success in successes:
            confirming = _confirming_failures(success, failures)
            if len(confirming) < FAILED_LOGON_MIN_EVENTS:
                continue
            detections.append(
                _detection(
                    spec,
                    (*confirming, success),
                    rationale=(
                        f"{len(confirming)} failed logons for {_describe_account(*account)} inside "
                        f"{FAILED_LOGON_WINDOW_SECONDS}s, followed by a successful logon "
                        "for the same account"
                    ),
                )
            )
    return _ordered(detections)


def detect_failed_logon_burst(events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    """R-AUTH-02: every failed-logon burst no R-AUTH-01 detection claims (T1110).

    Anchored on the burst, per task_plan.md T3.2's "Planner amendment A1" (see the module
    docstring): the rule sees only the group's **uncovered** failures — those no R-AUTH-01
    detection triggers on — and reports each merged run of ``FAILED_LOGON_MIN_EVENTS`` uncovered
    failures that fit inside one ``W``-second window. Because the triggers are exactly the
    failures no success could confirm, the rule's claim is true by construction and the two
    failed-logon rules never share a failure.
    """
    spec = _SPEC_BY_ID["R-AUTH-02"]
    claimed = _claimed_trigger_ids(events)
    detections: list[Detection] = []
    for account in _failed_logon_accounts(events):
        failures, _ = _failed_logon_group(events, account)
        for segment in _uncovered_burst_segments(failures, claimed):
            detections.append(
                _detection(
                    spec,
                    segment,
                    rationale=(
                        f"{len(segment)} failed logons for {_describe_account(*account)} "
                        f"(window_span_seconds={_span_seconds_text(segment)}), not "
                        "followed by a qualifying successful logon (R-AUTH-01)"
                    ),
                )
            )
    return _ordered(detections)


def _span_seconds_text(segment: Sequence[NormalisedEvent]) -> str:
    """A detection's own span in seconds, to the exact 100 ns, as integer arithmetic.

    A merged R-AUTH-02 segment can span **more** than ``FAILED_LOGON_WINDOW_SECONDS`` when bursts
    chain, so the rationale names the real span (planner amendment A2) instead of leaving the
    reader to infer one window. Rendered from the tick difference because ``datetime``/``float``
    would round the 100 ns tail away (AGENTS.md I2), and always with 7 fractional digits so two
    spans of different precision cannot look alike.
    """
    span_ticks = segment[-1].timestamp_ticks - segment[0].timestamp_ticks
    return f"{span_ticks // TICKS_PER_SECOND}.{span_ticks % TICKS_PER_SECOND:07d}"


def _claimed_trigger_ids(events: Sequence[NormalisedEvent]) -> frozenset[str]:
    """Every evidence id an R-AUTH-01 detection triggers on, for A1's uncovered complement.

    Taking the ids from the rule's own detections (rather than re-deriving ``F(S)``) is what
    makes "a trigger of an R-AUTH-01 detection" literally the condition A1 names, and keeps the
    two rules disjoint even if R-AUTH-01's anchor rule changes later.
    """
    return frozenset(
        evidence_id
        for detection in detect_failed_logon_then_success(events)
        for evidence_id in detection.trigger_evidence_ids
    )


def _failed_logon_accounts(
    events: Sequence[NormalisedEvent],
) -> tuple[tuple[str | None, str | None], ...]:
    """Every ``(user, host)`` group holding a failed logon, in a stable group order."""
    accounts = {
        _account(event)
        for event in events
        if _matches_event_id(event, SECURITY_CHANNEL, SECURITY_FAILED_LOGON)
    }
    return tuple(sorted(accounts, key=_account_sort_key))


def _failed_logon_group(
    events: Sequence[NormalisedEvent], account: tuple[str | None, str | None]
) -> tuple[list[NormalisedEvent], list[NormalisedEvent]]:
    """One group's failed and successful logons, both in ``(timestamp_ticks, evidence_id)`` order."""
    failures = sorted(
        (
            event
            for event in events
            if _account(event) == account
            and _matches_event_id(event, SECURITY_CHANNEL, SECURITY_FAILED_LOGON)
        ),
        key=event_sort_key,
    )
    successes = sorted(
        (
            event
            for event in events
            if _account(event) == account
            and _matches_event_id(event, SECURITY_CHANNEL, SECURITY_SUCCESSFUL_LOGON)
        ),
        key=event_sort_key,
    )
    return failures, successes


def _confirming_failures(
    success: NormalisedEvent, failures: Sequence[NormalisedEvent]
) -> tuple[NormalisedEvent, ...]:
    """``F(S)``: the failures in ``[t(S) - W, t(S))`` — half-open at both ends (T3.2).

    A failure logged in the same 100 ns tick as the success is *not* strictly before it, so it
    does not confirm the burst. ``failures`` must already be ordered by
    ``(timestamp_ticks, evidence_id)``, which fixes the order of the returned tuple.
    """
    span = FAILED_LOGON_WINDOW_SECONDS * TICKS_PER_SECOND
    return tuple(
        event
        for event in failures
        if success.timestamp_ticks - span <= event.timestamp_ticks < success.timestamp_ticks
    )


def _uncovered_burst_segments(
    failures: Sequence[NormalisedEvent], claimed: frozenset[str]
) -> tuple[tuple[NormalisedEvent, ...], ...]:
    """Every merged burst of the failures no R-AUTH-01 detection claims (A1).

    A candidate burst starts at each uncovered failure ``t_i`` and covers the uncovered failures
    in ``[t_i, t_i + W)`` — the anchor is included, the far end is not, exactly as
    :func:`_confirming_failures` is half-open at the other end. A candidate qualifies when it
    holds :data:`FAILED_LOGON_MIN_EVENTS` failures; candidates that overlap in the uncovered
    sequence merge into one segment, and a segment's triggers are every uncovered failure it
    spans, in ``(timestamp_ticks, evidence_id)`` order.
    """
    span = FAILED_LOGON_WINDOW_SECONDS * TICKS_PER_SECOND
    uncovered = [event for event in failures if event.evidence_id not in claimed]
    segments: list[list[int]] = []
    for anchor in range(len(uncovered)):
        end = anchor
        while end < len(uncovered) and uncovered[end].timestamp_ticks - uncovered[anchor].timestamp_ticks < span:
            end += 1
        if end - anchor < FAILED_LOGON_MIN_EVENTS:
            continue
        if segments and anchor < segments[-1][1]:
            segments[-1][1] = max(segments[-1][1], end)
        else:
            segments.append([anchor, end])
    return tuple(tuple(uncovered[start:end]) for start, end in segments)


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

    Every detection carries the ATT&CK technique of the binary it reports
    (:data:`DISCOVERY_TECHNIQUES`). A burst spans several binaries and therefore several
    techniques, so its field carries the technique of its first trigger and its rationale names
    every technique the burst covers.
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
        for window in _windows(group, DISCOVERY_WINDOW_SECONDS, _is_discovery_burst):
            binaries = sorted({_process_image_stem(event) for event in window})
            techniques = sorted({DISCOVERY_TECHNIQUES[stem] for stem in binaries})
            in_a_burst.update(event.evidence_id for event in window)
            detections.append(
                _detection(
                    spec,
                    window,
                    severity="medium",
                    attack_technique=DISCOVERY_TECHNIQUES[_process_image_stem(window[0])],
                    rationale=(
                        f"{len(binaries)} distinct discovery binaries ({', '.join(binaries)}) run by "
                        f"{_describe_account(*account)} inside {DISCOVERY_WINDOW_SECONDS}s, "
                        f"covering {'/'.join(techniques)}"
                    ),
                )
            )
    detections.extend(
        _detection(
            spec,
            (event,),
            severity="low",
            attack_technique=DISCOVERY_TECHNIQUES[_process_image_stem(event)],
            rationale=(
                f"discovery binary {_process_image_stem(event)!r} "
                f"({DISCOVERY_TECHNIQUES[_process_image_stem(event)]}) run by "
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
        if not command_line or not _is_powershell_command_line(command_line, _process_image(event)):
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
    """R-EXEC-03: a document/browser/WMI host spawning a shell or script engine (T1204/T1059).

    The detection's ``attack_technique`` is the primary :data:`SUSPICIOUS_PARENT_TECHNIQUE`
    (user execution) and its rationale names the secondary
    :data:`SUSPICIOUS_PARENT_SECONDARY_TECHNIQUE` the spawned shell belongs to.
    """
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
                    rationale=(
                        f"parent image {parent_image!r} spawned {child!r} "
                        f"({SUSPICIOUS_PARENT_TECHNIQUE}/{SUSPICIOUS_PARENT_SECONDARY_TECHNIQUE})"
                    ),
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


def _is_discovery_burst(window: Sequence[NormalisedEvent]) -> bool:
    """R-EXEC-01: does this candidate window hold enough *distinct* discovery binaries?"""
    return len({_process_image_stem(event) for event in window}) >= DISCOVERY_MIN_BINARIES


def _windows(
    events: Sequence[NormalisedEvent],
    window_seconds: int,
    qualifies: Callable[[Sequence[NormalisedEvent]], bool],
) -> tuple[tuple[NormalisedEvent, ...], ...]:
    """Every qualifying window ``[t, t + window_seconds]``, greedily and without overlap.

    The scan starts a candidate at the first event it has not consumed and takes every following
    event within ``window_seconds`` of that anchor. A candidate the predicate accepts consumes
    its own events, so no later candidate can reuse them; a candidate it rejects advances the
    scan by a **single** event.

    Anchoring a candidate at each unconsumed event is what makes the rule fire on any qualifying
    window rather than only on one that begins at the account's first event: a stray early
    ``whoami`` can no longer hide a burst that starts after it. Consumed windows never overlap,
    which keeps one event a trigger of at most one R-EXEC-01 burst detection.
    """
    ordered = sorted(events, key=event_sort_key)
    span = window_seconds * TICKS_PER_SECOND
    windows: list[tuple[NormalisedEvent, ...]] = []
    index = 0
    while index < len(ordered):
        end = index
        while end < len(ordered) and ordered[end].timestamp_ticks - ordered[index].timestamp_ticks <= span:
            end += 1
        candidate = tuple(ordered[index:end])
        if qualifies(candidate):
            windows.append(candidate)
            index = end
        else:
            index += 1
    return tuple(windows)


def _is_powershell_command_line(command_line: str, image: str | None = None) -> bool:
    """True when the process is PowerShell: the image names one, or a command-line token does.

    The comparison is against whole executable basenames, so ``notpowershell.exe`` and
    ``pwshish`` never match however their text contains ``powershell`` or ``pwsh`` as a substring.
    """
    if _executable_name(image) in POWERSHELL_EXECUTABLES:
        return True
    return any(_executable_name(token) in POWERSHELL_EXECUTABLES for token in _command_line_tokens(command_line))


def _executable_name(value: str | None) -> str:
    """The lower-cased basename of a Windows image path or command-line token, extension included."""
    if not value:
        return ""
    return value.replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def _command_line_tokens(command_line: str) -> tuple[str, ...]:
    """Split a command line on whitespace and quotes, so a quoted executable token is its own."""
    return tuple(part for part in re.split(r"[\s\"']+", command_line) if part)


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
    """Build one detection from its trigger events, ordered canonically.

    The ``detection_id`` names the **closing** trigger (``triggers[-1]``), the detection's last
    event in canonical order — see :mod:`m2.detection.schema` for why the first trigger is not
    always unique (R-AUTH-01's overlapping detections).
    """
    ordered = sorted(events, key=event_sort_key)
    triggers = tuple(event.evidence_id for event in ordered)
    return Detection(
        detection_id=make_detection_id(ordered[0].scenario_id, spec.rule_id, triggers[-1]),
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
        version="4",
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
        version="5",
        description="Failed-logon burst for the same account and host that no successful logon confirms",
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
        version="2",
        description="Discovery tooling: an enumeration burst, plus single hits",
        attack_technique="T1033",
        severity="low",
        params={
            "min_distinct_binaries": DISCOVERY_MIN_BINARIES,
            "window_seconds": DISCOVERY_WINDOW_SECONDS,
            "binaries": ",".join(sorted(DISCOVERY_BINARIES)),
            # Each detection is tagged with the technique of its own binary; a burst's field is
            # its first binary's, and its rationale names every technique the burst covers.
            "techniques": ",".join(f"{stem}={DISCOVERY_TECHNIQUES[stem]}" for stem in sorted(DISCOVERY_BINARIES)),
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
        version="2",
        description="Document, browser or WMI host spawning a shell or script engine",
        attack_technique=SUSPICIOUS_PARENT_TECHNIQUE,
        severity="high",
        params={
            "parents": ",".join(sorted(SUSPICIOUS_PARENT_IMAGES)),
            "children": ",".join(sorted(SHELL_IMAGES)),
            # The field carries the primary technique; both are recorded here and in rationale.
            "techniques": f"{SUSPICIOUS_PARENT_TECHNIQUE},{SUSPICIOUS_PARENT_SECONDARY_TECHNIQUE}",
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
