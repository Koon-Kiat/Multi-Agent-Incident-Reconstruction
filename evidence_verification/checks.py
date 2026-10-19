"""Deterministic claim checks: does the corpus actually support what a claim says?

Every check reads recorded events only. None consults an agent finding, a detection, an
orchestration trace or an answer key. A check returns a :class:`Check` whose ``grade`` says what a
failure means for the verdict:

``reject``        the claim rests on evidence that does not resolve in its scenario, or on evidence
                  that contradicts it. Verdict ``rejected``.
``insufficient``  every reference resolves and nothing contradicts the claim, but the cited records
                  do not show the activity the claim names. Verdict ``unverified``.
``partial``       the core activity is shown, but a secondary assertion (an entity, a time, a
                  technique, a link, an ordering) is not. Verdict ``partially_supported``.

The verdict is the worst grade among failed checks, in that order. A claim with no failed check is
``confirmed``: supported *as stated*. Support is not a judgement about whether the activity is
malicious, so a benign lookalike whose records are real and as described is confirmed.
"""

from __future__ import annotations

from event_processing.identity import authentication_principals

import re
from decimal import Decimal
from dataclasses import dataclass, field
from typing import Literal

from event_processing.ids import parse_evidence_id
from event_processing.query import EventStore
from event_processing.schema import NormalisedEvent
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks
from incident_reconstruction.claims import Claim, Reconstruction

from . import facts
from .facts import SECURITY, SYSMON

Grade = Literal["reject", "insufficient", "partial"]
Status = Literal["pass", "fail", "not_applicable"]

CONFLICT_TYPES = (
    "unresolved_reference", "invalid_reference", "scenario_mismatch", "contradicted_by_evidence",
    "structure_unsupported", "time_mismatch", "entity_mismatch", "ordering_conflict",
    "unsupported_assertion", "link_unsupported",
)

# ---------------------------------------------------------------------------------------------
# Vocabulary the structure and ATT&CK checks recognise. The sets mirror the Event Processing &
# Detection Engine's published rule vocabulary so a claim built from a detection is judged by the
# same definition of "discovery binary" or "file drop"; a test keeps them from drifting apart.
# ---------------------------------------------------------------------------------------------

DISCOVERY_TECHNIQUES = {
    "whoami": "T1033", "quser": "T1033", "qwinsta": "T1033", "systeminfo": "T1082", "tasklist": "T1057",
    "ipconfig": "T1016", "arp": "T1016", "route": "T1016", "net": "T1135", "net1": "T1135",
    "nltest": "T1482", "dsquery": "T1087.002",
}
SHELL_IMAGES = frozenset({"cmd", "powershell", "pwsh", "wscript", "cscript", "rundll32", "regsvr32"})
POWERSHELL_IMAGES = frozenset({"powershell", "pwsh"})
SUSPICIOUS_PARENTS = frozenset({"winword", "excel", "powerpnt", "outlook", "msedge", "chrome", "firefox",
                                "wmiprvse", "mshta"})
FILE_DROP_EXTENSIONS = (".exe", ".dll", ".ps1", ".bat", ".vbs", ".js")
USER_WRITABLE_MARKERS = ("\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\")
RUN_KEY_MARKERS = ("\\currentversion\\run", "\\currentversion\\runonce")
POWERSHELL_ABUSE = re.compile(
    r"(?i)(?:^|[\s\"'])-e(?:nc|ncodedcommand)(?=[\s\"']|$)|frombase64string|-\s*w(?:indowstyle)?\s+hidden|"
    r"\biex\b|invoke-expression|downloadstring")
LSASS_STEM = "lsass"

# How far a cited record may lie outside the span a claim states. The orchestrator spans a stage by its
# trigger events and cites related records up to 60 s (endpoint) or 120 s (account) away, so a tight bound
# would penalise that design rather than catch a claim whose times are wrong. Fixed in the evaluation
# protocol before any scored run; it was set from plumbing runs, never from the answer key.
SPAN_TOLERANCE_SECONDS = 120

NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
                "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z")
_CHANNEL_EVENT = re.compile(r"\b(Security|Sysmon)\s+(?:[Ee]vent\s*(?:ID\s*)?)?(\d{1,5})\b")
_BARE_EVENT = re.compile(r"\b[Ee]vent\s*ID\s*[:=]?\s*(\d{1,5})\b")
_FILE_TOKEN = re.compile(
    r"(?<![\w\\/.-])(?:[A-Za-z]:\\[^\s\"'<>|?*,;]+|[\w$.-]+\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|js|scr|sys|dit|jfm|lnk))",
    re.I)
_FAILED_COUNT = re.compile(
    r"\b(\d+|" + "|".join(NUMBER_WORDS) + r")\s+(?:consecutive\s+|repeated\s+|separate\s+)?failed\s+"
    r"(?:interactive\s+)?(?:logon|login|authentication|sign-in)s?\b", re.I)
_FAILURE_SEPARATION = re.compile(
    r"\bfailed\s+(?:logon|login|authentication|sign-in)s?\b[^.!?;\n]{0,100}?\b"
    r"(\d+(?:\.\d+)?|" + "|".join(NUMBER_WORDS) + r")\s+"
    r"(milliseconds?|seconds?|minutes?)\s+apart\b", re.I)
_AUTH_ORDER = re.compile(
    r"\b(failed|successful)\s+(?:logon|login|authentication|sign-in)s?\b"
    r"([^.!?;\n]{0,100}?)\b(preceded|before|followed\s+by|after)\b[^.!?;\n]{0,60}?"
    r"\b(failed|successful)\s+(?:logon|login|authentication|sign-in)s?\b",re.I)


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    grade: Grade
    detail: str = ""
    conflict_type: str = ""
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status == "fail" and self.conflict_type not in CONFLICT_TYPES:
            raise ValueError(f"a failed check needs a conflict type from {CONFLICT_TYPES}")


def _pass(name: str, grade: Grade, detail: str = "") -> Check:
    return Check(name, "pass", grade, detail)


def _na(name: str, grade: Grade, detail: str) -> Check:
    return Check(name, "not_applicable", grade, detail)


def _fail(name: str, grade: Grade, conflict_type: str, detail: str, ids: tuple[str, ...] = ()) -> Check:
    return Check(name, "fail", grade, detail, conflict_type, ids)


@dataclass
class ClaimEvidence:
    """What one claim cites, looked up by the verifier itself."""

    claim: Claim
    cited: dict[str, NormalisedEvent] = field(default_factory=dict)
    context: dict[str, NormalisedEvent] = field(default_factory=dict)
    problems: list[Check] = field(default_factory=list)

    def cited_events(self) -> list[NormalisedEvent]:
        return sorted(self.cited.values(), key=lambda e: (e.timestamp_ticks, e.evidence_id))

    def context_events(self) -> list[NormalisedEvent]:
        return sorted(self.context.values(), key=lambda e: (e.timestamp_ticks, e.evidence_id))


# ---------------------------------------------------------------------------------------------
# 1. Reference resolution
# ---------------------------------------------------------------------------------------------

def gather(claim: Claim, scenario_id: str, store: EventStore) -> ClaimEvidence:
    """Resolve every cited and context ID through the store; record each failure as a check."""
    gathered = ClaimEvidence(claim)
    seen: dict[str, str] = {}
    for label, ids, target in (("cited", claim.evidence_ids, gathered.cited),
                               ("context", claim.context_evidence_ids, gathered.context)):
        for evidence_id in ids:
            if evidence_id in seen and seen[evidence_id] != "ok":
                continue  # one failure per ID, however many times it is cited
            try:
                parsed = parse_evidence_id(evidence_id)
            except ValueError:
                seen[evidence_id] = "invalid"
                gathered.problems.append(_fail(
                    "reference_resolves", "reject", "invalid_reference",
                    f"{evidence_id!r} is not a well-formed scenario-scoped evidence ID", (evidence_id,)))
                continue
            if parsed.scenario_id != scenario_id:
                seen[evidence_id] = "scenario"
                gathered.problems.append(_fail(
                    "reference_resolves", "reject", "scenario_mismatch",
                    f"{evidence_id} belongs to scenario {parsed.scenario_id}, not {scenario_id}; record numbers "
                    "repeat across scenarios, so the reference cannot support this claim", (evidence_id,)))
                continue
            result = store.lookup(evidence_id)
            if result.status != "found" or result.event is None:
                seen[evidence_id] = "missing"
                gathered.problems.append(_fail(
                    "reference_resolves", "reject", "unresolved_reference",
                    f"{evidence_id} does not exist in the {scenario_id} corpus ({label} reference)", (evidence_id,)))
                continue
            seen[evidence_id] = "ok"
            target[evidence_id] = result.event
    return gathered


def resolution_check(gathered: ClaimEvidence) -> Check:
    if gathered.problems:
        return gathered.problems[0]
    count = len(gathered.cited) + len(set(gathered.context) - set(gathered.cited))
    return _pass("reference_resolves", "reject", f"all {count} referenced records exist in the claim's scenario")


# ---------------------------------------------------------------------------------------------
# 2. Time
# ---------------------------------------------------------------------------------------------

def time_checks(gathered: ClaimEvidence) -> list[Check]:
    claim = gathered.claim
    try:
        first, last = iso_to_ticks(claim.first_utc), iso_to_ticks(claim.last_utc)
    except ValueError:
        return [_fail("span_is_valid", "reject", "contradicted_by_evidence",
                      f"claim span {claim.first_utc!r}..{claim.last_utc!r} is not a valid UTC interval")]
    if first > last:
        return [_fail("span_is_valid", "reject", "contradicted_by_evidence",
                      f"claim span starts ({claim.first_utc}) after it ends ({claim.last_utc})")]
    checks = [_pass("span_is_valid", "reject")]
    context = gathered.context_events()
    ticks = {event.timestamp_ticks for event in context}
    missing = [value for value, ts in ((claim.first_utc, first), (claim.last_utc, last)) if ts not in ticks]
    if missing:
        checks.append(_fail("span_endpoints_recorded", "partial", "time_mismatch",
                            f"no referenced record is timestamped {' or '.join(missing)}; the stated span edge "
                            "is not attested by the evidence"))
    else:
        checks.append(_pass("span_endpoints_recorded", "partial", "both span edges are recorded event times"))
    slack = SPAN_TOLERANCE_SECONDS * TICKS_PER_SECOND
    outside = [event.evidence_id for event in gathered.cited_events()
               if not first - slack <= event.timestamp_ticks <= last + slack]
    if outside:
        checks.append(_fail("cited_events_inside_span", "partial", "time_mismatch",
                            f"{len(outside)} cited record(s) lie more than {SPAN_TOLERANCE_SECONDS} s outside the "
                            "claim's own span", tuple(outside[:5])))
    else:
        checks.append(_pass("cited_events_inside_span", "partial",
                            f"every cited record is within {SPAN_TOLERANCE_SECONDS} s of the claim's span"))
    return checks


# ---------------------------------------------------------------------------------------------
# 3. Entities
# ---------------------------------------------------------------------------------------------

def entity_checks(gathered: ClaimEvidence) -> list[Check]:
    claim = gathered.claim
    events = gathered.context_events()
    pool = facts.value_pool(events)
    lowered = facts.folded(pool)
    missing: list[str] = []
    total = 0
    for kind, values in (("account", claim.entities.accounts), ("host", claim.entities.hosts),
                         ("process", claim.entities.processes), ("process GUID", claim.entities.process_guids),
                         ("file", claim.entities.files)):
        for value in values:
            total += 1
            if not facts.grounded(value, pool, lowered):
                missing.append(f"{kind} {value}")
    checks: list[Check] = []
    if missing:
        checks.append(_fail("entities_recorded", "partial", "entity_mismatch",
                            f"{len(missing)} of {total} claimed entities appear in no referenced record: "
                            + "; ".join(missing[:4])))
    else:
        checks.append(_pass("entities_recorded", "partial",
                            f"all {total} claimed entities appear in the referenced records" if total
                            else "the claim names no entities"))
    # A host label may be recorded as an FQDN in one source and a short name in another; compare labels.
    claim_hosts = {h.split(".")[0].casefold() for h in claim.entities.hosts}
    evidence_hosts = {e.host.split(".")[0].casefold() for e in gathered.cited_events() if e.host}
    if claim_hosts and evidence_hosts and not claim_hosts & evidence_hosts:
        checks.append(_fail("host_agrees", "reject", "contradicted_by_evidence",
                            f"the claim names host(s) {sorted(claim.entities.hosts)} but every cited record is "
                            f"from {sorted(evidence_hosts)}"))
    else:
        checks.append(_pass("host_agrees", "reject"))
    return checks


# ---------------------------------------------------------------------------------------------
# 4. What the claim text asserts
# ---------------------------------------------------------------------------------------------

def text_checks(gathered: ClaimEvidence) -> list[Check]:
    claim = gathered.claim
    text = claim.claim_text
    context = gathered.context_events()
    known_ticks = {e.timestamp_ticks for e in context}
    for edge in (claim.first_utc, claim.last_utc):
        try:
            known_ticks.add(iso_to_ticks(edge))
        except ValueError:
            pass  # an invalid span is already a failed span_is_valid check
    checks: list[Check] = []

    unmatched_times = []
    for stamp in dict.fromkeys(_ISO.findall(text)):
        try:
            if iso_to_ticks(stamp) not in known_ticks:
                unmatched_times.append(stamp)
        except ValueError:
            unmatched_times.append(stamp)
    checks.append(_fail("text_times_recorded", "partial", "time_mismatch",
                        "the claim text states time(s) no referenced record or span edge carries: "
                        + ", ".join(unmatched_times[:3])) if unmatched_times
                  else _pass("text_times_recorded", "partial"))

    absent = []
    for channel_word, number in _CHANNEL_EVENT.findall(text):
        channel = SECURITY if channel_word == "Security" else SYSMON
        if not any(e.channel == channel and e.source_event_id == int(number) for e in context):
            absent.append(f"{channel_word} {number}")
    for number in _BARE_EVENT.findall(text):
        if not any(e.source_event_id == int(number) for e in context):
            absent.append(f"Event ID {number}")
    checks.append(_fail("text_event_types_recorded", "partial", "unsupported_assertion",
                        "the claim text names event type(s) none of its referenced records is: "
                        + ", ".join(dict.fromkeys(absent))) if absent
                  else _pass("text_event_types_recorded", "partial"))

    pool = facts.value_pool(context)
    haystack = "\n".join(pool).casefold() + "\n" + "\n".join(e.raw_xml for e in context).casefold()
    # Unquoted Windows paths can run to sentence/closing punctuation. Prefer
    # the literal match (preserving a recorded unusual name); otherwise remove
    # prose punctuation without changing internal dots or path components.
    unrecorded = [token for token in dict.fromkeys(_FILE_TOKEN.findall(text))
                  if token.casefold() not in haystack
                  and token.rstrip(".)]}:").casefold() not in haystack]
    checks.append(_fail("text_files_recorded", "partial", "unsupported_assertion",
                        "the claim text names file/process(es) that no referenced record contains: "
                        + ", ".join(unrecorded[:3])) if unrecorded
                  else _pass("text_files_recorded", "partial"))

    count_match = _FAILED_COUNT.search(text)
    if count_match:
        raw = count_match.group(1).casefold()
        claimed = int(raw) if raw.isdigit() else NUMBER_WORDS[raw]
        cited = sum(1 for e in gathered.cited_events() if e.channel == SECURITY and e.source_event_id == 4625)
        in_context = sum(1 for e in context if e.channel == SECURITY and e.source_event_id == 4625)
        if claimed != cited:
            checks.append(_fail("text_failed_logon_count", "partial", "unsupported_assertion",
                                f"the claim text says {claimed} failed logons; {cited} cited record(s) are failed "
                                f"logons ({in_context} in the stage's context)"))
        else:
            checks.append(_pass("text_failed_logon_count", "partial", f"{claimed} failed logons cited"))
    vague = re.search(r"\b(dozens|hundreds|thousands)\s+(?:of\s+)?failed\s+logons?\b",text,re.I)
    if vague:
        minimum={"dozens":24,"hundreds":200,"thousands":2000}[vague.group(1).casefold()]
        cited=sum(e.channel==SECURITY and e.source_event_id==4625 for e in gathered.cited_events())
        if cited<minimum:
            checks.append(_fail("text_failed_logon_count","partial","unsupported_assertion",
                f"the claim says {vague.group(1)}, requiring at least {minimum} cited failed logons; found {cited}"))
    for separation in _FAILURE_SEPARATION.finditer(text):
        raw, unit = separation.groups()
        duration = Decimal(NUMBER_WORDS[raw.casefold()]) if raw.casefold() in NUMBER_WORDS else Decimal(raw)
        seconds = duration * ({"millisecond": Decimal("0.001"), "second": Decimal(1), "minute": Decimal(60)}[unit.casefold().rstrip("s")])
        failures = [e for e in gathered.cited_events() if e.channel == SECURITY and e.source_event_id == 4625]
        # "Apart" states a separation between two failures. More records make
        # that pair ambiguous; do not silently choose whichever pair agrees.
        if len(failures) != 2 or Decimal(failures[-1].timestamp_ticks - failures[0].timestamp_ticks) != seconds * TICKS_PER_SECOND:
            checks.append(_fail("text_failed_logon_separation", "partial", "time_mismatch",
                                "the stated separation is not supported by exactly two cited failed-logon timestamps"))
        else:
            checks.append(_pass("text_failed_logon_separation", "partial", "the cited failure timestamps agree"))
    for ordering in _AUTH_ORDER.finditer(text):
        first,between,relation,second=ordering.groups()
        if first.casefold()==second.casefold() or re.search(r"\b(?:not|never)\b",between,re.I):
            continue  # Do not infer an order from negation or an ambiguous same-type pair.
        types={"failed":4625,"successful":4624}
        left=[e.timestamp_ticks for e in gathered.cited_events() if e.channel==SECURITY and e.source_event_id==types[first.casefold()]]
        right=[e.timestamp_ticks for e in gathered.cited_events() if e.channel==SECURITY and e.source_event_id==types[second.casefold()]]
        if relation.casefold()=="after":
            left,right=right,left
        if not left or not right or max(left)>=min(right):
            checks.append(_fail("text_logon_order","partial","ordering_conflict",
                                "the cited timestamps do not establish the successful/failed logon order stated in the text"))
        else:
            checks.append(_pass("text_logon_order","partial","the stated order agrees with the cited timestamps"))
    return checks


# ---------------------------------------------------------------------------------------------
# 5. The activity the claim's type names
# ---------------------------------------------------------------------------------------------

def _drops_file(event: NormalisedEvent) -> bool:
    target = event.event_data.get("TargetFilename", "")
    lowered = target.casefold()
    return (event.channel == SYSMON and event.source_event_id == 11 and lowered.endswith(FILE_DROP_EXTENSIONS)
            and any(marker in lowered for marker in USER_WRITABLE_MARKERS))


def _failed_then_success(events: list[NormalisedEvent], minimum: int, need_success: bool) -> tuple[bool, str]:
    failures = {}
    successes = {}
    principals = authentication_principals(events)
    for event in events:
        if event.channel != SECURITY:
            continue
        account = principals.get(event.evidence_id)
        if event.source_event_id == 4625:
            failures.setdefault(account, []).append(event)
        elif event.source_event_id == 4624:
            successes.setdefault(account, []).append(event)
    best = max(failures.values(), key=len, default=[])
    if len(best) < minimum:
        return False, f"at least {minimum} failed logons for one account (found {len(best)})"
    if not need_success:
        return True, f"{len(best)} failed logons for one account"
    for account, group in failures.items():
        for success in successes.get(account, []):
            preceding = [f for f in group if f.timestamp_ticks < success.timestamp_ticks]
            if len(preceding) >= minimum:
                # Every cited failure in this principal's sequence must precede
                # its successful outcome, not merely the first one.
                if len(preceding) == len(group):
                    return True, f"{len(preceding)} failed logons then a successful logon for the same principal"
    return False, f"at least {minimum} failures for one principal strictly before a successful outcome"


STRUCTURES = {
    "failed_logons_then_success": lambda ev: _failed_then_success(ev, 2, True),
    "repeated_failed_logons": lambda ev: _failed_then_success(ev, 2, False),
    "explicit_credential_logon": lambda ev: (
        any(e.channel == SECURITY and e.source_event_id == 4648 for e in ev), "a Security 4648 record"),
    "lsass_access": lambda ev: (
        any(e.channel == SYSMON and e.source_event_id == 10
            and facts.stem(e.event_data.get("TargetImage")) == LSASS_STEM for e in ev), "a Sysmon 10 on lsass"),
    "discovery_commands": lambda ev: (
        any(facts.is_process_creation(e) and facts.stem(facts.process_image(e)) in DISCOVERY_TECHNIQUES for e in ev),
        "a process creation of a discovery binary"),
    "suspicious_powershell": lambda ev: (
        any(facts.is_process_creation(e) and facts.stem(facts.process_image(e)) in POWERSHELL_IMAGES
            and POWERSHELL_ABUSE.search(facts.command_line(e)) for e in ev),
        "a PowerShell process creation with encoded, hidden or download arguments"),
    "unusual_parent_shell": lambda ev: (
        any(facts.is_process_creation(e) and facts.stem(facts.process_image(e)) in SHELL_IMAGES
            and facts.stem(facts.parent_image(e)) in SUSPICIOUS_PARENTS for e in ev),
        "an interpreter created by a document, browser or WMI host"),
    "payload_written": lambda ev: (any(_drops_file(e) for e in ev),
                                   "a Sysmon 11 file creation of an executable or script in a user-writable path"),
    "audit_log_cleared": lambda ev: (any(e.channel == SECURITY and e.source_event_id == 1102 for e in ev),
                                     "a Security 1102 record"),
    "service_installed": lambda ev: (any(e.channel == SECURITY and e.source_event_id == 4697 for e in ev),
                                     "a Security 4697 record"),
    "scheduled_task_created": lambda ev: (any(e.channel == SECURITY and e.source_event_id == 4698 for e in ev),
                                          "a Security 4698 record"),
    "run_key_set": lambda ev: (any(e.channel == SYSMON and e.source_event_id == 13
                                   and any(m in e.event_data.get("TargetObject", "").casefold() for m in RUN_KEY_MARKERS)
                                   for e in ev), "a Sysmon 13 Run/RunOnce value"),
}


def structure_check(gathered: ClaimEvidence) -> Check:
    claim_type = gathered.claim.claim_type
    predicate = STRUCTURES.get(claim_type)
    if predicate is None:
        return _na("claim_type_structure", "insufficient",
                   f"claim type {claim_type!r} has no structural check; the generic checks still apply")
    cited_ok, detail = predicate(gathered.cited_events())
    if cited_ok:
        return _pass("claim_type_structure", "insufficient", f"the cited records show {claim_type}: {detail}")
    context_ok, _ = predicate(gathered.context_events())
    if context_ok:
        return _fail("claim_type_structure", "partial", "structure_unsupported",
                     f"the stage's context shows {claim_type} but the cited records alone do not (needs {detail})")
    return _fail("claim_type_structure", "insufficient", "structure_unsupported",
                 f"the cited records do not show {claim_type}; needs {detail}")


# ---------------------------------------------------------------------------------------------
# 6. ATT&CK mappings
# ---------------------------------------------------------------------------------------------

def _creations_with(events, stems) -> bool:
    return any(facts.is_process_creation(e) and facts.stem(facts.process_image(e)) in stems for e in events)


def _discovery_indicator(technique_id: str):
    stems = {name for name, technique in DISCOVERY_TECHNIQUES.items() if technique == technique_id}
    return lambda ev: _creations_with(ev, stems)


# Observables that DEFINE a technique: required for a mapping marked ``supported``.
DEFINING = {
    "T1070.001": lambda ev: any(e.channel == SECURITY and e.source_event_id == 1102 for e in ev),
    "T1003.001": lambda ev: STRUCTURES["lsass_access"](ev)[0],
    "T1543.003": lambda ev: any(e.channel == SECURITY and e.source_event_id == 4697 for e in ev),
    "T1053.005": lambda ev: any(e.channel == SECURITY and e.source_event_id == 4698 for e in ev),
    "T1547.001": lambda ev: STRUCTURES["run_key_set"](ev)[0],
    "T1059.001": lambda ev: STRUCTURES["suspicious_powershell"](ev)[0],
    "T1059": lambda ev: any(facts.is_process_creation(e) and facts.stem(facts.process_image(e)) in SHELL_IMAGES
                            for e in ev),
    **{technique: _discovery_indicator(technique) for technique in set(DISCOVERY_TECHNIQUES.values())},
}
# Observables merely CONSISTENT with a technique: required for any mapping not marked ``uncertain``.
INDICATIVE = {
    "T1110": lambda ev: sum(1 for e in ev if e.channel == SECURITY and e.source_event_id == 4625) >= 2,
    "T1078": lambda ev: any(e.channel == SECURITY and e.source_event_id in (4624, 4648) for e in ev),
    "T1105": lambda ev: any(_drops_file(e) for e in ev),
    "T1204": lambda ev: STRUCTURES["unusual_parent_shell"](ev)[0],
}


def attack_checks(gathered: ClaimEvidence) -> list[Check]:
    checks: list[Check] = []
    for mapping in gathered.claim.attack:
        events = [gathered.context[i] for i in mapping.evidence_ids if i in gathered.context]
        technique = mapping.technique_id
        label = f"attack_{technique}"
        ids = tuple(mapping.evidence_ids[:3])
        defining, indicative = DEFINING.get(technique), INDICATIVE.get(technique)
        if mapping.status == "uncertain":
            checks.append(_na(label, "partial", f"{technique} is marked uncertain; it asserts nothing"))
        elif defining is None and indicative is None:
            checks.append(_na(label, "partial", f"the verifier holds no observable for {technique}"))
        elif mapping.status == "supported" and defining is None:
            checks.append(_fail(label, "partial", "unsupported_assertion",
                                f"{technique} is marked supported but only indicative observables exist for it, "
                                "so at most tentative is warranted", ids))
        else:
            observable = defining if mapping.status == "supported" else (indicative or defining)
            if observable(events):
                checks.append(_pass(label, "partial", f"{technique} ({mapping.status}) has a matching observable"))
            else:
                checks.append(_fail(label, "partial", "unsupported_assertion",
                                    f"{technique} is marked {mapping.status} but its evidence holds no matching "
                                    "observable", ids))
    return checks


# ---------------------------------------------------------------------------------------------
# 7. Relationships between claims and chronological order (need the whole reconstruction)
# ---------------------------------------------------------------------------------------------

def _shared_accounts(a: ClaimEvidence, b: ClaimEvidence) -> set[str]:
    def keys(g):
        return {k for e in g.context_events() for k in facts.event_accounts(e)}
    return keys(a) & keys(b)


def _guids(g: ClaimEvidence, parent: bool = False) -> set[str]:
    func = facts.parent_process_guid if parent else facts.process_guid
    return {guid for e in g.context_events() if (guid := func(e))}


def link_checks(gathered: ClaimEvidence, others: dict[str, ClaimEvidence]) -> list[Check]:
    checks: list[Check] = []
    claim = gathered.claim
    for link in claim.related_claims:
        other = others.get(link.claim_id)
        if other is None:
            continue
        earlier, later = (gathered, other) if claim.position < other.claim.position else (other, gathered)
        failed: list[str] = []
        for reason in (part.strip() for part in link.reason.split(";")):
            if reason.startswith("shared account"):
                names = [n.strip().casefold() for n in reason[len("shared account"):].split(",") if n.strip()]
                shared = _shared_accounts(gathered, other)
                failed += [f"shared account {n}" for n in names if n not in shared]
            elif reason == "same process":
                if not _guids(gathered) & _guids(other):
                    failed.append("same process")
            elif reason.startswith("a process in the later stage was started by"):
                if not _guids(later, parent=True) & _guids(earlier):
                    failed.append("process lineage")
        if failed:
            checks.append(_fail(f"link_{link.claim_id}", "partial", "link_unsupported",
                                f"link to {link.claim_id} asserts {', '.join(failed)}, which the two claims' "
                                "records do not show"))
        else:
            checks.append(_pass(f"link_{link.claim_id}", "partial"))
    return checks


def order_checks(reconstruction: Reconstruction, gathered: dict[str, ClaimEvidence]) -> dict[str, Check]:
    """A claim's declared start must not precede its predecessor's. Each declared start is separately attested
    against recorded times by ``span_endpoints_recorded``, so together the two pin the order to the evidence."""
    results: dict[str, Check] = {}
    previous_ticks: int | None = None
    previous_id = ""
    for claim in reconstruction.claims:
        try:
            start = iso_to_ticks(claim.first_utc)
        except ValueError:
            results[claim.claim_id] = _na("timeline_order", "partial", "the claim's start time is not valid")
            continue
        if previous_ticks is not None and start < previous_ticks:
            results[claim.claim_id] = _fail(
                "timeline_order", "partial", "ordering_conflict",
                f"position {claim.position} starts before {previous_id}, which precedes it in the timeline")
        else:
            results[claim.claim_id] = _pass("timeline_order", "partial")
        previous_ticks, previous_id = start, claim.claim_id
    return results


# ---------------------------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------------------------

_RANK = {"reject": 0, "insufficient": 1, "partial": 2}
VERDICT_FOR = {"reject": "rejected", "insufficient": "unverified", "partial": "partially_supported"}


def verdict_for(checks: list[Check]) -> str:
    failed = [c for c in checks if c.status == "fail"]
    if not failed:
        return "confirmed"
    return VERDICT_FOR[min(failed, key=lambda c: _RANK[c.grade]).grade]
