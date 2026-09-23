"""Reproducible descriptions of retrieved evidence, never attack classifications."""

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable

from authentication_agent.models import AuthenticationEvent, Entities, Finding, ObservedEvents, TimePeriod, utc_ticks
from authentication_agent.queries.semantics import account_of, event_order

BASE_UNCERTAINTY = (
    "Authentication telemetry alone does not establish account compromise or a common actor.",
    "Observations cover only retrieved evidence within the requested window.",
)


def entities_for(event: AuthenticationEvent) -> tuple[Entities, list[str]]:
    issues: list[str] = []

    def optional_text(key: str) -> str | None:
        value = event.event_data.get(key)
        if value is not None and not isinstance(value, str):
            issues.append(f"Malformed {key} in {event.evidence_id}; not used as an entity.")
            return None
        return value

    reported = optional_text("TargetUserName")
    logon = event.event_data.get("LogonType")
    if type(logon) is int and 0 <= logon <= 99:
        logon = str(logon)
    elif logon is not None and (not isinstance(logon, str) or not logon.isascii() or not logon.isdigit() or len(logon) > 2):
        issues.append(f"Malformed LogonType in {event.evidence_id}; not used as an entity.")
        logon = None
    entities = Entities(account=account_of(event), reported_account=reported,
                        domain=optional_text("TargetDomainName"), host=event.host,
                        source_address=optional_text("IpAddress"),
                        workstation=optional_text("WorkstationName"), logon_type=logon)
    if event.user is not None and reported is not None and event.user != reported:
        issues.append(f"Conflicting user and TargetUserName in {event.evidence_id}; event kept separate.")
    for name, value in entities.model_dump().items():
        if value is None or value in ("", "-"):
            issues.append(f"Missing or unavailable {name} in {event.evidence_id}.")
    return entities, issues


def build_observations(events: Iterable[AuthenticationEvent], truncated: bool) -> tuple[Finding, ...]:
    groups: dict[str, list[tuple[AuthenticationEvent, Entities, list[str]]]] = defaultdict(list)
    for event in sorted(events, key=event_order):
        entities, issues = entities_for(event)
        # No linkage through unknown/conflicting identity dimensions. Separate records
        # can still be observed individually, without assuming an actor relationship.
        key = entities.model_dump_json()
        if issues:
            key += event.evidence_id
        groups[key].append((event, entities, issues))
    findings = []
    for group in groups.values():
        records = [item[0] for item in group]
        failures = [event for event in records if event.source_event_id == 4625]
        successes = [event for event in records if event.source_event_id == 4624]
        first_success = utc_ticks(successes[0].timestamp_utc) if successes else None
        before = sum(utc_ticks(e.timestamp_utc) < first_success for e in failures) if first_success is not None else 0
        # Equal timestamps are deterministic ties, not evidence of temporal precedence.
        last_success = utc_ticks(successes[-1].timestamp_utc) if successes else None
        repeated_then_success = last_success is not None and sum(utc_ticks(f.timestamp_utc) < last_success for f in failures) >= 2
        ids = tuple(e.evidence_id for e in records)
        digest = hashlib.sha256(json.dumps(ids).encode()).hexdigest()[:24]
        description = f"Retrieved {len(failures)} failed logon(s) and {len(successes)} successful logon(s) with these recorded entity values."
        if repeated_then_success:
            description += " At least two failures precede a success."
        uncertainty = list(BASE_UNCERTAINTY)
        uncertainty.extend(issue for _, _, issues in group for issue in issues)
        if truncated:
            uncertainty.append("At least one query was truncated; counts and sequences may be incomplete.")
        if len({utc_ticks(e.timestamp_utc) for e in records}) < len(records):
            uncertainty.append("Equal timestamps do not establish event precedence; evidence_id breaks ordering ties only.")
        findings.append(Finding(finding_id=f"AUTH-{digest}", scenario_id=records[0].scenario_id,
            observed_events=ObservedEvents(description=description, failed_logons=len(failures), successful_logons=len(successes),
                failures_before_first_success=before, repeated_failures_followed_by_success=repeated_then_success),
            timestamps=TimePeriod(first_utc=records[0].timestamp_utc, last_utc=records[-1].timestamp_utc),
            entities=group[0][1], evidence_ids=ids, uncertainty=tuple(uncertainty)))
    return tuple(findings)
