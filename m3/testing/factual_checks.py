"""Deterministic synthetic development assertions, not M6 verification/scoring."""

from collections.abc import Iterable

from m3.models import AuthenticationEvent, InvestigationResult, utc_ticks


def check_synthetic_result(
    result: InvestigationResult,
    retrieved: Iterable[AuthenticationEvent],
    expected_error: str | None = None,
) -> list[str]:
    """Check facts against original fixture records, never a model explanation."""
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    InvestigationResult.model_validate_json(result.model_dump_json())
    if expected_error is not None:
        require(result.status == "failed" and result.error_code == expected_error,
                f"expected fail-closed outcome {expected_error}")
        require(not result.findings, "failed investigations must contain no findings")
        return errors
    require(result.status == "completed" and result.error_code is None, "investigation did not complete")
    if result.status != "completed":
        require(not result.findings, "failure leaked partial findings")
        return errors

    original = {event.evidence_id: event for event in retrieved}
    cited = [evidence_id for finding in result.findings for evidence_id in finding.evidence_ids]
    require(set(cited) == set(original), "findings do not cover exactly the retrieved evidence")
    require(len(cited) == len(set(cited)), "evidence was counted in multiple findings")
    if not original:
        require(not result.findings and bool(result.uncertainty), "empty result must express uncertainty without findings")
    for finding in result.findings:
        require(bool(finding.evidence_ids), "finding has no evidence")
        require(finding.scenario_id == result.request.scenario_id, "finding scenario mismatch")
        require(bool(finding.uncertainty), "finding has no uncertainty")
        require(finding.interpretation in (None,
            "The observed authentication sequence may warrant further investigation; it does not establish compromise.",
            "Additional context is needed to interpret this authentication activity; no attack classification is made."),
            "interpretation is not one of the qualified M3 phrases")
        if not finding.evidence_ids or any(eid not in original for eid in finding.evidence_ids):
            errors.append("unknown evidence reference")
            continue
        events = [original[eid] for eid in finding.evidence_ids]
        ordered = sorted(events, key=lambda event: (utc_ticks(event.timestamp_utc), event.evidence_id))
        require(events == ordered, "evidence is not in full-precision chronological order")
        require(finding.timestamps.first_utc == ordered[0].timestamp_utc, "first timestamp changed")
        require(finding.timestamps.last_utc == ordered[-1].timestamp_utc, "last timestamp changed")
        failures = [event for event in events if event.source_event_id == 4625]
        successes = [event for event in events if event.source_event_id == 4624]
        require(finding.observed_events.failed_logons == len(failures), "failed-logon count mismatch")
        require(finding.observed_events.successful_logons == len(successes), "successful-logon count mismatch")
        before_first = sum(utc_ticks(event.timestamp_utc) < utc_ticks(successes[0].timestamp_utc)
                           for event in failures) if successes else 0
        relationship = any(sum(utc_ticks(failure.timestamp_utc) < utc_ticks(success.timestamp_utc)
                               for failure in failures) >= 2 for success in successes)
        require(finding.observed_events.failures_before_first_success == before_first, "failure/success sequence mismatch")
        require(finding.observed_events.repeated_failures_followed_by_success == relationship, "repeated-failure relationship mismatch")
        for event in events:
            require(event.scenario_id == result.request.scenario_id, "cross-scenario evidence")
            require(utc_ticks(result.request.start_utc) <= utc_ticks(event.timestamp_utc) < utc_ticks(result.request.end_utc), "evidence outside window")
            require(event.source_event_id in (4624, 4625) and event.channel == "Security", "non-authentication evidence")
            data = event.event_data
            def text_value(key):
                value = data.get(key)
                return value if isinstance(value, str) else None
            logon = data.get("LogonType")
            if type(logon) is int and 0 <= logon <= 99:
                logon = str(logon)
            elif not isinstance(logon, str) or not logon.isascii() or not logon.isdigit() or len(logon) > 2:
                logon = None
            expected_entities = {
                "account": event.user if event.user is not None else text_value("TargetUserName"),
                "reported_account": text_value("TargetUserName"), "domain": text_value("TargetDomainName"),
                "host": event.host, "source_address": text_value("IpAddress"),
                "workstation": text_value("WorkstationName"), "logon_type": logon,
            }
            require(finding.entities.model_dump() == expected_entities, "entity association mismatch")
            if any(value in (None, "", "-") for value in expected_entities.values()):
                require(any("Missing" in item for item in finding.uncertainty), "missing fields lack uncertainty")
            if event.user is not None and text_value("TargetUserName") is not None and event.user != text_value("TargetUserName"):
                require(any("Conflicting" in item for item in finding.uncertainty), "conflicting accounts lack uncertainty")
    return errors
