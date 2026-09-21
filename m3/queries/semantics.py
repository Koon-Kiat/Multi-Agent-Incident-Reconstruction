"""Shared M3 adapter semantics, independent of any provider implementation."""

from m3.config import Limits
from m3.models import AuthenticationEvent, QueryRequest, utc_ticks, TICKS_PER_SECOND


def account_of(event: AuthenticationEvent) -> str | None:
    if event.user is not None:
        return event.user
    value = event.event_data.get("TargetUserName")
    return value if isinstance(value, str) else None


def event_order(event: AuthenticationEvent) -> tuple[int, str]:
    return utc_ticks(event.timestamp_utc), event.evidence_id


def matches(event: AuthenticationEvent, request: QueryRequest) -> bool:
    return (
        event.scenario_id == request.scenario_id
        and event.source_event_id in request.event_ids
        and utc_ticks(request.start_utc) <= utc_ticks(event.timestamp_utc) < utc_ticks(request.end_utc)
        and (request.account is None or account_of(event) == request.account)
        and (request.host is None or event.host == request.host)
    )


def check_bounds(request: QueryRequest, limits: Limits) -> None:
    if utc_ticks(request.end_utc) - utc_ticks(request.start_utc) > limits.max_window_seconds * TICKS_PER_SECOND:
        raise ValueError("query exceeds maximum time window")
    if request.limit > limits.max_events_per_query:
        raise ValueError("query exceeds maximum result count")
