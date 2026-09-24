"""One definition of filtering for the provider and its independent caller checks."""

from endpoint_agent.config import Limits
from endpoint_agent.models import ENDPOINT_EVENT_IDS, SYSMON_CHANNEL, QueryRequest
from event_processing.schema import NormalisedEvent
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks


def event_order(event: NormalisedEvent) -> tuple[int, str]:
    return event.timestamp_ticks, event.evidence_id


def process_guid(event: NormalisedEvent) -> str | None:
    # Sysmon ProcessAccess uses SourceProcessGUID, not ProcessGuid.
    return event.event_data.get("SourceProcessGUID" if event.source_event_id == 10 else "ProcessGuid")


def check_bounds(query: QueryRequest, limits: Limits) -> None:
    if iso_to_ticks(query.end_utc) - iso_to_ticks(query.start_utc) > limits.max_window_seconds * TICKS_PER_SECOND:
        raise ValueError("query exceeds maximum window")
    if query.limit > limits.max_events_per_query:
        raise ValueError("query exceeds event limit")


def matches(event: NormalisedEvent, query: QueryRequest) -> bool:
    return (event.scenario_id == query.scenario_id and event.channel == SYSMON_CHANNEL
            and event.source_event_id in ENDPOINT_EVENT_IDS and event.source_event_id in query.event_ids
            and iso_to_ticks(query.start_utc) <= event.timestamp_ticks < iso_to_ticks(query.end_utc)
            and (query.host is None or event.host == query.host)
            and (query.account is None or event.user == query.account)
            and (query.process_guid is None or process_guid(event) == query.process_guid)
            and (query.parent_process_guid is None or (event.source_event_id == 1
                 and event.event_data.get("ParentProcessGuid") == query.parent_process_guid)))
