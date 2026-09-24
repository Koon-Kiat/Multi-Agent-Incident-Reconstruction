"""Offer the existing immutable corpus through the endpoint retrieval contract."""

from event_processing.query import EventStore
from event_processing.schema import NormalisedEvent
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks
from endpoint_agent.config import Limits
from endpoint_agent.models import SYSMON_CHANNEL, QueryRequest, QueryResult
from endpoint_agent.queries.semantics import check_bounds, event_order, matches


class CorpusEndpointProvider:
    def __init__(self, store: EventStore, limits: Limits | None = None):
        self._store = store
        self._limits = limits or Limits()

    def get_event(self, evidence_id: str) -> NormalisedEvent | None:
        found = self._store.lookup(evidence_id)
        if found.event is None or found.event.channel != SYSMON_CHANNEL:
            return None
        return found.event

    def query(self, request: QueryRequest) -> QueryResult:
        request = QueryRequest.model_validate_json(request.model_dump_json())
        check_bounds(request, self._limits)
        if request.limit > self._store.limits.max_limit:
            raise ValueError("query exceeds corpus limits")
        if iso_to_ticks(request.end_utc) - iso_to_ticks(request.start_utc) > self._store.limits.max_window_seconds * TICKS_PER_SECOND:
            raise ValueError("query exceeds corpus window")
        # Use the public snapshot API, as the authentication adapter does. Filtering
        # precedes limiting: applying GUID filters to a capped prefix loses evidence.
        events = sorted((event for event in self._store.scenario_events(request.scenario_id)
                         if matches(event, request)), key=event_order)
        return QueryResult(events=tuple(events[:request.limit]),
                           truncated=len(events) > request.limit, total_matched=len(events))
