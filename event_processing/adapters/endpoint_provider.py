"""Offer the existing immutable corpus through the endpoint retrieval contract."""

from event_processing.query import EventStore
from event_processing.schema import NormalisedEvent
from endpoint_agent.config import Limits
from endpoint_agent.models import SYSMON_CHANNEL, QueryRequest, QueryResult
from endpoint_agent.queries.semantics import check_bounds


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
        # Compile endpoint field conventions into declarative shared query filters.
        # The store applies all predicates before limiting/detaching records.
        filters = None
        if request.process_guid is not None or request.parent_process_guid is not None:
            filters = {}
            for event_id in request.event_ids:
                if request.parent_process_guid is not None and event_id != 1:
                    continue
                fields = {}
                if request.process_guid is not None:
                    fields["SourceProcessGUID" if event_id == 10 else "ProcessGuid"] = request.process_guid
                if request.parent_process_guid is not None:
                    fields["ParentProcessGuid"] = request.parent_process_guid
                filters[event_id] = fields
        result = self._store.query(request.scenario_id, request.start_utc, request.end_utc,
            channels=(SYSMON_CHANNEL,), event_ids=request.event_ids, host=request.host,
            user=request.account, limit=request.limit, event_data_filters=filters)
        return QueryResult(events=result.events, truncated=result.truncated, total_matched=result.total_matched)
