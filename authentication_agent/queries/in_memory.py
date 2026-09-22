"""Small synthetic adapter, not an ingestion pipeline or database."""

from collections.abc import Iterable

from authentication_agent.config import Limits
from authentication_agent.models import AuthenticationEvent, QueryRequest, QueryResult
from .semantics import check_bounds, matches, event_order


class InMemoryAuthenticationEventProvider:
    def __init__(self, events: Iterable[AuthenticationEvent], limits: Limits | None = None):
        self._limits = limits or Limits()
        self._events: dict[str, AuthenticationEvent] = {}
        for event in events:
            # Revalidate even objects built through unchecked model_construct/model_copy.
            copy = AuthenticationEvent.model_validate_json(event.model_dump_json())
            if copy.evidence_id in self._events:
                raise ValueError("duplicate evidence_id")
            self._events[copy.evidence_id] = copy

    def get_event(self, evidence_id: str) -> AuthenticationEvent | None:
        event = self._events.get(evidence_id)
        return event.model_copy(deep=True) if event is not None else None

    def query(self, request: QueryRequest) -> QueryResult:
        check_bounds(request, self._limits)
        events = sorted((e for e in self._events.values() if matches(e, request)), key=event_order)
        return QueryResult(events=tuple(e.model_copy(deep=True) for e in events[:request.limit]), truncated=len(events) > request.limit)
