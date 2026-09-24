from typing import Protocol

from event_processing.schema import NormalisedEvent
from endpoint_agent.models import QueryRequest, QueryResult


class EndpointEventProvider(Protocol):
    """Queries return Sysmon 1/10/11/13; exact lookup preserves any Sysmon record."""

    def query(self, request: QueryRequest) -> QueryResult: ...

    def get_event(self, evidence_id: str) -> NormalisedEvent | None: ...
