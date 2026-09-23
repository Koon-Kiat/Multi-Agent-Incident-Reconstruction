from typing import Protocol

from authentication_agent.models import AuthenticationEvent, QueryRequest, QueryResult


class AuthenticationEventProvider(Protocol):
    """Exact ID lookup returns None when absent; queries use [start, end)."""

    def get_event(self, evidence_id: str) -> AuthenticationEvent | None: ...

    def query(self, request: QueryRequest) -> QueryResult: ...
