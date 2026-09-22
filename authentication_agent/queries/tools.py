"""The sole evidence access boundary exposed to model-selected actions."""

import json

from pydantic import Field

from authentication_agent.config import Limits
from authentication_agent.errors import InvestigationError
from authentication_agent.models import AuthenticationEvent, InvestigationRequest, Model, QueryRequest, QueryResult, ToolCall, utc_ticks
from .interface import AuthenticationEventProvider
from .semantics import check_bounds, event_order, matches


class GetArguments(Model):
    evidence_id: str = Field(min_length=1, max_length=200)


class HistoryArguments(QueryRequest):
    account: str = Field(max_length=512)


TOOL_ARGUMENT_MODELS = {
    "query_authentication_events": QueryRequest,
    "get_authentication_event": GetArguments,
    "get_account_authentication_history": HistoryArguments,
}


class AuthenticationTools:
    def __init__(self, request: InvestigationRequest, provider: AuthenticationEventProvider, limits: Limits):
        self.request, self.provider, self.limits = request, provider, limits
        self.calls = 0
        self.retrieved: dict[str, AuthenticationEvent] = {}
        self.truncated = False
        self.missing = False

    def _scope(self) -> QueryRequest:
        return QueryRequest(**self.request.model_dump(), limit=self.limits.max_events_per_query)

    def _accept(self, event: AuthenticationEvent, query: QueryRequest) -> AuthenticationEvent:
        encoded = event.model_dump_json()
        if len(encoded.encode()) > self.limits.max_event_bytes:
            raise InvestigationError("event_size_limit")
        event = AuthenticationEvent.model_validate_json(encoded)
        if not matches(event, query):
            raise InvestigationError("provider_scope_violation")
        previous = self.retrieved.get(event.evidence_id)
        if previous is not None and previous != event:
            raise InvestigationError("evidence_changed")
        return event

    def execute(self, call: ToolCall) -> dict:
        if self.calls >= self.limits.max_tool_calls:
            raise InvestigationError("tool_budget_exhausted")
        self.calls += 1
        args = TOOL_ARGUMENT_MODELS[call.name].model_validate_json(json.dumps(call.arguments))
        if isinstance(args, GetArguments):
            event = self.provider.get_event(args.evidence_id)
            if event is None:
                self.missing = True
                return {"found": False, "evidence_id": args.evidence_id}
            if event.evidence_id != args.evidence_id:
                raise InvestigationError("provider_id_mismatch")
            event = self._accept(event, self._scope())
            self.retrieved[event.evidence_id] = event
            return {"found": True, "evidence_ids": [event.evidence_id]}
        check_bounds(args, self.limits)
        if args.scenario_id != self.request.scenario_id or utc_ticks(args.start_utc) < utc_ticks(self.request.start_utc) or utc_ticks(args.end_utc) > utc_ticks(self.request.end_utc):
            raise InvestigationError("tool_scope_violation")
        result = self.provider.query(args)
        result = QueryResult.model_validate_json(result.model_dump_json())
        if len(result.events) > args.limit or list(result.events) != sorted(result.events, key=event_order):
            raise InvestigationError("provider_contract_violation")
        if len({e.evidence_id for e in result.events}) != len(result.events):
            raise InvestigationError("provider_duplicate_evidence")
        accepted = [self._accept(event, args) for event in result.events]
        self.retrieved.update((event.evidence_id, event) for event in accepted)
        self.truncated |= result.truncated
        return {"evidence_ids": [e.evidence_id for e in accepted], "truncated": result.truncated}

    def validate_references(self) -> None:
        """Bounded final consistency readback; this is not an Evidence Verification & Evaluation verification verdict."""
        for evidence_id, original in self.retrieved.items():
            current = self.provider.get_event(evidence_id)
            if current is None:
                raise InvestigationError("missing_evidence")
            current = self._accept(current, self._scope())
            if current.evidence_id != evidence_id or current != original:
                raise InvestigationError("evidence_changed")
