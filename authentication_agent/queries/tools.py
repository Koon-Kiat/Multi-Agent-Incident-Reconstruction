"""The sole evidence boundary for trusted and model-selected operations."""

from copy import deepcopy
import json

from authentication_agent.config import Limits
from authentication_agent.errors import InvestigationError
from authentication_agent.models import AuthenticationEvent, GetArguments, HistoryArguments, InvestigationRequest, OperationReceipt, QueryRequest, QueryResult, ToolCall, utc_ticks
from .interface import AuthenticationEventProvider
from .semantics import check_bounds, event_order, matches


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
        self.operations: list[OperationReceipt] = []
        self.evidence_readbacks = 0
        self._cache: dict[str, tuple[int, dict]] = {}

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

    @staticmethod
    def _provider_call(method, argument):
        try:
            return method(argument)
        except TimeoutError as exc:
            raise InvestigationError("provider_timeout") from exc
        except ConnectionError as exc:
            raise InvestigationError("provider_connection_failed") from exc
        except Exception as exc:
            # Neither event text nor adapter exception messages cross this boundary.
            raise InvestigationError("provider_failure") from exc

    def not_run(self, call: ToolCall, required_index: int) -> None:
        self.operations.append(OperationReceipt(index=len(self.operations), origin="required",
            required_index=required_index, call=call, status="not_run", error_code="earlier_operation_failed"))

    def execute(self, call: ToolCall, *, origin="model", required_index=None) -> dict:
        # Validate independently of ModelReply, including model_construct bypasses.
        call = ToolCall.model_validate_json(call.model_dump_json())
        receipt = dict(index=len(self.operations), origin=origin, required_index=required_index, call=call)
        invoked = False
        try:
            if self.calls >= self.limits.max_tool_calls:
                raise InvestigationError("tool_budget_exhausted")
            self.calls += 1  # Duplicate and rejected attempts consume budget, too.
            args = TOOL_ARGUMENT_MODELS[call.name].model_validate_json(json.dumps(call.arguments))
            if isinstance(args, GetArguments):
                if args.evidence_id.rsplit("-SEC-", 1)[0] != self.request.scenario_id:
                    raise InvestigationError("provider_scope_violation")
                key = "get:" + args.evidence_id
            else:
                check_bounds(args, self.limits)
                if args.scenario_id != self.request.scenario_id or utc_ticks(args.start_utc) < utc_ticks(self.request.start_utc) or utc_ticks(args.end_utc) > utc_ticks(self.request.end_utc):
                    raise InvestigationError("tool_scope_violation")
                # History has identical provider semantics. Normalize only equivalent
                # timestamps/defaults/event sets; receipts retain exact caller args.
                canonical = args.model_dump(mode="json")
                canonical.update(start_utc=utc_ticks(args.start_utc), end_utc=utc_ticks(args.end_utc),
                                 event_ids=sorted(set(args.event_ids)))
                key = "query:" + json.dumps(canonical, sort_keys=True)
            reused_from = None
            accepted = {}
            if key in self._cache:
                reused_from, cached = self._cache[key]
                output = deepcopy(cached)
            else:
                invoked = True
                output, accepted = self._retrieve(args)
            ids = tuple(output.get("evidence_ids", ()))
            new_ids = tuple(eid for eid in ids if eid not in self.retrieved)
            # Commit only after every event in a provider batch has been validated.
            self.retrieved.update(accepted)
            if invoked:
                self._cache[key] = (receipt["index"], deepcopy(output))
            self.operations.append(OperationReceipt(**receipt,
                status="completed" if ids else "no_evidence", evidence_ids=ids, new_evidence_ids=new_ids,
                truncated=output.get("truncated", False), provider_invoked=invoked, reused_from=reused_from))
            return output
        except Exception as exc:
            code = exc.code if isinstance(exc, InvestigationError) else (
                "provider_contract_violation" if invoked else "invalid_contract_or_model_response")
            self.operations.append(OperationReceipt(**receipt, status="failed" if invoked else "rejected",
                                                     provider_invoked=invoked, error_code=code))
            raise InvestigationError(code) from exc

    def _retrieve(self, args) -> tuple[dict, dict[str, AuthenticationEvent]]:
        if isinstance(args, GetArguments):
            event = self._provider_call(self.provider.get_event, args.evidence_id)
            if event is None:
                self.missing = True
                return {"found": False, "evidence_id": args.evidence_id}, {}
            if event.evidence_id != args.evidence_id:
                raise InvestigationError("provider_id_mismatch")
            event = self._accept(event, self._scope())
            return {"found": True, "evidence_ids": [event.evidence_id]}, {event.evidence_id: event}
        result = self._provider_call(self.provider.query, args)
        result = QueryResult.model_validate_json(result.model_dump_json())
        if len(result.events) > args.limit or list(result.events) != sorted(result.events, key=event_order):
            raise InvestigationError("provider_contract_violation")
        if len({e.evidence_id for e in result.events}) != len(result.events):
            raise InvestigationError("provider_duplicate_evidence")
        accepted = [self._accept(event, args) for event in result.events]
        self.truncated |= result.truncated
        return ({"evidence_ids": [e.evidence_id for e in accepted], "truncated": result.truncated},
                {event.evidence_id: event for event in accepted})

    def validate_references(self) -> None:
        """Final consistency readback; separate from tool calls and verification verdicts."""
        for evidence_id, original in self.retrieved.items():
            self.evidence_readbacks += 1
            current = self._provider_call(self.provider.get_event, evidence_id)
            if current is None:
                raise InvestigationError("missing_evidence")
            current = self._accept(current, self._scope())
            if current.evidence_id != evidence_id or current != original:
                raise InvestigationError("evidence_changed")
