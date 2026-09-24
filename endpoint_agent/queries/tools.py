"""Enforce scenario, time, type, identity, limits and immutable evidence at every call."""

from copy import deepcopy
import json

from endpoint_agent.config import Limits
from endpoint_agent.errors import InvestigationError
from endpoint_agent.models import (GetArguments, InvestigationRequest, OperationReceipt,
                                   ProcessArguments, QueryRequest, QueryResult, ToolCall)
from endpoint_agent.queries.interface import EndpointEventProvider
from endpoint_agent.queries.semantics import check_bounds, event_order, matches
from event_processing.ids import parse_evidence_id
from event_processing.schema import NormalisedEvent
from event_processing.timeutil import iso_to_ticks

GUID_KEYS = ("ProcessGuid", "ParentProcessGuid", "SourceProcessGUID", "TargetProcessGUID")


class EndpointTools:
    def __init__(self, request: InvestigationRequest, provider: EndpointEventProvider, limits: Limits):
        self.request, self.provider, self.limits = request, provider, limits
        self.calls = 0
        self.retrieved: dict[str, NormalisedEvent] = {}
        self.truncated = False
        self.missing = False
        self.operations: list[OperationReceipt] = []
        self.evidence_readbacks = 0
        self._cache: dict[str, tuple[int, dict]] = {}

    def scope(self) -> QueryRequest:
        return QueryRequest(**self.request.window(), limit=self.limits.max_events_per_query)

    def _accept(self, event: NormalisedEvent, query: QueryRequest) -> NormalisedEvent:
        encoded = event.model_dump_json()
        if len(encoded.encode()) > self.limits.max_event_bytes:
            raise InvestigationError("event_size_limit")
        event = NormalisedEvent.model_validate_json(encoded)
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
        except TimeoutError:
            raise InvestigationError("provider_timeout") from None
        except ConnectionError:
            raise InvestigationError("provider_connection_failed") from None
        except Exception:
            raise InvestigationError("provider_failure") from None

    def _query_for(self, call: ToolCall) -> QueryRequest:
        args = call.arguments
        if isinstance(args, ProcessArguments):
            known = {(event.host, event.event_data[key]) for event in self.retrieved.values()
                     for key in GUID_KEYS if event.host and event.event_data.get(key) not in (None, "", "-")}
            if (args.host, args.process_guid) not in known:
                raise InvestigationError("unknown_process_reference")
            fields = {**self.request.window(), "host": args.host, "limit": args.limit}
            if call.name == "get_process_children":
                fields.update(parent_process_guid=args.process_guid, event_ids=(1,))
            else:
                fields["process_guid"] = args.process_guid
                if call.name == "get_process_creation":
                    fields["event_ids"] = (1,)
            query = QueryRequest(**fields)
        else:
            query = args
        check_bounds(query, self.limits)
        if (query.scenario_id != self.request.scenario_id
                or iso_to_ticks(query.start_utc) < iso_to_ticks(self.request.start_utc)
                or iso_to_ticks(query.end_utc) > iso_to_ticks(self.request.end_utc)):
            raise InvestigationError("tool_scope_violation")
        return query

    def not_run(self, call: ToolCall) -> None:
        self.operations.append(OperationReceipt(index=len(self.operations), origin="seed", call=call,
                                               status="not_run", error_code="earlier_operation_failed"))

    def execute(self, call: ToolCall, *, origin="model") -> dict:
        call = ToolCall.model_validate_json(call.model_dump_json())
        receipt = dict(index=len(self.operations), origin=origin, call=call)
        invoked = False
        try:
            if self.calls >= self.limits.max_tool_calls:
                raise InvestigationError("tool_budget_exhausted")
            self.calls += 1
            args = call.arguments
            if isinstance(args, GetArguments):
                if parse_evidence_id(args.evidence_id).scenario_id != self.request.scenario_id:
                    raise InvestigationError("tool_scope_violation")
                query = self.scope()
                key = "get:" + args.evidence_id
            else:
                query = self._query_for(call)
                values = query.model_dump(mode="json")
                values.update(start_utc=iso_to_ticks(query.start_utc), end_utc=iso_to_ticks(query.end_utc),
                              event_ids=sorted(set(query.event_ids)))
                key = "query:" + json.dumps(values, sort_keys=True)
            accepted = {}
            reused_from = None
            if key in self._cache:
                reused_from, cached = self._cache[key]
                output = deepcopy(cached)
            else:
                invoked = True
                if isinstance(args, GetArguments):
                    event = self._provider_call(self.provider.get_event, args.evidence_id)
                    if event is None:
                        self.missing = True
                        output = {"evidence_ids": [], "requested_evidence_id": args.evidence_id,
                                  "found": False, "total_matched": 0, "truncated": False}
                    else:
                        if event.evidence_id != args.evidence_id:
                            raise InvestigationError("provider_id_mismatch")
                        event = self._accept(event, query)
                        accepted[event.evidence_id] = event
                        output = {"evidence_ids": [event.evidence_id], "found": True,
                                  "total_matched": 1, "truncated": False}
                else:
                    result = self._provider_call(self.provider.query, query)
                    result = QueryResult.model_validate_json(result.model_dump_json())
                    if (len(result.events) > query.limit
                            or list(result.events) != sorted(result.events, key=event_order)
                            or len({event.evidence_id for event in result.events}) != len(result.events)):
                        raise InvestigationError("provider_contract_violation")
                    for candidate in result.events:
                        event = self._accept(candidate, query)
                        accepted[event.evidence_id] = event
                    output = {"evidence_ids": list(accepted), "total_matched": result.total_matched,
                              "truncated": result.truncated}
            ids = tuple(output["evidence_ids"])
            new_ids = tuple(eid for eid in ids if eid not in self.retrieved)
            # A batch becomes visible only after all its records pass the boundary.
            self.retrieved.update(accepted)
            self.truncated |= output["truncated"]
            if invoked:
                self._cache[key] = (receipt["index"], deepcopy(output))
            self.operations.append(OperationReceipt(**receipt, status="completed" if ids else "no_evidence",
                evidence_ids=ids, new_evidence_ids=new_ids, truncated=output["truncated"],
                total_matched=output["total_matched"], provider_invoked=invoked, reused_from=reused_from))
            return output
        except Exception as error:
            code = error.code if isinstance(error, InvestigationError) else (
                "provider_contract_violation" if invoked else "invalid_contract_or_model_response")
            self.operations.append(OperationReceipt(**receipt, status="failed" if invoked else "rejected",
                                                   provider_invoked=invoked, error_code=code))
            raise InvestigationError(code) from None

    def validate_references(self) -> None:
        # Existence/readback is a development consistency check, not independent verification.
        for evidence_id, original in self.retrieved.items():
            self.evidence_readbacks += 1
            current = self._provider_call(self.provider.get_event, evidence_id)
            if current is None:
                raise InvestigationError("missing_evidence")
            current = self._accept(current, self.scope())
            if current.evidence_id != evidence_id or current != original:
                raise InvestigationError("evidence_changed")
