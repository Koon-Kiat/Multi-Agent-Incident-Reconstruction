"""Incident Reconstruction Orchestrator entry point: deterministic facts, constrained model interpretation."""

import json

from pydantic import ValidationError

from authentication_agent.config import CONFIGURATION_VERSION, Limits
from authentication_agent.context import BATCH_PROMPT, context_measure
from authentication_agent.errors import InvestigationError
from authentication_agent.llm import LLMAdapter
from authentication_agent.models import ContextBatch, InvestigationRequest, InvestigationResult, ModelReply, RequiredOperations, RunMetadata, ToolCall
from authentication_agent.observations import build_observations
from authentication_agent.prompts import PROMPT_VERSION, SYSTEM_PROMPT
from authentication_agent.queries.interface import AuthenticationEventProvider
from authentication_agent.queries.tools import AuthenticationTools, TOOL_ARGUMENT_MODELS
from authentication_agent.planning import query_menu,decoder,parse_reply as parse_planned_reply,POLICY

INTERPRETATIONS = {
    "may_warrant_review": "The observed authentication sequence may warrant further investigation; it does not establish compromise.",
    "context_required": "Additional context is needed to interpret this authentication activity; no attack classification is made.",
}


def investigate(request: InvestigationRequest, provider: AuthenticationEventProvider,
                llm: LLMAdapter, limits: Limits | None = None, *,
                required_operations: RequiredOperations | None = None) -> InvestigationResult:
    """Run locally against any compatible provider; operational failure returns no findings."""
    limits = limits or Limits()
    tools = AuthenticationTools(request, provider, limits)
    model_calls = 0
    required_calls = ()
    required_attempted = 0
    context_batches = []

    def result(status: str, findings: tuple = (), error: str | None = None) -> InvestigationResult:
        if status == "failed":
            for index in range(required_attempted, len(required_calls)):
                tools.not_run(required_calls[index], index)
        uncertainty = []
        if tools.truncated:
            uncertainty.append("At least one query was truncated; this is not a complete window inventory.")
        if tools.missing:
            uncertainty.append("An exact evidence lookup returned not found; no replacement was used.")
        if status == "completed" and not findings:
            uncertainty.append("No authentication evidence was returned for this window; this does not establish absence of activity.")
        return InvestigationResult(status=status, request=request, findings=findings, error_code=error,
            uncertainty=tuple(uncertainty), metadata=RunMetadata(prompt_version=PROMPT_VERSION,
            configuration_version=CONFIGURATION_VERSION, llm=llm.metadata(), limits=limits.model_dump(),
            tool_calls=tools.calls, model_calls=model_calls, operations=tuple(tools.operations),
            evidence_readbacks=tools.evidence_readbacks, context_strategy="bounded-observations-v1",
            planning_policy=POLICY,
            context_batches=tuple(context_batches)))

    try:
        if required_operations is not None:
            if not isinstance(required_operations, RequiredOperations):
                raise ValueError("required operations must use the trusted typed interface")
            required_calls = RequiredOperations.model_validate_json(required_operations.model_dump_json(exclude_unset=True)).calls()
        # Mandatory bounded initial retrieval prevents unsupported model-only answers.
        last_tool = tools.execute(ToolCall(name="query_authentication_events", arguments={
            **request.model_dump(), "limit": limits.max_events_per_query}), origin="initial")
        for index, call in enumerate(required_calls):
            required_attempted = index + 1
            last_tool = tools.execute(call, origin="required", required_index=index)
        offset, annotations = 0, {}
        while True:
            menu,coverage=query_menu(request,tools,limits)
            observations = build_observations(tools.retrieved.values(), tools.truncated)
            model_observations = [{"index":i,**observation.model_dump(mode="json"),
                "events": [_event_context(tools.retrieved[eid]) for eid in observation.evidence_ids]}
                for i,observation in enumerate(observations)]
            response_schema = ModelReply.grounded_schema(observations, max_events_per_query=limits.max_events_per_query)
            response_schema = decoder(response_schema,observations,menu)
            context = {"request": request.model_dump(), "tool_calls_remaining": limits.max_tool_calls - tools.calls,
                "available_queries":menu,"coverage":coverage,
                "last_tool_result": last_tool,
                "operation_history": [op.model_dump(mode="json") for op in tools.operations],
                "tool_argument_schemas": {name: response_schema["$defs"][model.__name__]
                    for name, model in TOOL_ARGUMENT_MODELS.items()},
                "limits": limits.model_dump(), "observations": model_observations}
            messages = [{"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": json.dumps(context)}]
            batch = observations
            counter = getattr(llm,"input_token_upper_bound",None)
            fits, size, upper = context_measure(messages, response_schema, llm.metadata(), limits,counter)
            if offset or not fits:
                # All source event details stay intact. Only repetitive history
                # and fixed instructions are condensed; irreducible findings
                # fail explicitly instead of clipping their evidence.
                def prepare(count):
                    selected = observations[offset:offset + count]
                    ids = {eid for o in selected for eid in o.evidence_ids}
                    schema = ModelReply.grounded_schema(selected, max_events_per_query=limits.max_events_per_query)
                    schema = decoder(schema,selected,menu)
                    latest = tools.operations[-1].model_dump(mode="json") if tools.operations else None
                    if latest is not None:
                        latest["evidence_ids"] = [eid for eid in latest["evidence_ids"] if eid in ids]
                        latest["new_evidence_ids"] = [eid for eid in latest["new_evidence_ids"] if eid in ids]
                    view = {"request": request.model_dump(), "tool_calls_remaining": limits.max_tool_calls-tools.calls,
                            "available_queries":menu,"coverage":coverage,
                            "last_tool_result": {**last_tool, "evidence_ids": [eid for eid in last_tool.get("evidence_ids", ()) if eid in ids]},
                            "operation_history": [latest] if latest else [],
                            "limits": {"max_events_per_query": limits.max_events_per_query},
                            "batch": {"offset": offset, "count": count, "total": len(observations)},
                            "observations": [{**o,"index":i} for i,o in enumerate(model_observations[offset:offset+count])]}
                    msg = [{"role":"system","content":SYSTEM_PROMPT},
                           {"role":"user","content":json.dumps(view,ensure_ascii=False)}]
                    measurement = context_measure(msg,schema,llm.metadata(),limits,counter)
                    return selected,msg,schema,measurement
                best = prepare(min(1,len(observations)-offset))
                if not best[3][0]:
                    raise InvestigationError("context_size_limit")
                low, high = 2, len(observations)-offset
                while low <= high:
                    middle = (low+high)//2
                    candidate = prepare(middle)
                    if candidate[3][0]:
                        best, low = candidate, middle+1
                    else:
                        high = middle-1
                batch,messages,response_schema,(_,size,upper) = best
            context_batches.append(ContextBatch(index=model_calls,revision=tools.calls,
                observation_ids=tuple(o.finding_id for o in batch),
                evidence_ids=tuple(dict.fromkeys(eid for o in batch for eid in o.evidence_ids)),
                context_bytes=size,input_token_upper_bound=upper))
            model_calls += 1
            reply_text = llm.complete(messages, response_schema, limits)
            if not isinstance(reply_text, str):
                raise InvestigationError("invalid_model_response")
            if len(reply_text.encode()) > limits.max_model_output_bytes:
                raise InvestigationError("model_output_limit")
            reply = parse_planned_reply(reply_text,batch,menu)
            if reply.action == "tool":
                previous=(set(tools.retrieved),tools.truncated)
                last_tool = tools.execute(reply.tool)
                if previous!=(set(tools.retrieved),tools.truncated):
                    offset, annotations = 0, {}
                continue
            by_id = {o.finding_id: o for o in batch}
            for annotation in reply.annotations:
                observation = by_id.get(annotation.observation_id)
                if observation is None or annotation.evidence_ids != observation.evidence_ids or annotation.observation_id in annotations:
                    raise InvestigationError("invalid_evidence_reference")
                annotations[annotation.observation_id] = annotation.interpretation
            offset += len(batch)
            if offset < len(observations):
                continue
            tools.validate_references()
            findings = tuple(o.model_copy(update={"interpretation": INTERPRETATIONS.get(annotations.get(o.finding_id))}) for o in observations)
            # Validate the final serialized boundary Incident Reconstruction Orchestrator will consume.
            return InvestigationResult.model_validate_json(result("completed", findings).model_dump_json())
    except InvestigationError as exc:
        return result("failed", error=exc.code)
    except (ValidationError, ValueError, TypeError, KeyError):
        return result("failed", error="invalid_contract_or_model_response")
    except TimeoutError:
        return result("failed", error="model_timeout")
    except ConnectionError:
        return result("failed", error="model_connection_failed")
    except Exception:
        # Provider/adapter extensions must not leak log contents in public errors.
        return result("failed", error="adapter_failure")


def _event_context(event) -> dict:
    """Bounded authentication details, without raw XML or arbitrary event text."""
    return {"evidence_id": event.evidence_id, "timestamp_utc": event.timestamp_utc,
            "event_id": event.source_event_id, "account": event.user, "host": event.host,
            "authentication_fields": {key: value for key, value in event.event_data.items()
                if key in {"TargetUserName", "TargetDomainName", "TargetUserSid", "IpAddress", "WorkstationName",
                           "LogonType", "Status", "SubStatus", "AuthenticationPackageName", "LogonProcessName"}
                and isinstance(value, (str, int, type(None)))}}
