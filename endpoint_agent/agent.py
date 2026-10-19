"""Local endpoint investigation: bounded model decisions, deterministic source facts."""

import json

from pydantic import ValidationError

from endpoint_agent.config import CONFIGURATION_VERSION, Limits
from endpoint_agent.context import model_batch
from endpoint_agent.errors import InvestigationError
from endpoint_agent.llm import LLMAdapter
from endpoint_agent.models import (InvestigationRequest, InvestigationResult, ModelReply,
                                   RunMetadata, ToolCall, interpretations_for)
from endpoint_agent.observations import build_observations
from endpoint_agent.prompts import PROMPT_VERSION
from endpoint_agent.queries.interface import EndpointEventProvider
from endpoint_agent.queries.semantics import check_bounds
from endpoint_agent.queries.tools import EndpointTools

INTERPRETATIONS = {
    "context_required": "Additional context is needed to assess the intent of this endpoint activity.",
    "execution_requires_review": "The recorded execution may warrant investigation; it does not establish malicious intent.",
    "administration_possible": "Legitimate administration is one possible explanation; the evidence does not establish benign intent.",
    "process_access_requires_review": "The recorded process access warrants contextual review; it does not establish credential extraction.",
    "artifact_requires_review": "The recorded artifact change may warrant review; its later execution or use is not established.",
}


def _tool(name: str, arguments: dict) -> ToolCall:
    return ToolCall.model_validate_json(json.dumps({"name": name, "arguments": arguments}))


def investigate(request: InvestigationRequest, provider: EndpointEventProvider,
                llm: LLMAdapter, limits: Limits | None = None) -> InvestigationResult:
    """Return the common envelope with endpoint payloads; failures return no findings.

    Request/config construction may raise before dispatch. Providers must represent
    a consistent snapshot. Async callers should run this function in a worker thread.
    """
    request = InvestigationRequest.model_validate_json(request.model_dump_json())
    limits = limits or Limits()
    limits = Limits.model_validate_json(limits.model_dump_json())
    tools = EndpointTools(request, provider, limits)
    seed_calls = tuple(_tool("get_endpoint_event", {"evidence_id": eid}) for eid in request.seed_evidence_ids)
    seeds_attempted = 0
    model_calls = 0
    context_batches = []

    def result(status, findings=(), error=None):
        if status == "failed":
            for call in seed_calls[seeds_attempted:]:
                tools.not_run(call)
        uncertainty = []
        if tools.truncated:
            uncertainty.append("At least one query was truncated; returned findings are an incomplete endpoint inventory.")
        if tools.missing:
            uncertainty.append("An exact evidence lookup returned not found; no replacement ID was used.")
        if status == "completed" and not findings:
            uncertainty.append("No supported endpoint evidence was returned; this does not establish absence of activity.")
        return InvestigationResult(status=status, request=request, findings=findings, error_code=error,
            uncertainty=tuple(uncertainty), metadata=RunMetadata(
                prompt_version=PROMPT_VERSION, configuration_version=CONFIGURATION_VERSION,
                llm=llm.metadata(), limits=limits.model_dump(), tool_calls=tools.calls,
                model_calls=model_calls, operations=tuple(tools.operations),
                evidence_readbacks=tools.evidence_readbacks, retrieved_events=len(tools.retrieved),
                truncated=tools.truncated, context_strategy="complete-evidence-batches-v1",
                context_batches=tuple(context_batches), window_total_matched=tools.window_total_matched,
                window_coverage_complete=tools.window_coverage_complete))

    try:
        check_bounds(tools.scope(), limits)
        if len(seed_calls) + 1 > limits.max_tool_calls:
            raise InvestigationError("seed_budget_exceeded")
        last_tool = tools.execute(_tool("query_endpoint_events", {
            **request.window(), "limit": limits.max_events_per_query}), origin="initial")
        initial = last_tool
        for call in seed_calls:
            seeds_attempted += 1
            last_tool = tools.execute(call, origin="seed")
        # Avoid trading the old time-split evidence coverage for a successful but
        # capped root window. Keep exact seeds ahead of optional recovery pages.
        if not tools.window_coverage_complete:
            last_tool = tools.recover_window(initial)
        observations = build_observations(tools.retrieved.values(), tools.truncated)
        offset, annotations = 0, {}
        while True:
            batch, messages, schema, receipt = model_batch(
                request, limits, tools, observations, offset, last_tool, llm.metadata(),
                getattr(llm,"input_token_upper_bound",None))
            context_batches.append(receipt.model_copy(update={"index": model_calls}))
            model_calls += 1
            reply_text = llm.complete(messages, schema, limits)
            if not isinstance(reply_text, str):
                raise InvestigationError("invalid_model_response")
            if len(reply_text.encode()) > limits.max_model_output_bytes:
                raise InvestigationError("model_output_limit")
            reply = ModelReply.parse_grounded_reply(reply_text,batch).root
            if reply.action == "tool":
                previous=(set(tools.retrieved),tools.truncated)
                last_tool = tools.execute(ToolCall(reply.tool))
                # A new record may corroborate or invalidate an earlier link.
                # Rebuild globally and review the new snapshot from its start;
                # annotations for old finding IDs must not survive that change.
                if previous!=(set(tools.retrieved),tools.truncated):
                    observations = build_observations(tools.retrieved.values(), tools.truncated)
                    offset, annotations = 0, {}
                continue
            by_id = {finding.finding_id: finding for finding in batch}
            for annotation in reply.annotations:
                observation = by_id.get(annotation.observation_id)
                if (observation is None or annotation.evidence_ids != observation.evidence_ids
                        or annotation.observation_id in annotations):
                    raise InvestigationError("invalid_evidence_reference")
                if annotation.interpretation is not None and annotation.interpretation not in interpretations_for(observation):
                    raise InvestigationError("invalid_interpretation")
                annotations[annotation.observation_id] = annotation.interpretation
            offset += len(batch)
            if offset < len(observations):
                continue
            tools.validate_references()
            findings = tuple(item.model_copy(update={
                "interpretation": INTERPRETATIONS.get(annotations.get(item.finding_id))}) for item in observations)
            return InvestigationResult.model_validate_json(result("completed", findings).model_dump_json())
    except InvestigationError as error:
        return result("failed", error=error.code)
    except (ValidationError, ValueError, KeyError, TypeError):
        return result("failed", error="invalid_contract_or_model_response")
    except TimeoutError:
        return result("failed", error="model_timeout")
    except ConnectionError:
        return result("failed", error="model_connection_failed")
    except Exception:
        return result("failed", error="adapter_failure")
