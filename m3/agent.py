"""M5 entry point: deterministic facts, constrained model interpretation."""

import json

from pydantic import ValidationError

from m3.config import CONFIGURATION_VERSION, Limits
from m3.errors import InvestigationError
from m3.llm import LLMAdapter
from m3.models import InvestigationRequest, InvestigationResult, ModelReply, RunMetadata, ToolCall
from m3.observations import build_observations
from m3.prompts import PROMPT_VERSION, SYSTEM_PROMPT
from m3.queries.interface import AuthenticationEventProvider
from m3.queries.tools import AuthenticationTools, TOOL_ARGUMENT_MODELS

INTERPRETATIONS = {
    "may_warrant_review": "The observed authentication sequence may warrant further investigation; it does not establish compromise.",
    "context_required": "Additional context is needed to interpret this authentication activity; no attack classification is made.",
}


def investigate(request: InvestigationRequest, provider: AuthenticationEventProvider,
                llm: LLMAdapter, limits: Limits | None = None) -> InvestigationResult:
    """Run locally against any compatible provider; operational failure returns no findings."""
    limits = limits or Limits()
    tools = AuthenticationTools(request, provider, limits)
    model_calls = 0

    def result(status: str, findings: tuple = (), error: str | None = None) -> InvestigationResult:
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
            tool_calls=tools.calls, model_calls=model_calls))

    try:
        # Mandatory bounded initial retrieval prevents unsupported model-only answers.
        last_tool = tools.execute(ToolCall(name="query_authentication_events", arguments={
            **request.model_dump(), "limit": limits.max_events_per_query}))
        while True:
            observations = build_observations(tools.retrieved.values(), tools.truncated)
            context = {"request": request.model_dump(), "tool_calls_remaining": limits.max_tool_calls - tools.calls,
                "last_tool_result": last_tool, "observations": [o.model_dump(mode="json") for o in observations],
                "tool_argument_schemas": {name: model.model_json_schema() for name, model in TOOL_ARGUMENT_MODELS.items()},
                "response_schema": ModelReply.model_json_schema(), "limits": limits.model_dump()}
            messages = [{"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": json.dumps(context)}]
            if len(json.dumps(messages).encode()) > limits.max_context_bytes:
                raise InvestigationError("context_size_limit")
            model_calls += 1
            reply_text = llm.complete(messages, ModelReply.model_json_schema(), limits)
            if not isinstance(reply_text, str):
                raise InvestigationError("invalid_model_response")
            if len(reply_text.encode()) > limits.max_model_output_bytes:
                raise InvestigationError("model_output_limit")
            reply = ModelReply.model_validate_json(reply_text)
            if reply.action == "tool":
                last_tool = tools.execute(reply.tool)
                continue
            by_id = {o.finding_id: o for o in observations}
            annotations = {}
            for annotation in reply.annotations:
                observation = by_id.get(annotation.observation_id)
                if observation is None or annotation.evidence_ids != observation.evidence_ids or annotation.observation_id in annotations:
                    raise InvestigationError("invalid_evidence_reference")
                annotations[annotation.observation_id] = annotation.interpretation
            tools.validate_references()
            findings = tuple(o.model_copy(update={"interpretation": INTERPRETATIONS.get(annotations.get(o.finding_id))}) for o in observations)
            # Validate the final serialized boundary M5 will consume.
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
