"""Lossless, bounded model views over a complete endpoint evidence snapshot.

Batching changes only model presentation. Findings and relationships are always
computed over the entire retrieved union, never over an individual batch.
"""

import json

from endpoint_agent.errors import InvestigationError
from endpoint_agent.models import ContextBatch, ModelReply
from endpoint_agent.observations import BASE_UNCERTAINTY
from endpoint_agent.prompts import SYSTEM_PROMPT

# Two chat messages, including role delimiters and the generation prefix. The
# shared Qwen byte-level tokenizer cannot use more text tokens than UTF-8 bytes.
# The JSON decoder's schema is not prompt text; it still counts toward the
# independent serialized-context byte limit below.
CHAT_TEMPLATE_TOKEN_RESERVE = 256


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _observation(finding):
    # Scope is carried once in request. Null fields mean unavailable, and the
    # common uncertainty applies to every row. All non-null source facts,
    # relationships, evidence IDs and full-resolution timestamps are retained.
    value = finding.model_dump(mode="json", exclude_none=True,
                               exclude={"agent_type", "scenario_id", "interpretation"})
    value["uncertainty"] = [s for s in finding.uncertainty if s not in BASE_UNCERTAINTY]
    return value


def model_batch(request, limits, tools, observations, offset, last_tool, llm_metadata):
    """Choose the largest fitting consecutive batch, or fail without dropping data.

    A caller exposing num_ctx (including Ollama and FinishGuard) also gets a
    conservative input token bound with output space reserved. Custom adapters
    without num_ctx receive the serialized byte guard only.
    """
    num_ctx = llm_metadata.get("num_ctx")
    token_budget = num_ctx - limits.max_output_tokens if type(num_ctx) is int else None

    def prepare(count):
        batch = observations[offset:offset + count]
        ids = {eid for finding in batch for eid in finding.evidence_ids}
        # Full receipts remain in result metadata. The model needs the latest
        # operation for follow-up/repeat decisions, not repeated evidence lists.
        history = []
        if tools.operations:
            op = tools.operations[-1]
            receipt = op.model_dump(mode="json", include={
                "origin", "call", "status", "total_matched", "truncated", "reused_from"})
            receipt["returned_events"] = len(op.evidence_ids)
            history.append(receipt)
        last = {**last_tool, "returned_events": len(last_tool["evidence_ids"]),
                "evidence_ids": [eid for eid in last_tool["evidence_ids"] if eid in ids]}
        context = {
            "request": request.window(),
            "limits": {"max_events_per_query": limits.max_events_per_query},
            "tool_calls_remaining": limits.max_tool_calls - tools.calls,
            "last_tool_result": last, "operation_history": history,
            "coverage": {"retrieved_events": len(observations), "truncated": tools.truncated,
                         "missing_exact_lookup": tools.missing},
            "batch": {"offset": offset, "count": count, "total": len(observations),
                      "revision": tools.calls},
            "shared_uncertainty": BASE_UNCERTAINTY,
            "observations": [_observation(finding) for finding in batch],
        }
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _json(context)}]
        schema = ModelReply.grounded_schema(batch, limits.max_events_per_query)
        # Mandatory seeds/recovery can consume every slot before model review.
        # Preserve the existing opt-out behavior for model-driven budget loops;
        # the orchestrator's optional FinishGuard continues to own that policy.
        if (tools.calls >= limits.max_tool_calls and tools.operations
                and tools.operations[-1].origin != "model"):
            schema = {"$defs": schema["$defs"], "$ref": "#/$defs/_FinishReply"}
        size = len(_json({"messages": messages, "schema": schema}).encode("utf-8"))
        tokens = sum(len(m["content"].encode("utf-8")) for m in messages) + CHAT_TEMPLATE_TOKEN_RESERVE
        fits = size <= limits.max_context_bytes and (token_budget is None or tokens <= token_budget)
        return fits, batch, messages, schema, size, tokens

    remaining = len(observations) - offset
    # Empty windows still require one model decision and the same guards.
    first = prepare(min(1, remaining))
    if not first[0]:
        raise InvestigationError("context_size_limit")
    best = first
    low, high = 2, remaining
    while low <= high:
        middle = (low + high) // 2
        candidate = prepare(middle)
        if candidate[0]:
            best, low = candidate, middle + 1
        else:
            high = middle - 1
    _, batch, messages, schema, size, tokens = best
    receipt = ContextBatch(index=0, revision=tools.calls,
        observation_ids=tuple(f.finding_id for f in batch),
        evidence_ids=tuple(dict.fromkeys(eid for f in batch for eid in f.evidence_ids)),
        context_bytes=size, input_token_upper_bound=tokens if token_budget is not None else None)
    return batch, messages, schema, receipt
