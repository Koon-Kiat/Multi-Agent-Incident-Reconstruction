# Incident Reconstruction Orchestrator handoff

The Authentication Investigation Agent's existing call boundary is tested with
the real corpus and local Ollama. The actual Incident Reconstruction Orchestrator
is not connected or tested. This handoff does not implement dispatch, correlation,
endpoint investigation or independent evidence verification.

## Invoke with the existing provider and local adapter

```python
from m2.adapters.m3_provider import M2AuthenticationProvider
from m2.query import EventStore
from m3 import InvestigationRequest, investigate
from m3.config import Limits, OllamaConfig
from m3.investigate_corpus import local_model_runtime
from m3.llm.ollama_client import OllamaClient

limits = Limits()
store = EventStore.load("out/corpus")
provider = M2AuthenticationProvider(store, limits)
config = OllamaConfig(model="qwen3:8b", endpoint="http://127.0.0.1:11434",
                      num_ctx=8192, think=False, temperature=0.0, seed=0)
runtime = local_model_runtime(config)  # Confirm local installed weights first.
llm = OllamaClient(config)
request = InvestigationRequest(scenario_id="S02",
    start_utc="2026-09-21T02:04:30Z", end_utc="2026-09-21T02:06:00Z")
result = investigate(request, provider, llm, limits)
payload = result.model_dump(mode="json")
```

Required request fields: `scenario_id`, `start_utc`, `end_utc`. UTC bounds must be
ordered and within configured duration. Check `store.scenario_ids` before dispatch
if unknown scenarios must differ from empty windows. Use the same limits for
provider and agent. Load once and reuse the verified read-only snapshot.
Account/host filters belong to query tools, not the top-level request.

`AuthenticationEventProvider` supplies `query(QueryRequest) -> QueryResult` and
`get_event(evidence_id) -> AuthenticationEvent | None`. `LLMAdapter` supplies
`metadata()` and `complete(messages, schema, limits) -> str`.
For async dispatch use
`await asyncio.to_thread(investigate, request, provider, llm, limits)`.
Direct calls inside an event loop return `sync_adapter_requires_worker_thread`.
The [real-data CLI](../m3/README.md) runs this boundary;
`m3/examples/invoke_m3.py` remains the synthetic injection example.

## Consume the existing result

`InvestigationResult` remains `m3-provisional-v1`. Export the schema with
`python -m m3.investigate_corpus --schema`. Consume structured fields:

| Result | Handling |
| --- | --- |
| Completed, nonempty | Evidence-derived observations; retain uncertainty |
| Completed, empty | No returned authentication evidence; not proof of no activity |
| Completed, truncation uncertainty | Partial inventory; counts/sequences cover retrieved records |
| Failed, empty | Operational/model/contract error; inspect `error_code`, never classify as clean |

Each finding has `finding_id`, `agent_type: authentication`, `scenario_id`,
`observed_events`, `timestamps`, `entities`, ordered `evidence_ids`, `uncertainty`
and nullable `interpretation`. Metadata records versions, LLM settings, limits
and call counts. Record runtime version/digest from preflight when needed.

Python computes observations. Optional interpretations are qualified phrases:
review may be warranted or more context is needed. Authentication patterns alone
never establish compromise or a common actor. No `verification_status` or
independent evaluation verdict is emitted.

Keep exact IDs and original timestamp strings. Citations resolve unchanged within
the request scope at final readback. Missing, fabricated, changed or cross-scenario
references fail closed with no partial findings. Equal timestamps imply no causal
precedence. The `M3-` finding-ID prefix remains a compatibility identifier.

## Errors, deadlines and outstanding decisions

Defaults: 8 tool calls, 100 events/query, one-hour window and 60 seconds per model
request. The new CLI uses context 8192 and thinking disabled. Initial retrieval
uses one tool call; final consistency reads are bounded separately by the retrieved
union. A whole investigation can span several model deadlines. Provider latency
and corpus loading are outside that deadline. The synchronous interface cannot
forcibly cancel a custom blocking provider.

Typical errors include `model_timeout`, `model_connection_failed`,
`incomplete_model_response`, `invalid_evidence_reference`, `evidence_changed`,
`missing_evidence`, `tool_scope_violation`, `provider_scope_violation`,
`tool_budget_exhausted`, `context_size_limit` and
`invalid_contract_or_model_response`. Request/config construction, preflight and
corpus loading can raise before dispatch. CLI setup diagnostics (exit 2) are not
typed investigation results. Exit 3 preserves the completed-but-truncated typed
result without changing the public schema.

Qwen3 still fails directed tool-selection checks. Required retrieval must remain
deterministic; do not depend on model execution of a prescribed follow-up plan.
See [actual results](AUTHENTICATION_CORPUS_INTEGRATION.md). Do not retry the same
unsupported response indefinitely.

Outstanding decisions: final envelope agreement, provider lifetime,
model/configuration ownership, scenario/window dispatch, whole-run deadlines,
cancellation, bounded retries and continuation for truncated windows. The Endpoint
Investigation Agent's findings, cross-source correlation and end-to-end
reconstruction require their owners' implementations and integration tests.
