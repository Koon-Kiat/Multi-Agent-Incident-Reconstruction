# Incident Reconstruction Orchestrator handoff

The Authentication Investigation Agent's existing call boundary is tested with
the real corpus and local Ollama. The actual Incident Reconstruction Orchestrator
is not connected or tested. This handoff does not implement dispatch, correlation,
endpoint investigation or independent evidence verification.

## Invoke with the existing provider and local adapter

```python
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.query import EventStore
from authentication_agent import InvestigationRequest, investigate
from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.investigate_corpus import local_model_runtime
from authentication_agent.llm.ollama_client import OllamaClient

limits = Limits()
store = EventStore.load("out/corpus")
provider = CorpusAuthenticationProvider(store, limits)
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
`get_event(evidence_id) -> AuthenticationEvent | None`. Exact lookup can return
any supported Security event, including 4634/4688; queries only return 4624/4625.
The agent rejects unsupported event types before using them in findings. Sysmon,
unknown and malformed IDs return `None` through this provider; use `EventStore`
for cross-source access. PR #10
detaches constructor inputs and returned records, so caller mutation cannot
change the snapshot. `LLMAdapter` supplies
`metadata()` and `complete(messages, schema, limits) -> str`.
For async dispatch use
`await asyncio.to_thread(investigate, request, provider, llm, limits)`.
Direct calls inside an event loop return `sync_adapter_requires_worker_thread`.
The [real-data CLI](../authentication_agent/README.md) runs this boundary;
`authentication_agent/examples/invoke_authentication.py` remains the synthetic injection example.

## Consume the existing result

`InvestigationResult` remains `authentication-result-v1`. Export the schema with
`python -m authentication_agent.investigate_corpus --schema`. Consume structured fields:

| Result | Handling |
| --- | --- |
| Completed, nonempty | Evidence-derived observations; retain uncertainty |
| Completed, empty | No returned authentication evidence; not proof of no activity |
| Completed, truncation uncertainty | Partial inventory; counts/sequences cover retrieved records |
| Failed, empty | Operational/model/contract error; inspect `error_code`, never classify as clean |

Each finding has `finding_id`, `agent_type: authentication`, `scenario_id`,
`observed_events`, `timestamps`, `entities`, ordered `evidence_ids`, `uncertainty`
and nullable `interpretation`. Metadata records versions, LLM settings, limits
and call counts. Current prompt/configuration versions are
`authentication-prompt-v4` and `authentication-config-v3`; the result schema and
call signature are unchanged. Record runtime version/digest from preflight when needed.

Python computes observations. Optional interpretations are qualified phrases:
review may be warranted or more context is needed. Authentication patterns alone
never establish compromise or a common actor. No `verification_status` or
independent evaluation verdict is emitted.

Keep exact IDs and original timestamp strings. Citations resolve unchanged within
the request scope at final readback. Missing, fabricated, changed or cross-scenario
references fail closed with no partial findings. Equal timestamps imply no causal
precedence. The `AUTH-` finding-ID prefix identifies authentication observations.

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

The final real-corpus Qwen3 matrix passes **7/11 checks**, with all natural
S01-S03 findings passing factual readback. It still substitutes an observed ID
for a requested missing ID, skips the success-only query and account-history requests,
and finishes instead of attempting the budget-exhaustion exercise. These are
plan-following failures, not a demonstrated budget bypass. Even an empty window
produced one redundant query in the final run. Required retrieval must remain
deterministic; do not depend on model execution of a prescribed follow-up plan.
Tool execution still validates arguments, scope, event type and budgets. The
unchanged result schema does not certify that a developer's external plan was
followed; the validation runner reports those failures separately in `check_errors`.
See [actual results](AUTHENTICATION_CORPUS_INTEGRATION.md). Avoid unbounded retries
of an unsupported model response. Do not treat `completed` as an accuracy verdict.

Outstanding decisions: final envelope agreement, provider lifetime,
model/configuration ownership, scenario/window dispatch, whole-run deadlines,
cancellation, bounded retries and continuation for truncated windows. The Endpoint
Investigation Agent's findings, cross-source correlation and end-to-end
reconstruction require their owners' implementations and integration tests.
