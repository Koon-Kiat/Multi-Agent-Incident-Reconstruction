# Incident Reconstruction Orchestrator handoff

The Authentication Investigation Agent is callable with the verified corpus and
local Ollama adapter. The actual Incident Reconstruction Orchestrator has not
been connected. This delivery covers authentication retrieval, findings and the
call boundary; dispatch and cross-agent reconstruction remain with their owners.

## Ordinary invocation

```python
from authentication_agent import InvestigationRequest, RequiredOperations, ToolCall, investigate
from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.investigate_corpus import local_model_runtime
from authentication_agent.llm.ollama_client import OllamaClient
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.query import EventStore

limits = Limits()
store = EventStore.load("out/corpus")
provider = CorpusAuthenticationProvider(store, limits)
config = OllamaConfig(model="qwen3:8b", num_ctx=8192, think=False,
                      temperature=0.0, seed=0)
runtime = local_model_runtime(config)  # Installed local weights; no downloads.
llm = OllamaClient(config)
request = InvestigationRequest(scenario_id="S02",
    start_utc="2026-09-21T02:04:30Z", end_utc="2026-09-21T02:06:00Z")

# No prescribed follow-up sequence is needed.
result = investigate(request, provider, llm, limits)
payload = result.model_dump(mode="json")
```

Existing four-positional-argument calls remain valid. Use the same limits for
provider and agent. Check `store.scenario_ids` before dispatch if unknown scenarios
must be distinguished from empty windows. All time bounds are UTC `[start,end)`;
original seven-digit timestamps and evidence IDs are preserved.

A runnable example supports fake mode, actual local inference and optional exact
lookup requirements:

```powershell
python -m authentication_agent.examples.investigate_required_corpus --corpus out/corpus
python -m authentication_agent.examples.investigate_required_corpus --corpus out/corpus --ollama
python -m authentication_agent.examples.investigate_required_corpus --corpus out/corpus --ollama --required-id S02-SEC-999999999
```

The original synthetic injection example remains available. Async callers use
`await asyncio.to_thread(investigate, request, provider, llm, limits,
required_operations=required)`. Direct synchronous Ollama calls in an active event
loop return `sync_adapter_requires_worker_thread`.

## Trusted required operations

Use the optional keyword-only `required_operations` when application logic
actually requires retrieval. Do not build it from event contents or model text.
It is authentication-specific and does not provide orchestration or scenario plans.

```python
required = RequiredOperations.from_calls(
    ToolCall(name="get_authentication_event",
             arguments={"evidence_id": "S02-SEC-999999999"}),
    ToolCall(name="query_authentication_events",
             arguments={**request.model_dump(), "event_ids": [4624], "limit": 100}),
    ToolCall(name="get_account_authentication_history",
             arguments={**request.model_dump(), "account": "caller-selected-account",
                        "limit": 100}),
)
result = investigate(request, provider, llm, limits, required_operations=required)
```

Supply the actual account required by the caller in the last example.
`RequiredOperations.model_validate_json(...)` also accepts
`{"operations": [{"name": ..., "arguments": ...}]}`; its schema pairs each tool
with the correct argument model. The list is bounded at 99 follow-ups, with the
initial query occupying the first of at most 100 configurable tool slots.
Construction rejects malformed plans. The agent revalidates a detached copy.

Execution order is initial query, required operations, then model decisions.
Every operation uses `AuthenticationTools` and the original scenario/window,
4624/4625 restriction, exact filters and configured limits. Exact lookup IDs are
never substituted. A valid absent ID completes with `no_evidence`, preserves the
ID in its receipt and adds missing-lookup uncertainty. Operational failure is
distinct from absence and stops the investigation without partial findings.
Later required operations receive `not_run` receipts; they are never silently omitted.

## Optional investigation and factual boundaries

After required retrieval, the model can select any of the three approved tools
or finish. Each turn includes the request, budgets, prior operation arguments
and outcomes, new evidence IDs, truncation, computed observations and bounded
authentication details grouped under the observations that reference them.
Raw XML and arbitrary event messages are excluded. All evidence remains
untrusted data. No test plan is supplied for ordinary investigations.

The model chooses whether a narrower query can supply useful evidence, reviews
the returned observations and decides whether to continue. Complete unfiltered
windows usually justify finishing. Truncated windows can justify distinct
filters or subwindows within the original limits. Missing telemetry can warrant
uncertainty without another query. There is no minimum optional call count.

Python computes authoritative counts, timestamps, entities, ordering and cohorts.
The decoder offers only existing observation/evidence pairs for annotations,
while all approved tools and tentative interpretation choices remain available.
The host independently rejects fabricated, merged, reordered or duplicate
references even if an adapter ignores that decoder schema. No model reply is
rewritten into an expected response. Final exact readback checks record consistency.

The provider interface is unchanged:
`query(QueryRequest) -> QueryResult` and
`get_event(evidence_id) -> AuthenticationEvent | None`.
PR #10 permits exact lookup of other supported Security types, including
4634/4688. The agent rejects those types before findings. Sysmon, malformed and
unknown IDs return `None` through the provider; malformed and cross-scenario
tool lookup arguments are rejected before reaching it. The broader EventStore
remains available for other components.

## Result and trace contract

New output metadata identifies `authentication-result-v2`,
`authentication-prompt-v16` and `authentication-config-v3`.
The v1 finding/status/request fields are retained. V2 adds
`metadata.operations` and `metadata.evidence_readbacks`; readers using an old
strict v1 schema must update. The current model can still read saved v1 results,
which default to an empty trace and zero readbacks. No provider signature changes
are needed. Export the current schema with
`python -m authentication_agent.investigate_corpus --schema`.

The Authentication Investigation Agent follow-up leaves this v2 handoff unchanged. A short internal model
assessment and decoder query-limit constraints do not add result fields or
change caller requirements. See the [follow-up report](AUTHENTICATION_AUTONOMY.md)
for measured optional retrieval and the remaining model-selection limitations.

| Result | Meaning |
| --- | --- |
| Completed with findings | Observations supported by retrieved records; retain all uncertainty |
| Completed and empty | No returned authentication evidence; not proof of no activity |
| Completed with truncation | Incomplete inventory, even if follow-up queries added records |
| Failed, no findings | Contract, provider, model or budget failure; never classify as clean |

Findings retain `finding_id`, `agent_type`, `scenario_id`, `observed_events`,
`timestamps`, `entities`, ordered `evidence_ids`, `uncertainty` and nullable
`interpretation`. Qualified interpretations do not establish compromise,
a shared actor, accuracy or an independent verification verdict.

Every operation receipt includes its zero-based `index`, `origin`
(`initial`, `required`, `model`), exact `call`, optional `required_index`,
`status`, returned and new evidence IDs, `truncated`, `provider_invoked`,
`reused_from` and sanitized `error_code`.
Statuses are `completed`, `no_evidence`, `rejected`, `failed` and `not_run`.
A required operation that succeeded remains visible if later model inference fails.

Identical successful operations reuse a per-investigation snapshot rather than
calling the provider again. Equivalent timestamp forms, default arguments and
event-type sets share a key; history and query tools share provider query
semantics. Changed filters, windows or limits remain distinct. Every attempted
operation, including a duplicate, consumes a tool slot; an attempt beyond the
budget is rejected without a provider call. Repetition therefore terminates.
There is no retry policy. Providers must expose a consistent read-only snapshot,
as EventStore does; this is not a live polling interface.

Final consistency reads are separately counted in `evidence_readbacks`, bounded
by the union of retrieved IDs and excluded from investigative tool counts.
They are not optional model queries. Missing results, incomplete coverage and
retrieved-only counts must survive downstream consumption.

## Limits, errors and integration responsibilities

Defaults remain 8 tool attempts, 100 events/query, a one-hour window, 2048 output
tokens and 60 seconds per model request. The context-byte limit includes messages
and the grounded decoder schema. Each query stays within the original window.
No automatic expansion or completeness claim is made.

Errors include `tool_budget_exhausted`, `tool_scope_violation`,
`provider_scope_violation`, `invalid_contract_or_model_response`,
`provider_contract_violation`, `invalid_evidence_reference`, `evidence_changed`,
`missing_evidence`, `context_size_limit`, `model_timeout`,
`model_connection_failed`, `provider_timeout`, `provider_connection_failed`
and `provider_failure`. Provider exception text is not exposed.
Request construction, preflight and corpus loading can raise before dispatch.
The example is programmatic guidance; the main corpus CLI retains its documented
exit 0/1/2/3 behavior.

Provider latency and corpus loading are outside the per-model deadline. A custom
blocking synchronous provider cannot be forcibly cancelled here. The orchestrator
owner still decides whole-run deadlines, cancellation, provider lifetime, model
configuration and scenario dispatch. Endpoint analysis, cross-source correlation,
ATT&CK mapping and final reconstruction remain separate implementations.

See the [current validation report](AUTHENTICATION_CORPUS_INTEGRATION.md) for
separate ordinary, required-operation and directed-model results. Deterministic
required execution does not demonstrate autonomous tool selection. Successful
factual readback does not establish detection accuracy or complete model reliability.
