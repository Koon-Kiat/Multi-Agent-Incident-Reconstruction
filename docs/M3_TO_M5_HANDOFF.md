# M3 to M5 integration handoff

Status: M5 is not present in local or fetched `origin/main`, and there were no
open delivery PRs at the 2026-09-22 refresh. M3's entry point is implemented;
orchestrator compatibility and the final shared finding contract await M5.

## Calling M3

Use the existing public synchronous entry point:

```python
from m3 import InvestigationRequest, investigate
from m3.config import Limits, OllamaConfig
from m3.llm.ollama_client import OllamaClient

request = InvestigationRequest(
    scenario_id="SYN-A",
    start_utc="2026-01-10T00:00:00Z",
    end_utc="2026-01-10T00:01:00Z",
)
llm = OllamaClient(OllamaConfig(
    model="qwen3:8b", endpoint="http://localhost:11434", num_ctx=8192, think=False,
))
result = investigate(request, m2_authentication_provider, llm, Limits())
payload = result.model_dump(mode="json")
```

`m2_authentication_provider` is supplied by M5 after M2 delivers the read-only
adapter; it implements `AuthenticationEventProvider`. The model shown is the
user-selected provisional local validation model, not a final team selection.
Keep Ollama local-only and use an already installed model. No cloud inference or
model download occurs in this call.

For an async orchestrator, use
`await asyncio.to_thread(investigate, request, provider, llm, limits)`.
The synchronous Ollama adapter intentionally reports
`sync_adapter_requires_worker_thread` if called directly inside a running loop.
Do not block the orchestrator's event loop.

## Runnable synthetic example

`m3/examples/invoke_m3.py` demonstrates provider and LLM injection without any
orchestration, endpoint investigation or incident reconstruction:

```powershell
python -m m3.examples.invoke_m3
python -m m3.examples.invoke_m3 --scenario SYN-E
$env:MAIR_OLLAMA_MODEL = 'qwen3:8b'
$env:MAIR_OLLAMA_ENDPOINT = 'http://127.0.0.1:11435'
$env:MAIR_OLLAMA_NUM_CTX = '8192'
$env:MAIR_OLLAMA_THINK = 'off'
python -m m3.examples.invoke_m3 --ollama
```

The last command uses the dedicated local-only validation server; see the
validation report for server startup and exact runtime settings. The example
does not implement M5 responsibilities. Its success, empty and failure envelopes
are covered by `m3/tests/test_m5_example.py`.

## Result contract

`InvestigationResult` in `m3/models.py` is the existing provisional schema. Obtain
the JSON schema with `python -m m3 --schema`. Consume fields directly, not text:

| Outcome | Meaning |
| --- | --- |
| `status='completed'`, findings nonempty | Validated evidence-derived observations with optional tentative interpretation |
| `status='completed'`, findings empty | No authentication evidence returned for the window; uncertainty states this is not proof of no activity |
| `status='failed'`, findings empty | Operational/model/contract failure; inspect `error_code`; never treat this as a clean scenario |

Each finding has `finding_id`, `agent_type='authentication'`, `scenario_id`,
`observed_events`, `timestamps`, `entities`, ordered `evidence_ids`, `uncertainty`
and optional `interpretation`. Counts, entities, timing and evidence references
are computed in Python. Model interpretation is restricted to qualified phrases;
it is not an attack/compromise classification or an M6 verification status.

Every cited ID must have been retrieved through the approved tools and must
resolve exactly to the same record in the same scenario at final readback.
Missing/changed/fabricated/cross-scenario references fail closed, without partial
findings. Equal timestamps use ID ordering for reproducibility, not causality.
Truncated queries explicitly limit the completeness of observations.

## Errors and budgets

`Limits` controls tool calls, query size, window duration, context/event/output
bytes, output tokens and the model request timeout. The initial query consumes
one tool call. Every model turn finishes or requests another bounded tool call.
Ollama requests have both socket timeouts and a total asynchronous deadline.
Provider latency is not covered by that deadline; M2 must bound its own I/O.

Typical errors include `model_timeout`, `model_connection_failed`,
`model_not_installed_or_endpoint_missing`, `incomplete_model_response`,
`invalid_contract_or_model_response`, `tool_budget_exhausted`,
`invalid_evidence_reference`, `missing_evidence` and `evidence_changed`.
Schema-valid input construction may itself raise a Pydantic validation error
before `investigate` is called; validate M5's request before dispatch.
Treat adapters as trusted Python integrations, not untrusted plugins.

Real Qwen3 validation found that an exact requested tool order is not reliable:
one directed query exercise selected an allowed exact-event lookup instead.
Mandatory retrieval must remain deterministic in M3/M5 code. Do not rely on the
model to fulfill an externally prescribed query plan. All natural scenario
observations remained evidence-correct, and missing lookup plus tool-budget
exercises failed or completed according to the existing contract. See the
[actual validation record](M3_VALIDATION_AND_INTEGRATION.md).

## Remaining contract decisions

Agree the final shared finding envelope, M2 adapter injection/lifetime, scenario
and window dispatch, model/configuration ownership, provider timeouts, retry
policy and any continuation strategy for truncated windows. Correlation, shared
actor attribution and full incident reconstruction remain M5 responsibilities.
Independent verification/evaluation remain M6 responsibilities.

## Message to send to M5

> M3 exposes `investigate(request, provider, llm, limits) -> InvestigationResult`
> and a runnable injection example at `m3/examples/invoke_m3.py`. Requests need a
> scenario ID and bounded UTC window; supply M2's read-only provider and the local
> Ollama adapter. Results distinguish completed, empty and failed investigations,
> preserve evidence IDs and uncertainty, and make no independent verification or
> compromise verdict. Async callers should use `asyncio.to_thread`. Please confirm
> the shared result envelope, dispatch/retry policy and provider ownership so we
> can connect M3 when M2 and the orchestrator are ready.
