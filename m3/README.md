# M3 Authentication Investigation Agent

This is the independent M3 development milestone. It runs locally with synthetic
normalised Windows Security events, without M2, M4, M5, M6 or an LLM server.
All interfaces here are **provisional M3 adapters**, not an agreed team contract.
No evaluation materials are used by the module, fixtures, prompts or tests.

## Run locally

From the repository root, with Python 3.11 or later (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe -m m3 --mode fake --scenario SYN-A --start 2026-01-10T00:00:00Z --end 2026-01-10T00:01:00Z
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp
```

If dependencies are already installed, the shorter commands are:

```powershell
python -m m3 --mode fake --scenario SYN-A --start 2026-01-10T00:00:00Z --end 2026-01-10T00:01:00Z
python -m pytest -q --basetemp .test-tmp
python -m m3 --schema
```

Installation also exposes the equivalent `mair-m3` command. JSON goes to stdout;
exit code 0 means a completed investigation (possibly empty), 1 an operational
failure with no findings, and 2 invalid CLI/configuration input. Configuration
errors emit a compact diagnostic; investigation results use the typed envelope.
The CLI only loads its packaged synthetic fixture; it has no arbitrary input
path or EVTX mode. Run real events through an M2 provider once that is available.

## Optional local Ollama

No team model setting existed at implementation time. `MAIR_OLLAMA_MODEL` (or
`--model`) is therefore required for Ollama mode. Choose a model already installed
on your own machine; this package never installs, pulls or downloads a model.
The provisional runtime defaults are temperature 0, seed 0 and a 32768-token
context. They are not a team model selection or a reproducibility guarantee for
different runtime/model versions or hardware.

Real local validation has now been performed with the user's selected
`qwen3:8b` (provisional, not a team-wide model decision). The tested profile is
an 8192-token context and thinking disabled:

```powershell
$env:MAIR_OLLAMA_MODEL = 'qwen3:8b'
$env:MAIR_OLLAMA_NUM_CTX = '8192'
$env:MAIR_OLLAMA_THINK = 'off'
```

The equivalent CLI flags are `--num-ctx 8192 --think off`. `--think auto` leaves
the runtime default unchanged; `on` and `off` explicitly select thinking behavior
for compatible models. These settings do not alter evidence validation or the
60-second request deadline. See the [validation report](../docs/M3_VALIDATION_AND_INTEGRATION.md)
for actual successes, initial failures, model limitations and local-only startup.

Use an Ollama server configured for local-only operation. Set
`OLLAMA_NO_CLOUD=1` in the environment of the **server**, then restart it, or use
Ollama's `disable_ollama_cloud` server setting. Setting it only in the client shell
does not reconfigure an already running server. See the
[official local-only configuration](https://docs.ollama.com/faq#how-do-i-disable-ollama-cloud-features).
Keep Ollama bound to loopback. A local service is a trusted dependency; this Python
package is not an OS sandbox for arbitrary provider code or a misconfigured proxy.

```powershell
ollama list
$env:MAIR_OLLAMA_MODEL = '<exact-installed-local-model-name>'
$env:MAIR_OLLAMA_ENDPOINT = 'http://localhost:11434'
python -m m3 --mode ollama --scenario SYN-A --start 2026-01-10T00:00:00Z --end 2026-01-10T00:01:00Z

# Explicit opt-in: the rest of the suite never requires Ollama.
$env:MAIR_RUN_OLLAMA_SMOKE = '1'
python -m pytest -q -m ollama
Remove-Item Env:MAIR_RUN_OLLAMA_SMOKE
```

The transport uses [`POST /api/chat`](https://docs.ollama.com/api/chat) with
`stream: false` and the Pydantic response schema in `format`, following
[Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs).
Models/runtimes must support this schema, including nullable fields and references.
Unsupported schemas fail closed; there is no unvalidated free-text fallback.
Endpoints are restricted to HTTP loopback origins, `localhost` is pinned to
127.0.0.1, environment proxies are disabled, redirects are rejected, and model
names containing `cloud` are refused. The server's local-only setting also
prevents a renamed cloud-backed model from forwarding evidence externally.

## Integration with M2

Implement `m3.queries.interface.AuthenticationEventProvider`:

```python
def get_event(self, evidence_id: str) -> AuthenticationEvent | None: ...
def query(self, request: QueryRequest) -> QueryResult: ...
```

`None` is the explicit not-found value. Lookup is an exact, corpus-wide ID lookup;
never substitute a nearby or fuzzy-matched record. The agent separately checks
scenario, event type and investigation window on every lookup. Queries require
`scenario_id`, `start_utc`, `end_utc`; optional fields are `event_ids`, `account`,
`host`, and `limit`. `QueryResult` contains `events` and a mandatory `truncated`
boolean. Set `truncated` when more matching evidence exists than was returned.

Boundary semantics requiring M2 confirmation:

| Area | Provisional M3 contract |
| --- | --- |
| Time range | UTC `[start_utc, end_utc)`: inclusive start, exclusive end; start must precede end |
| Precision | ISO 8601 string with `Z` or `+00:00`, 0-7 fractional digits; preserve the exact original UTC string and all seven digits if supplied |
| Ordering | Integer 100ns ticks, then evidence ID lexicographically; tied timestamps do not establish precedence |
| Scope | Exact scenario match, Security channel, Event IDs 4624/4625 only for queries/tools |
| Filters | Exact, case-sensitive string equality; `None` means no filter and `""` filters for an actual empty value |
| Account | Use `user` when non-null, otherwise string `event_data.TargetUserName`; no inferred domain stripping/case folding |
| Limits | Reject excessive windows/result limits rather than silently expanding or clamping them |
| Read-only | No mutations; detached deep copies on input and return in the synthetic provider |
| Consistency | Exact lookup must return the same event during investigation and final reference readback |
| Evidence IDs | `scenario_id + '-SEC-' + original record_id`, e.g. `SYN-A-SEC-1`; globally unique for the supported corpus layout |

The provisional event model requires `evidence_id`, `scenario_id`, `source_type`
(`windows_security`), `channel` (`Security`), positive integer `source_event_id`
and `record_id`, `timestamp_utc`, and nonempty `raw_reference`. `host` and `user`
may be null or empty; `event_data` is a JSON object (empty when absent).
Known optional event fields are `TargetUserName`, `TargetDomainName`, `IpAddress`,
`WorkstationName`, and `LogonType`. Other event-data fields survive storage but
are not fed to the model. Malformed optional identity values are retained in the
event, excluded from entities and reported as uncertainty. Invalid required
fields reject the record. Extra top-level fields need an explicit adapter mapping.

`raw_reference` is opaque: M3 never opens it. Preserve the original source
reference and record ID so M6 can resolve them independently later. Synthetic
references are `synthetic://...`, not actual EVTX locations. The proposed ID
format assumes one original Security record namespace per scenario; if M2
combines exports/hosts with overlapping record IDs, agree an extended stable
namespace before integration. Duplicate IDs are rejected today.

Keep precise timestamps as strings or integer ticks through the M2 adapter.
Do not round-trip them through Python `datetime` alone. M3 accepts already-UTC
timestamps; timezone conversion/normalisation remains M2's responsibility.

The agent imports only the provider Protocol and shared semantics. Replacing
`InMemoryAuthenticationEventProvider` requires no agent-logic rewrite. M2 may
translate its final shared schema at this boundary; these models do not freeze
M2's database, normalisation or detection design.

## Integration with M5

The synchronous Python entry point is:

```python
investigate(
    request: InvestigationRequest,
    provider: AuthenticationEventProvider,
    llm: LLMAdapter,
    limits: Limits | None = None,
) -> InvestigationResult
```

Working example, also usable as M5's future call pattern:

```python
from m3 import InvestigationRequest, investigate
from m3.__main__ import synthetic_provider
from m3.llm.fake import FakeLLM

request = InvestigationRequest(
    scenario_id="SYN-A",
    start_utc="2026-01-10T00:00:00Z",
    end_utc="2026-01-10T00:01:00Z",
)
result = investigate(request, synthetic_provider(), FakeLLM())
print(result.model_dump_json(indent=2))
# Swap the provider and LLMAdapter implementations when integrating.
```

`LLMAdapter` supplies `metadata()` and `complete(messages, schema, limits) -> str`.
An adapter must honor the timeout/output limits; the supplied Ollama adapter
implements transport limits and every reply is validated by the agent.
The model chooses between approved tools and a finish action. There is no
dynamic function dispatch, Python/SQL execution, filesystem tool or arbitrary URL
fetch. Model-generated tool arguments cannot expand the original scenario/window.

## Findings and uncertainty

The result envelope contains `status` (`completed`/`failed`), the request, findings,
`error_code`, run-level uncertainty, and reproducibility metadata. A completed run
with no evidence returns `findings: []` and an explicit coverage limitation.
The machine-readable schema is available via `InvestigationResult.model_json_schema()`
or `python -m m3 --schema`.

Each finding has `finding_id`, `agent_type: authentication`, `scenario_id`,
`observed_events`, optional `interpretation`, `timestamps`, `entities`, ordered
`evidence_ids`, and `uncertainty`. See the complete executed output in
[examples/synthetic-result.json](examples/synthetic-result.json).

Python constructs facts from the union of retrieved records. Cohorts distinguish
account, reported account, domain, target host, source address, workstation and
logon type. Missing, conflicting or malformed identity dimensions keep events
separate. This intentionally favors uncertainty over linking unrelated activity.
For each cohort, counts cover retrieved evidence, not necessarily the whole
window. Two or more failed logons strictly before a success form an observation
of repeated failures followed by success. This is descriptive arithmetic, not a
baseline detector, threat classification, causal inference or attack label.
Timestamps tied at full precision never establish a before/after relationship.

The model can request more bounded evidence and choose `may_warrant_review`,
`context_required`, or null for an existing observation. Python renders those
choices as qualified text. Free-form model narratives are deliberately excluded
in v1 so unsupported entity details or compromise claims cannot enter findings.
All computed observations are returned, even if the model annotates only some.
This finite interpretation vocabulary is a known initial limitation.

Every model reference must exactly match an existing observation and its ordered
evidence IDs. Before return, every referenced event is looked up again and checked
against its retrieved content and scope. Missing, changed, cross-scenario or
fabricated references fail the run with no findings. This is internal consistency
validation; no `verification_status` is emitted. Independent verification belongs
to M6. M5 still needs to agree the final finding schema and orchestrate agents.

## Limits and failure behavior

All limits are configurable through `Limits`, with upper/lower validation bounds.
The CLI exposes the most common overrides: `--max-tool-calls`, `--max-events`,
`--max-window-seconds`, `--timeout`.

| Limit | Default |
| --- | ---: |
| Approved tool calls, including initial query | 8 |
| Events per query | 100 |
| Investigation/query window | 3600 seconds |
| Model content | 32768 UTF-8 bytes |
| Stored event accepted by tools | 16384 UTF-8 bytes |
| Model context envelope | 262144 UTF-8 bytes |
| Model request timeout | 60 seconds |
| Generated model tokens | 2048 |

Each model turn either finishes or consumes another tool call, bounding model
turns by the same budget. Retrieved records are deduplicated by evidence ID.
Final exact-ID consistency reads are separate from the model tool budget and
bounded by the number of distinct retrieved records (at most tool calls times
events per query). Truncation remains explicit; v1 has no pagination token and
does not claim complete coverage after a truncated query. A model may narrow
the window or filters for additional queries.

The HTTP client applies both transport timeouts and an overall asynchronous
deadline for each request, including response reception. Async M5 applications
should invoke this synchronous entry point with `await asyncio.to_thread(investigate,
request, provider, llm)`; calling the synchronous Ollama adapter directly inside
a running event loop returns `sync_adapter_requires_worker_thread`. Custom Python
providers are trusted integration code; M3 cannot cancel an indefinitely blocked
provider. Failure codes distinguish connection, timeout, HTTP/model absence,
invalid responses, exhausted budgets, limits and provider contract violations.
Failures return no partial findings and no fabricated substitute interpretation.
Exceptions do not include event bodies. The program does not log prompt contents.
Returned JSON intentionally includes the evidence-derived entities the caller
requested; handle that output according to your local evidence policy.

Metadata records the requested model, endpoint, generation configuration, limits,
prompt/configuration/contract versions and call counts. Runtime binary version,
and model digest are not automatically captured; record these alongside real
evaluation runs. Keep personal system specifications out of shared artifacts.
The fake mode is deterministic. Local LLM runs may differ.

The optional synthetic validation runner captures runtime version, installed model
digest, source hashes, actual assistant JSON, provider-call receipts, results and
deterministic development checks:

```powershell
python -m m3.validate_synthetic --mode ollama --model qwen3:8b --endpoint http://127.0.0.1:11435 --num-ctx 8192 --think off --output-dir .m3-runtime/reproduction
```

Use a new/empty output directory. This runner only uses packaged synthetic events;
it is not a production logger, a model-performance benchmark, or M6 verification.
It exits nonzero if a development check fails. The recorded Qwen run includes a
failed exact tool-selection exercise; do not present its suite as entirely green.
The normal scenario findings still passed all factual checks. Unprompted runs
returned null interpretations; a separate directed exercise produced a qualified
interpretation. Native Ollama function-calling is not claimed: approved actions
are emitted through M3's structured JSON action protocol and dispatched by Python.

Focused integration handoffs and ready-to-send messages are available for
[M2](../docs/M3_TO_M2_HANDOFF.md) and [M5](../docs/M3_TO_M5_HANDOFF.md).
Run the reusable M2 contract suite with
`python -m pytest -q m3/tests/test_provider_contract.py`, and the programmatic M5
example with `python -m m3.examples.invoke_m3` (add `--ollama` for a configured
local model). M2/M5 delivery and final shared-contract agreement remain pending.

## Fixtures and tests

All fixtures are invented, with documentation-reserved source addresses and
synthetic source references. They contain no expected explanation, stage or
classification fields. Fixture scenarios are development examples, not M1 cases.

| Requested case | Synthetic coverage |
| --- | --- |
| A | SYN-A: three failures followed by success; one unsupported Security event is filtered out |
| B | SYN-B: ordinary successful logons; separate test treats a failure/success sequence as a benign lookalike |
| C | SYN-C: failures without success |
| D | SYN-D: distinct accounts, hosts, source addresses, logon types and workstations |
| E | SYN-E: deliberately absent, empty query |
| F | SYN-F: missing, empty, conflicting and malformed optional fields |
| G | Tests request nonexistent SYN-A-SEC-999 and SYN-G-SEC-999; no fabricated event is stored |
| H | SYN-H1 and SYN-H2 share original record ID 42 |
| I | SYN-I: reverse record-ID order with timestamps 100ns apart |

`m3/tests` covers these cases, structured output, deterministic ordering,
read-only copies, provider consistency, arbitrary-tool rejection, untrusted log
data boundaries, invalid model responses, timeouts, HTTP failures and budgets.
`tests/test_contribution_checks.py` covers contribution rules and commit pagination.
The optional `ollama` test is skipped unless explicitly enabled. No default test
uses a real model, public EVTX files, private directories or hidden expected outcomes.

To support new authentication event types, extend the permitted ID set and
deterministic observation mapping with tests. M2 owns raw-event conversion;
M3 does not add a parallel EVTX parser. Sysmon analysis, baseline detection,
cross-source reconstruction, evaluation scoring, dashboards and response actions
are outside this implementation.
