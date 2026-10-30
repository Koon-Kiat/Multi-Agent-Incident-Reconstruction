# Endpoint investigation handoff

The endpoint module consumes the unchanged `security-event-v1` corpus and exposes
an additive `endpoint-result-v1` result contract. The common finding envelope
matches authentication findings; `observed_events` and `entities` carry distinct
endpoint types. Consumers should dispatch on `agent_type` and use the appropriate
typed result model. The authentication-only `Finding` class cannot deserialize
endpoint payloads. No existing authentication or normalized-event fields change.
The orchestrator consumes this callable boundary; the verifier later reads reconstructed claims
and source records independently.
The [2026-10-18 context correction](ENDPOINT_CONTEXT_COVERAGE.md) changes only
endpoint internals and adds optional endpoint metadata with historical defaults;
the request, provider API and finding envelope are unchanged.

## Ordinary invocation

```python
from endpoint_agent import InvestigationRequest, investigate
from endpoint_agent.config import Limits, OllamaConfig
from endpoint_agent.investigate_corpus import local_model_runtime
from endpoint_agent.llm import OllamaClient
from endpoint_agent.llm.fake import FakeLLM
from event_processing.adapters.endpoint_provider import CorpusEndpointProvider
from event_processing.query import EventStore

limits = Limits()
store = EventStore.load("out/corpus")
provider = CorpusEndpointProvider(store, limits)
request = InvestigationRequest(
    scenario_id="S02",
    start_utc="2026-09-21T02:04:30Z",
    end_utc="2026-09-21T02:06:30Z",
)
result = investigate(request, provider, FakeLLM(), limits)
payload = result.model_dump(mode="json")

# For installed local weights, preflight before sending any evidence:
config = OllamaConfig(model="qwen3:8b", num_ctx=8192, think=False,
                      temperature=0.0, seed=0)
# runtime = local_model_runtime(config)
# result = investigate(request, provider, OllamaClient(config), limits)
```

Pass the same limits to provider and agent. Programmatic callers should preserve
the runtime metadata returned by preflight alongside run results; the CLI adds
it to result metadata automatically. Async callers use
`await asyncio.to_thread(investigate, request, provider, llm, limits)`.

## Detection triggers and time bounds

The caller owns routing. A supported Sysmon trigger can be supplied through
`seed_evidence_ids`; it will receive an exact lookup even if absent from the
initial capped window. Inspect the source record's channel and event type before
routing mixed-channel rule output. Endpoint tools admit Sysmon 1/10/11/13 only.

Detection windows are closed, while query windows are `[start,end)`. An exact
conversion is:

```python
from event_processing.timeutil import iso_to_ticks, ticks_to_iso

# `detection` is a Detection supplied by the existing detection engine.
# `sysmon_trigger_ids` contains its caller-validated supported Sysmon references.
# request = InvestigationRequest(
#     scenario_id=detection.scenario_id,
#     start_utc=detection.window_start_utc,
#     end_utc=ticks_to_iso(iso_to_ticks(detection.window_end_utc) + 1),
#     seed_evidence_ids=tuple(sysmon_trigger_ids),
# )
```

For a single-event detection this produces a one-tick window. The orchestrator
may authorize a larger bounded context window before invocation to retrieve
parent/child evidence. The model cannot expand the window itself. Never interpret
a missing parent as proof that a parent did not exist.

## Provider contract

`endpoint_agent.queries.interface.EndpointEventProvider` defines:

- `query(QueryRequest) -> QueryResult`, returning ordered, detached
  `NormalisedEvent` records with truthful `total_matched` and `truncated` fields.
- `get_event(evidence_id) -> NormalisedEvent | None`, preserving any exact Sysmon
  record. Missing/malformed IDs and Security records return `None`; the tool layer
  rejects unsupported Sysmon types, cross-scenario references and outside-window
  records before they can become findings.

`event_processing.adapters.endpoint_provider.CorpusEndpointProvider` implements
the protocol through public `EventStore` methods. It adds no parser, storage or
event-ID format. Queries use `EventStore.query(event_data_filters=...)`, not
`scenario_events()`. The adapter translates process-field names into declarative
per-event-type equality filters; it has no private store access or custom index.
All endpoint predicates apply inside the store before the result cap **and before
deep-copying records**, respecting both provider and store bounds. Only returned
records are detached, retaining their full fields including `raw_xml`; caller
mutation cannot change the corpus. This is needed because the existing
`process_by_guid` and `children_of` helpers search a whole scenario, and filtering
their already-truncated output can lose matching in-window records.

The existing sorted snapshot provides deterministic timestamp/evidence-ID order.
The store bisects the authorized half-open time window, counts every matching
record for exact `total_matched`, retains at most `limit` records, and reports
`truncated` exactly when the total exceeds the returned count. Empty or unknown
scenarios yield no records, zero matches and no truncation. Counting still scans
the window, but neither all scenario events nor all matches are materialized or
deep-copied for each follow-up query. The agent's separate `matches()` boundary
check remains in place to validate returned records independently.

`QueryRequest` contains `scenario_id`, `start_utc`, `end_utc`, `event_ids`,
`account`, `host`, `process_guid`, `parent_process_guid` and `limit`. Filters
combine with AND, preserve case/domain strings, and distinguish `None` from `""`.
`process_guid` matches `SourceProcessGUID` for event 10 and `ProcessGuid` for other
supported types. `parent_process_guid` selects only matching process-creation
records. The account filter uses normalized `user` exactly as stored.

The agent exposes these through five typed tools. A query and each exact seed
run before model decisions. Bounded recovery queries then reuse the same query
API with overlapping tail windows. Their cursor comes from the last query page,
never a potentially later exact seed; equal-timestamp events remain eligible.
Recovery stops on no progress or exhausted budget. A GUID tool requires a
host/GUID pair already seen in retrieved events. Receipts identify `initial`,
`seed`, `coverage` and `model`
origins, exact arguments, returned/new IDs, truncation, snapshot reuse and failures.
Later seeds are marked `not_run` if an earlier required operation fails.
Final readbacks are counted separately from investigative tool calls.

## Consumption rules

Completed findings contain observations of supported source records and optional
qualified interpretations. `metadata.window_total_matched` is the initial whole
window's count; `window_coverage_complete` requires exactly that many distinct
retrieved records. Until then, `metadata.truncated` and finding-level incomplete
inventory uncertainty must survive reconstruction and reporting. Once the whole
inventory is recovered these warnings clear, while original query truncation
flags remain unchanged in operation receipts. An empty completed result is distinct
from a failed result. Failures carry sanitized error codes and no partial findings.

Each finding describes an anchor event in `observed_events.evidence_id`; its
`evidence_ids` also includes any corroborating creation record. References are
ordered by `(timestamp_ticks,evidence_id)`. Finding timestamps span the cited
records; the anchor's own timestamp is retained inside `observed_events`.
An event may corroborate multiple findings, so the number of findings is not a
count of distinct incidents. Reconstruct chains from typed relationships, keeping
every relationship's source and target citation.

`entities.account` is normalized `user`; `reported_account` is `User` or, for
event 10, `SourceUser`. `target_account` is event 10's `TargetUser`. Missing and
conflicting values remain explicit. Domain/case variants are not merged into a
common actor, and chronology alone does not establish authentication causation.

Independent verification owns support verdicts. This module's exact-ID readback
checks existence and stability only. The verifier can resolve every citation
through `store.lookup()` to its original `raw_reference`, `raw_xml` and source
digest without receiving the investigator's private model context.

`context_strategy: complete-evidence-batches-v1` uses globally computed findings
and consecutive model batches. `context_batches` records each attempted call's
`index`, `revision` (tool-call count), `observation_ids`, `evidence_ids`,
`context_bytes` and optional `input_token_upper_bound`. After a follow-up, earlier
annotations are discarded and all observations are reviewed again only if the
retrieved snapshot changed; unchanged retrieval preserves completed batches. A completed
result's final revision covers every returned finding. Batch failure still returns
no partial findings. Metadata defaults let the updated models read historical
`endpoint-result-v1` outputs; consumers with private strict metadata copies must
adopt the updated endpoint model. No consumer code or scoring definition changes.
