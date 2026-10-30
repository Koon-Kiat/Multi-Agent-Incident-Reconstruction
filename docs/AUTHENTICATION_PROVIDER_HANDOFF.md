# Event Processing & Detection Engine integration handoff

PR #10 resolved the provider conversion and constructor ownership issues reported
by the authentication integration. Its merged implementation is now ported into
`event_processing/`, preserving `CorpusAuthenticationProvider` and the descriptive
interfaces. These are inherited fixes, not new fixes by this integration.

## Agreed and tested boundary

Supply `CorpusAuthenticationProvider(EventStore.load(corpus_path), limits)` to
`investigate(request, provider, llm, limits)`. Use the same `Limits` on both sides.

| Property | Behavior |
| --- | --- |
| Exact lookup | Any supported Security record, including 4634 and 4688; exact original ID and fields |
| Missing lookup | `None` for unknown/malformed IDs and Sysmon records; no substitution |
| Queries | Only Security 4624/4625, as permitted by `QueryRequest` |
| Agent tools | Reject non-authentication types, other scenarios and records outside the request window before producing findings |
| Time | Original seven-digit UTC timestamp; `[start,end)`; integer 100ns ordering |
| Filters | Exact scenario/account/host/type; non-null `user` else string `TargetUserName` |
| Missing fields | Null and empty remain distinct; no invented values |
| Bounds | Excessive requests rejected; count limits report truncation |
| References | Original record ID/raw reference; final exact readback rejects missing or changed records |
| Ownership | Constructor deep-copies caller records; returned records are detached; corpus digests verified on load |

The broader `EventStore` remains available for cross-source evidence access by
other components. An authentication-provider exact lookup does not authorize an
authentication finding. The agent validates scope and event type independently.

The agent's optional `required_operations` keyword uses this same provider API;
no processing-side change is needed. New result v2 operation receipts distinguish
required retrieval from optional model choices. Within one invocation identical
operations reuse the verified snapshot, including absent lookups. Providers must
remain consistent for the invocation; final exact record readbacks still run.
Malformed or cross-scenario lookup arguments are now rejected by agent tools
before provider access. The provider's broader exact-lookup behavior is unchanged.

## Contract and ownership verification

All **12 original reusable provider-contract checks pass** against the actual
integrated adapter. PR #10 added default-discovery coverage in
`event_processing/tests/test_authentication_provider_contract.py`; the original
explicit diagnostic also passes unchanged. Its additional supported-schema
constructor regression now passes. No assertion was relaxed or marked xfail.

```powershell
python -m pytest -q event_processing/tests/test_authentication_provider_contract.py
python -m pytest -q authentication_agent/testing/check_processing_contract.py
python -m pytest -q tests/test_authentication_corpus.py
```

Generic fixtures contain nested/non-string `event_data` and noncanonical
timestamps beyond the EVTX schema. Both contract fixtures use explicitly unchecked
**test-only** records to exercise mapping with the original assertions. Production
corpus loading still validates the EVTX schema. The generic fixture is not an
example ingestion format.

Real S01–S03 tests cover counts, exact IDs, sub-microsecond ordering, a one-tick
window, collisions, filters, empty/truncated results and fabricated references.
Real 4634/4688 records are returned by exact lookup but fail at the agent's tool
boundary with `provider_scope_violation` and no findings. Constructor and returned
record isolation are covered by the original regression and inherited query tests.

See the [query API](EVENT_QUERY_API.md), [authentication manual](../authentication_agent/README.md),
[naming guide](COMPONENT_NAMING.md) and [orchestrator integration](ORCHESTRATOR_HANDOFF.md).
The pipeline consumes this provider; final evaluation remains a separate,
review-gated workflow described in [the evaluation checklist](FINAL_EVALUATION_HANDOFF.md).
