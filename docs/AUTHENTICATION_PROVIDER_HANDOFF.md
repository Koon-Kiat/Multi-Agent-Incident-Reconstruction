# Event Processing & Detection Engine integration handoff

PR #8 delivered the corpus, `EventStore` and `CorpusAuthenticationProvider`. The
Authentication Investigation Agent now consumes that adapter through the existing
`investigate()` logic. `python -m authentication_agent.investigate_corpus` loads the existing corpus;
no parser, normaliser, store or adapter is duplicated.

## Tested boundary

Supply `CorpusAuthenticationProvider(EventStore.load(corpus_path), limits)` to
`investigate(request, provider, llm, limits)`. Use the same `Limits` on both sides.

| Property | Observed behavior |
| --- | --- |
| Scope | Security 4624 and 4625 only |
| Lookup | Exact scenario-scoped ID; `None` for missing, malformed or non-authentication ID |
| Time | Original seven-digit UTC timestamp; `[start,end)`; integer 100ns ordering |
| Filters | Exact scenario/account/host/type; non-null `user` else string `TargetUserName` |
| Missing fields | Null and empty remain distinct; no invented entity values |
| Bounds | Excessive requests rejected; count limits return explicit truncation |
| References | Original record ID and raw reference retained; final exact readback |
| Read-only | Returned adapter records are detached; corpus-file changes rejected by digest verification |

Public S01–S03 tests verify counts against actual records, entity fields,
ordering, a one-tick window, scenario collisions, truncation, empty results,
fabricated-reference rejection and structured findings. No answer keys are used.

## Unresolved compatibility diagnostic

The unchanged twelve-check generic contract reports **11 passed, 1 failed**.
`test_exact_lookup_preserves_every_original_field` includes `SYN-A-SEC-99`,
Security event 4634. The in-memory provider returns it; the processing adapter
intentionally returns `None`, as documented in PR #8. This is a scope disagreement,
not missing authentication query functionality. Both exclude non-logon evidence
at the agent tool boundary.

The generic fixtures also use nested/non-string `event_data` and noncanonical
timestamps, outside the EVTX schema. The diagnostic uses explicitly unchecked
**test-only** records to reach the actual `EventStore`/`CorpusAuthenticationProvider`
with unchanged assertions. It is an adapter probe, not proof those fixtures are
ingestible. Supported-schema and real-corpus tests use validated records.
No production validation is bypassed.

Proposed agreement: make exact authentication-provider lookup explicitly
authentication-only in the generic contract. If the team wants broader lookup,
agree the adapter change first. Neither behavior nor assertions changed here:

```powershell
python -m pytest -q authentication_agent/testing/check_processing_contract.py::TestProcessingProviderContract --tb=short
```

## Constructor snapshot issue

A separate supported-schema regression shows `EventStore([event])` retains the
caller's mutable `event_data` dictionary. Mutating that original dictionary
after construction changes subsequent lookup results. This concerns the Event
Processing & Detection Engine's constructor ownership, not returned adapter
copies. The new integration uses `EventStore.load()`, whose parsed input objects
are not exposed to its caller.

```powershell
python -m pytest -q authentication_agent/testing/check_processing_contract.py::test_constructor_snapshot_detaches_supported_input --tb=short
```

Smallest proposed fix: detach records (at least copy `event_data`) at construction,
before indexing. The focused regression expects the original value and currently
fails. It remains outside default test discovery with the compatibility diagnostic;
no assertion was relaxed or marked expected-failure. Component-owner agreement
is needed before changing the implementation; the constructor behavior was not changed. The separate naming migration is
documented in [the naming guide](COMPONENT_NAMING.md).

Baseline precision/recall/F1 and evaluation-definition agreements are separate.
The authentication query interface is delivered and exercised.
