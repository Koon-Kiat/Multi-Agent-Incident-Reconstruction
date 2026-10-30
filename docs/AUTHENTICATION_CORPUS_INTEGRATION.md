# Authentication corpus integration and validation

> **Historical report (2026-09-23).** Versions, results, limitations and
> reproduction commands below describe that recorded revision, not the current
> checkout. See the [documentation index](README.md) for maintained guides.
> Saved measurements remain evidence of the original run; they are not current
> evaluation results or independent human approval.

This is the historical PR #9 integration report. PR #9 was merged on 2026-09-23.
The subsequent Authentication Investigation Agent investigation is documented in the
[autonomous follow-up report](AUTHENTICATION_AUTONOMY.md).

Updated 2026-09-23 on `codex/authentication-corpus-integration`, continuing PR #9.
PR #10 was already integrated before this work. The branch contained main
`9dfe89c` through merge `d9d9a63`; the starting feature commit was `4f249ed`.
The initial working tree was clean, origin was fetched, and PR #9 had no newer
commits or review comments. Its owner had marked it ready for review; that state
is preserved. Main is not modified and PR #9 is not merged.

The agent now executes trusted required retrieval explicitly and retains a
separate model-controlled optional tool loop. Deterministic enforcement and
factual checks pass. **Useful autonomous follow-up retrieval was not demonstrated
by the installed Qwen3 model:** it finished all 16 ordinary runs without selecting
an optional tool. Required host operations must not be counted as model autonomy.

## Reproduced problems and classification

Before changing production code, fresh local runs reproduced **8/11 corpus**
and **15/16 synthetic** checks, rather than assuming the historical 7/11.
See [corpus baseline](validation/authentication-agent-2026-09-23/baseline-corpus/manifest.json)
and [synthetic baseline](validation/authentication-agent-2026-09-23/baseline-synthetic/manifest.json).

| Observation | Classification and evidence | Treatment |
| --- | --- | --- |
| Requested absent `S02-SEC-999999999`, model selected `S02-SEC-43571` | Test-only prescribed plan plus model/context limitation. The old production API could not declare this requirement. | Trusted typed requirements now preserve and dispatch the exact ID; the directed model test is retained unchanged. |
| Success-only query and account history skipped | Prescribed-plan failures; optional retrieval would add no records after the full initial S02 query. Finishing is valid in an ordinary investigation. | Keep optional finishing valid; required filters/history use the trusted interface. |
| Historical directed budget exercise finished early | Not reproduced in the fresh baseline: its extra lookup was rejected at the configured limit. It recurred in the final directed run. | Independent deterministic tests enforce the budget; directed expectations remain unchanged. |
| Empty-window initial query repeated once | Model redundancy combined with a loop defect: no operation history or duplicate suppression. | Return cached exact-operation results and charge attempts to the shared budget. |
| Malformed/absent cross-scenario lookup could reach provider | Dispatcher validation gap, independently of provider not-found behavior. | Reject malformed IDs and scenario mismatch before provider access. |
| Provider timeout labeled model timeout | Error-attribution defect. | Separate sanitized provider timeout/connection/failure codes. |

The old context contained observations and only the last result's IDs, without
the arguments or earlier operation history. Its default-finish instruction also
discouraged optional exploration. Required retrieval is an application contract
gap when callers actually need a specific follow-up, rather than proof that every
skipped optional query is an agent error. No directed test expectations were
changed to declare these model choices successful.

## Implementation and factual boundaries

- `investigate(request, provider, llm, limits, *, required_operations=None)`
  preserves existing positional callers. `RequiredOperations` is a typed,
  at-most-99 list using the existing tool argument models. The initial query
  remains mandatory. Requirements execute through `AuthenticationTools` before
  inference; evidence and model text cannot create mandatory operations.
- Required and optional operations share original scope, event type, argument,
  query-size and tool-attempt limits. Receipts retain exact arguments and IDs,
  origin, returned/new evidence, truncation, failure and cache reuse. An absent
  lookup is `no_evidence`, not a provider failure. Later omitted requirements
  are explicitly `not_run` after a failure; failed investigations return no findings.
- Equivalent successful queries/lookups execute once per immutable invocation
  snapshot. Duplicates still consume budget. Changed windows, account/host/event
  filters and limits remain available. Final consistency reads are separate and
  cannot be mistaken for model-selected exploration.
- Each model turn contains history and authentication details grouped with their
  computed observations. The model chooses tools, reviews returned evidence and
  chooses whether to finish or interpret. There is no scenario-specific plan,
  minimum query count, hidden evidence or injected ordinary follow-up request.
- Python remains authoritative for counts, exact IDs, timestamps, entities,
  cohorts and references. A grounded decoder schema permits only actual
  observation/evidence pairs for annotations, while retaining every approved
  tool and interpretation choice. Independent host checks still reject invalid
  references, including replies from adapters that ignore the schema.

Early richer-context experiments exposed a new citation-copying regression:
Qwen merged separate cohorts' IDs or used event IDs as observation IDs. Prompt
clarification alone did not resolve every case. Recorded ordinary/required
experiment totals were v5 **9/23**, v6 **17/23**, v7 **18/23**; those failures remain
in their original folders. V8's grounded annotation choices resolved the
regression in the recorded runs without rewriting replies or weakening checks.
No tool choice, missing-ID request or interpretation is pinned to an expected answer.
Current versions are `authentication-prompt-v8`, `authentication-config-v3`,
and `authentication-result-v2`.

V2 adds `metadata.operations` and `metadata.evidence_readbacks` to existing
finding/status/request fields. The current parser reads old v1 recordings;
consumers with a strict old schema must update. The provider API is unchanged.

## Final automated verification

| Check | Actual result |
| --- | --- |
| Full repository suite with real EVTX | **774 passed, 3 skipped** |
| Authentication unit/regression suite | **162 passed, 1 skipped** |
| Actual corpus integration tests | **30 passed** |
| Original reusable provider contract against actual adapter | **12 passed** |
| Original explicit contract plus constructor ownership regression | **13 passed** |
| Fake corpus / synthetic historical matrices | **11/11 / 16/16** |
| Fake ordinary and required-operation matrix | **23/23** |
| Explicit real local Ollama smoke | **1 passed, 776 deselected** |
| Fresh wheel, isolated import and required missing lookup | Completed; 7 S02 findings, explicit no-evidence receipt, descriptive packages only |
| Dependency consistency | `pip check` passed |

Full-suite skips are the opt-in live smoke and two Windows symlink cases.
The smoke ran separately. Normal tests require no model server.
New tests cover exact missing IDs, required filtered/history operations,
pre-inference execution, optional continuation and review, duplicates, distinct
queries, shared budgets, scope/type/schema rejection, provider failures and
independent rejection of invalid references. Real 4634/4688 rejection is tested
through both required and model tool paths. No assertion was removed or marked xfail.

Logs: [full](validation/authentication-agent-2026-09-23/full-suite-v8.txt),
[authentication](validation/authentication-agent-2026-09-23/authentication-tests-v8.txt),
[corpus](validation/authentication-agent-2026-09-23/real-corpus-tests-v8.txt),
[provider contract](validation/authentication-agent-2026-09-23/provider-contract-v8.txt),
[ownership diagnostic](validation/authentication-agent-2026-09-23/original-diagnostic-v8.txt),
[smoke](validation/authentication-agent-2026-09-23/live-smoke-v8.txt),
[wheel](validation/authentication-agent-2026-09-23/package-verification-v8.json).

## Real local model results: three separate categories

Final preflight recorded **Ollama 0.34.3 / qwen3:8b**,
digest `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`.
Every final run used loopback inference, context 8192, thinking disabled,
temperature 0 and seed 0. No model download or cloud inference occurred.
Personal hardware specifications are absent from saved reports and runtime data.

| Category | Result | What it establishes |
| --- | --- | --- |
| A. Ordinary investigations, eight cases repeated twice | **16/16** completed and factually checked; **zero optional tool selections** | Sufficient/empty/missing-context/truncated handling and bounded findings; no demonstrated autonomous retrieval |
| B. Trusted required operations | **7/7 checks**: six complete investigations with Qwen plus one expected budget rejection before inference | Exact required execution, missing/filter/history/combined/duplicate handling and deterministic budget enforcement |
| C. Retained historical corpus matrix | **7/11**; exit 1 | Prescribed-plan limitations remain; ordinary findings still pass factual readback |
| C. Retained historical synthetic matrix | **15/16**; exit 1 | Success-only query still selects a different approved tool |

Category A contains S01, S02, S03, an empty real window, the existing two-record
S02 coverage case, sufficient synthetic evidence, missing/conflicting synthetic
context and the existing two-record synthetic coverage case. Every case is
repeated with the same configured runtime. Initial evidence, actual messages,
decoder schema, replies, optional actions, provider receipts and final findings
are saved in [the ordinary/required recordings](validation/authentication-agent-2026-09-23/ollama-investigations-v8/manifest.json).

The full initial real windows contain all permitted authentication records, so a
repeat query cannot add evidence. In the bounded cases, narrower event/account
queries could retrieve additional records under the same cap; Qwen did not choose
them. Truncation remained explicit. Missing-context cases retained uncertainty.
These exercises expose an opportunity for optional retrieval without hiding data
or forcing tools. Controlled adapter tests prove the loop can select a distinct
query, receive new evidence and review it on the next turn. Those tests are not
evidence of Qwen's autonomous capability.

Category B's exact-missing receipt records `S02-SEC-999999999` as absent without
substitution. Required success filtering and exact account history execute even
though category C shows Qwen sometimes omits them. Duplicate required calls reuse
their first result. The one-slot budget case fails before inference, with one
rejected and one not-run follow-up; it is not counted as a successful model decision.

In the [final corpus matrix](validation/authentication-agent-2026-09-23/directed-corpus-v8/manifest.json),
the model substitutes `S02-SEC-43503` for the missing ID, finishes without the
success-only query or history, and finishes within the directed one-slot budget
exercise. This last result fails the prescribed exercise, not budget enforcement.
The [final synthetic matrix](validation/authentication-agent-2026-09-23/directed-synthetic-v8/manifest.json)
still fails the success-only directed query. Its other checks pass.
The retained matrices include ordinary and interpretation cases alongside directed
tool exercises; their totals are not pure autonomy scores.

No redundant query was selected in the final ordinary runs. One fixed-runtime
repeat set does not establish general reliability. All completed final results
passed factual readback, including directed cases whose plan checks failed.
No detection-accuracy, compromise, common-actor or independent-verification claim
follows from those checks.

## Inherited fixes and real evidence integrity

PR #10 resolved the provider and EventStore defects. This session does not
reimplement or claim those fixes. Exact lookup preserves any supported Security
record, including 4634/4688; query remains limited to 4624/4625. Sysmon and
unknown/malformed provider IDs return None. Agent tools reject unsupported
records before findings. Constructor inputs and returned records remain detached.

The processing package, original generic provider suite and original datasets
are unchanged from the starting feature commit. This preserves PR #10's protected
paths, manifest/schema validation, detection output safety, scoring/revision
validation, error handling and R-EXEC-02 version 2. Their tests pass in the full suite.
The earlier [PR #10 integration readback](validation/authentication-pr10-2026-09-23/integration-readback.json)
retains the merge's corpus/detection parity evidence.

The digest-verified corpus contains **6,661 records**: S01 2,700, S02 1,930,
S03 2,031. All six original EVTX files still match their LFS hashes.

| Scenario | UTC window, start inclusive / end exclusive | Findings | Failed / successful logons |
| --- | --- | ---: | ---: |
| S01 | 2022-08-31T17:46:00Z to 2022-08-31T17:49:00Z | 6 | 0 / 6 |
| S02 | 2026-09-21T02:04:30Z to 2026-09-21T02:06:00Z | 7 | 5 / 7 |
| S03 | 2026-09-21T02:24:50Z to 2026-09-21T02:26:00Z | 7 | 2 / 7 |

IDs, seven-digit timestamps, one-tick boundaries and scenario collisions remain
tested. Only public telemetry and neutral synthetic fixtures were used. No private
answer key, ground truth or runbook was accessed or used to plan retrieval.

[Final readback](validation/authentication-agent-2026-09-23/final-readback.json)
checks every new run's artifact hashes, completed findings against provider
receipts and unchanged records, failed empty envelopes, final-v8 source hashes,
corpus digest and original LFS objects. Earlier source hashes describe their
recorded versions, not the final tree. Recordings from prior PR #10 work remain
untouched. Source hashes include the local file bytes and line endings.

## Handoff and remaining limitations

The [handoff](ORCHESTRATOR_HANDOFF.md) and runnable
[corpus example](../authentication_agent/examples/investigate_required_corpus.py)
cover optional requirements, local configuration, receipt consumption, missing
evidence, incomplete coverage and failure handling. Existing calls with no plan
remain valid. Descriptive packages and `CorpusAuthenticationProvider` remain intact.

Within the authentication agent, reliable spontaneous useful retrieval and
prescribed-plan following remain model limitations. No bypass, relaxed assertion,
automatic response repair or alternate downloaded model is used to conceal them.
Mandatory retrieval is reliable through the trusted interface, while optional
retrieval remains model-controlled. Treat `completed` as bounded factual
completion, never a certificate of autonomy or complete investigation coverage.

The actual orchestrator is not implemented or connected. Its owner retains
dispatch, cross-agent correlation, whole-run deadlines/cancellation and final
reconstruction; endpoint analysis and independent evaluation remain separate.
The updated result metadata is the only downstream output-contract addition.

## Reproduce

Use new output directories; the runners refuse to overwrite prior recordings.

```powershell
python -m pytest -q --basetemp .test-tmp-reproduce
python -m pytest -q event_processing/tests/test_authentication_provider_contract.py::TestCorpusAuthenticationProviderContract
python -m pytest -q authentication_agent/testing/check_processing_contract.py
python -m pytest -q tests/test_authentication_corpus.py --basetemp .test-tmp-corpus-reproduce
python -m authentication_agent.validate_investigations --corpus out/corpus --mode ollama --output-dir out/validation/ordinary-required
python -m authentication_agent.validate_corpus --corpus out/corpus --mode ollama --model qwen3:8b --output-dir out/validation/directed-corpus
python -m authentication_agent.validate_synthetic --mode ollama --model qwen3:8b --num-ctx 8192 --think off --output-dir out/validation/directed-synthetic
python docs/validation/authentication-agent-2026-09-23/verify_recordings.py
python -m pip check
```

The two retained model matrices currently exit 1. Inspect their exact
`check_errors`; required-operation success does not turn those failures into passes.
