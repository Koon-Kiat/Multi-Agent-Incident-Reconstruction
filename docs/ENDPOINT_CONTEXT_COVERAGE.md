# Endpoint context and evidence coverage correction

> **Historical report (2026-10-18).** Versions, results, limitations and
> reproduction commands below describe that recorded revision, not the current
> checkout. See the [documentation index](README.md) for maintained guides.
> Saved measurements remain evidence of the original run; they are not current
> evaluation results or independent human approval.

The endpoint context limitation was correct on latest `main`, commit
`e6a5ac4c2f8ac2c1b3fe1749fde7213b901a3d5d`, fetched on 2026-10-18.
Both reported windows can be investigated without dropping supported evidence.
The correction stays inside the Endpoint Investigation Agent: bounded model
batches, bounded recovery queries, coverage receipts, tests and endpoint-related
documentation. Authentication, detection, shared normalization/query code,
orchestration, reconstruction, verification, datasets and scoring are unchanged.

The role boundary follows `MAIR_Six_Member_Roles_and_Boundaries.pdf`, pp. 2, 6
and 9, and `SecurityAnalytics_Proposal.docx`, sections 3.1–3.2: the Endpoint Investigation Agent investigates
recorded Sysmon evidence with read-only tools and separates facts from uncertain
interpretations. Cross-source timelines and independent verification remain
downstream responsibilities. Neither reference document is a runtime input.

## Reproduction and actual impact

The original orchestrator was run over the verified public S01–S03 corpus with
its existing default routing, limits, split depth of three and deterministic
fake models. These runs are plumbing/coverage checks, never scored experiments.

| Original unresolved task | Authorized half-open UTC window | Original context bytes | Supported records |
| --- | --- | ---: | ---: |
| `S02-endpoint-03.1.2.1` | `2026-09-21T02:07:26.6017385Z` to `2026-09-21T02:07:35.2471628Z` | 271,013 | 125 |
| `S03-endpoint-03.1.2.2` | `2026-09-21T02:26:50.1893142Z` to `2026-09-21T02:26:56.3601178Z` | 269,740 | 117 |

Each initial query returned only 100 records. Findings, a per-finding grounded
annotation schema and the complete operation history together exceeded the
262,144-byte guard. Both investigations failed before inference and returned no
findings. A byte guard alone also did not protect the 8192-token local profile.

The historical statement that neighbouring windows covered the detections was
insufficient as an evidence-coverage claim. Exact ID comparison found **none** of
the 125 S02 records or 117 S03 records in other completed baseline endpoint
tasks. Detection coverage therefore concealed missing endpoint observations,
process relationships and possible downstream context. These were unresolved
investigations, not evidence of clean activity. Historical outputs are preserved;
new code does not retroactively repair or rescore them.

## Correction

Process facts and GUID relationships are built over the entire retrieved union.
The model then receives consecutive batches, with a schema grounded only to the
current batch. Every observation must pass through review before completion;
every source reference still receives final exact-ID readback. Model follow-ups
rebuild the global snapshot and restart review, discarding earlier annotations
that could now reference changed or invalidated links. A later batch failure
still returns a typed failure with no partial findings.

No command line, path, GUID, identity, evidence ID or timestamp is clipped or
sampled. Presentation omits unavailable nulls, carries common scope/uncertainty
once and summarizes the latest operation. Full findings and all operation
receipts remain in the result. `context_batches` records attempted calls,
snapshot revisions, observation/evidence IDs and context bounds.

Both serialized messages/schema and available model context constrain each
batch. With `num_ctx`, the shared Qwen byte-level tokenizer receives a
conservative UTF-8 byte upper bound plus 256 tokens for the chat template, and
`max_output_tokens` is reserved separately. The installed model reports GPT-2
tokenization with the `qwen2` pre-tokenizer. Custom adapters without `num_ctx`
retain only the byte guard; a different tokenizer/template needs its own bound.

Making a capped root window succeed would otherwise bypass the orchestrator's
time splitting and reduce retrieved evidence. The endpoint therefore attempts
ordinary overlapping tail queries after mandatory seed lookups, within the
existing query/window/tool budgets. A cursor uses the last query page, not a late
seed, and includes its final timestamp so ties cannot be skipped. Recovery can
advance through pages already retrieved as seeds. It stops on exhausted budget
or no cursor progress. No shared query API or provider implementation changes.

`window_total_matched` records the initial full-window count.
`window_coverage_complete` requires that exact number of distinct in-scope
records. Incomplete-inventory warnings and result-level `truncated` clear only
then. Individual query truncation flags remain in their original receipts.
The request/finding envelope stays `endpoint-result-v1`; optional metadata has
historical defaults. `coverage` is an additional operation origin. The existing
consumer models and finish-guard opt-out remain compatible.

## Coverage validation

All nine original endpoint root windows completed with the existing retrieval
budgets and the simulated shared 8192-context profile, without time splitting.
Every supported record in each window was retrieved, reviewed and read back.

| Scenario | Root windows | Supported records by window | Baseline successful distinct IDs | New distinct IDs | Baseline IDs lost |
| --- | ---: | --- | ---: | ---: | ---: |
| S01 | 2 | 509, 148 | 203 | 657 | 0 |
| S02 | 3 | 23, 392, 366 | 408 | 781 | 0 |
| S03 | 4 | 109, 420, 368, 21 | 337 | 918 | 0 |

The comparison uses exact evidence-ID sets, not detection counts. Findings
retain all source facts, relationships, full-resolution timestamps and citations.
The two formerly failing windows additionally have dedicated 8192-profile
regressions checking all 125/117 records. Synthetic regressions cover dense time
ties, links across batches, many seeds, stale/cross-batch annotations, late
failure, immutable readbacks, irreducible context size and recovery gaps.

Measured source counts, ID digests, budgets and model-call bounds are retained in
[coverage-summary.json](validation/endpoint-context-2026-10-18/coverage-summary.json)
and [failing-windows.json](validation/endpoint-context-2026-10-18/failing-windows.json).
The corpus manifest SHA-256 is
`34c5d0ac01e5a6028cbc2a6deb39197a179007be549971119f83e6000f9069c7`.
No private answer key or runbook was loaded.

Both formerly failing windows also completed with installed local `qwen3:8b`,
Ollama 0.34.4, context 8192, thinking disabled, temperature/seed zero. Model digest:
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`.

| Live window | Findings / expected records | Exact readbacks | Model calls | Highest actual prompt tokens | Wall time |
| --- | ---: | ---: | ---: | ---: | ---: |
| S02 | 125 / 125 | 125 | 61 | 2,227 | 481.718 s |
| S03 | 117 / 117 | 117 | 59 | 2,215 | 410.021 s |

Neither run retained truncation. Every final-revision observation was presented,
every citation resolved, and all measured prompts plus the reserved 2048 output
tokens fit the 8192 context. The final standalone CLI live smoke test also passed.
[live-summary.json](validation/endpoint-context-2026-10-18/live-summary.json)
retains per-request token measurements and configuration. Final regression and
boundary-check outcomes are in
[checks.json](validation/endpoint-context-2026-10-18/checks.json).
The final full regression run passed **1,161 tests, with 7 skips**. Two boundary
tests added after collection passed in the separate endpoint rerun (25 passed,
1 optional skip); the explicit final-code live CLI test passed separately.
The complete current collection also passed without original EVTX, matching CI's
`lfs: false` checkout: **1,093 passed, 77 skipped**. Dependency and contribution
policy checks passed before PR submission.

These establish operational context handling and evidence coverage, not
classification accuracy, reconstruction accuracy or independent claim support.
Full generated findings and server logs remain under ignored
`out/endpoint-context-validation/`.

## Remaining limits and practical impact

- A page filled by one timestamp can prevent progress through a timestamp-only
  query API. The agent retains the gap instead of advancing one tick and silently
  dropping tied records. An appropriately authorized larger event cap can help;
  unrestricted same-timestamp pagination would require a shared API extension.
- Exhausted tool budgets still leave explicit incomplete retrieval. Exact missing
  seeds and unsupported Sysmon types remain outside any completeness claim.
  Inventory completeness is for supported Sysmon 1/10/11/13 inside the caller's
  original window, not the entire incident or raw corpus.
  Recovery uses slots otherwise available to model-selected follow-ups; complete
  recovery already includes all supported in-window records those tools could add.
- One observation plus fixed instructions/schema may still exceed the configured
  context. It fails closed without clipping source fields or returning partial
  findings. Parents outside the authorized window remain unavailable.
- Batches preserve observed evidence and globally corroborated links, but do not
  give a model simultaneous free-form reasoning across every record. Tentative
  per-observation annotations retain the original endpoint role limits.
- More model calls increase latency. The live S02 window took about eight minutes.
  The largest simulated root required 225 model calls: larger live root windows
  may exceed the orchestrator's existing 900-second task deadline. Full live
  end-to-end execution of all nine roots was not measured. Callers must retain
  timeout outcomes; deadline policy belongs to the Incident Reconstruction
  Orchestrator and is unchanged.
  Per-request timeout, cold loading, provider/model failures and total run
  cancellation retain their existing limitations.

## Reproduce

Use the repository's Python environment and original public Git LFS telemetry:

```powershell
python -m event_processing normalise --datasets datasets --out out/corpus
python -m pytest -q endpoint_agent/tests tests/test_endpoint_corpus.py --basetemp .test-tmp-endpoint-context
python -m pytest -q --basetemp .test-tmp-endpoint-regression
```

With the already installed local `qwen3:8b`, the previously failing windows can
be invoked directly without changing the common model or retrieval cap:

```powershell
python -m endpoint_agent --corpus out/corpus --scenario S02 --start 2026-09-21T02:07:26.6017385Z --end 2026-09-21T02:07:35.2471628Z --mode ollama --num-ctx 8192 --timeout 180
python -m endpoint_agent --corpus out/corpus --scenario S03 --start 2026-09-21T02:26:50.1893142Z --end 2026-09-21T02:26:56.3601178Z --mode ollama --num-ctx 8192 --timeout 180
```

The integration measurement uses the orchestrator's existing optional
`FinishGuard`, preserving the production caller behavior. Its per-request timeout
is 180 seconds for explicit live validation; production defaults remain unchanged.
