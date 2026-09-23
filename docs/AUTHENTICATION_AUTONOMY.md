# Authentication follow-up investigation

This Authentication Investigation Agent follow-up starts from merged PR #9 (`4ad96da`) on
the dedicated follow-up branch. It preserves the v2 result, provider contracts,
required operations, positional callers, and the endpoint investigation, reconstruction and independent verification boundaries. It uses only
public authentication telemetry and the existing neutral synthetic fixtures.

**Useful autonomous retrieval is demonstrated, but reliable selection remains
unresolved.** In both final ordinary synthetic coverage runs, Qwen3 selected an
unprescribed success-only query, read the new successful logon, and described the
updated failure-then-success sequence before finishing. A separate three-repeat
opportunity matrix on the same final code retrieved no useful new outcomes.
Both results are retained; the two successes are not a reliability claim.

## What the baseline establishes

Fresh validation with Ollama 0.34.3 and installed `qwen3:8b` reproduced **16/16
ordinary factual/completion checks, zero optional queries, and 7/7 trusted
required-operation checks**. The initial full-window inventories contained all
permitted authentication records. Finishing those cases was correct; repeating
their queries could not add context. The full baseline suite was **774 passed,
3 skipped**. These are fresh results, not copied claims from PR #9.

The four repeated bounded cases had a different interpretation: their initial
queries were truncated, and approved queries could retrieve additional records.
For the existing synthetic case, two initial failed logons leave the presence of
a subsequent success unresolved. In the existing S02 coverage case, two service
successes leave the presence of failed logons unresolved. The evaluator proves
availability through `AuthenticationTools`, separately from the agent run.
It does not give that witness, a desired tool, arguments, IDs, or a question to
the production model. It retains the existing two-record budget; no provider
record is removed, and the same cap governs the initial and optional queries.

## Supported contributing factors

| Area inspected | Evidence and interpretation |
| --- | --- |
| Initial retrieval | Complete unfiltered windows already contain the evidence; zero additional calls is appropriate there. |
| Context | V8 already contains computed observations, bounded event details, actual operation history, truncation, limits, and returned/new IDs. The bounded examples have genuine gaps, but the model often does not act on them. |
| Prompt and tools | V8 favors a minimal finish and has limited descriptions of query semantics. The prompt-only experiment still selected zero optional queries; wording alone did not resolve selection. |
| Decision format | An optional assessment was frequently omitted. Requiring a short assessment in the decoder made the model's decision observable and enabled a recorded useful query without prescribing its tool. This is evidence of a contributing format issue, not proof of a single root cause. |
| Schema/budget mismatch | A repeated run chose account history without `limit`. The decoder permitted omission, but the typed default of 100 exceeded the active cap of 2. The host correctly rejected it. The final decoder requires explicit query limits bounded by the active cap, and the context advertises those same schemas. No query or filter is preselected. |
| Argument semantics | Failed experiments selected account/host filters that retained the same earliest records. Several responses confused the per-query cap with a total evidence cap. A valid tool call is not necessarily a useful query. |
| Loop and results | Actual receipts and the next model message show newly retrieved events reaching the model. Controlled-adapter tests independently cover continuation, scope, budgets, exact references, and missing/truncated results. No dispatch defect prevented the demonstrated query. |
| Context/output budget | Token-count diagnostics separate capacity from selection. The experimental thinking profile also produced `done_reason=length` at 4,096 generated tokens and failed closed; a larger budget did not establish reliability. |
| Evaluation | Historical factual checks could pass without optional retrieval. The new evaluator separately measures available opportunities, model-selected calls, new/reviewed records, and qualified model annotations. |

The experiments do not isolate every causal interaction. Changes in prompt,
schema, and runtime can interact, and fixed temperature/seed did not make all
thinking-enabled repeats identical. The saved assessments are untrusted model
statements; neither they nor these development checks establish compromise.

The final implementation retains the smaller decision-summary prompt variant,
the corrected query schemas, and count-only runtime diagnostics. Extra coverage
summaries, carrying the previous assessment into each turn, and a broad prompt
rewrite did not improve selection consistently and are not shipped. Runtime
defaults remain context 8192, thinking off, temperature 0, seed 0, 2,048 output
tokens and a 60-second per-call timeout in the established validation profile.

## Demonstrated ordinary follow-up

The final ordinary recordings
[repeat 1](validation/authentication-autonomy-2026-09-24/final-v16-investigations/ordinary-synthetic_bounded-1.json)
and [repeat 2](validation/authentication-autonomy-2026-09-24/final-v16-investigations/ordinary-synthetic_bounded-2.json)
contain the actual request and two model turns. The initial mandatory query
returned `SYN-A-SEC-1` and `SYN-A-SEC-2`, both failures, with `truncated: true`.
The model independently chose:

```json
{
  "name": "query_authentication_events",
  "arguments": {
    "scenario_id": "SYN-A",
    "start_utc": "2026-01-10T00:00:00Z",
    "end_utc": "2026-01-10T00:01:00Z",
    "limit": 2,
    "event_ids": [4624]
  }
}
```

The provider returned new record `SYN-A-SEC-4`. The next model turn received its
actual event details and the updated observation, and its final assessment
explicitly described two failures followed by a success while declining to infer
compromise or a common actor. The model emitted `annotations: []`; the v2
interpretation therefore remained null. The host correctly reported two failures
and one success and retained truncation uncertainty. This is useful retrieval
and review, not a successful non-null-annotation check or complete-window inventory.

The receipt has `origin: model`, exact arguments, `provider_invoked: true`, and
`new_evidence_ids: ["SYN-A-SEC-4"]`. It is neither a trusted required operation
nor a cached/redundant query. Prompt/output counts were 2,635/142 for the decision
and 2,941/76 for review, below the configured budgets, with `done_reason: stop`.
Context/output exhaustion does not explain these ordinary decisions.
Across the full ordinary matrix, prompt evaluation reached 7,780 tokens. Those
counters do not by themselves prove that the runtime never trims long inputs;
the host byte limit is not a token-limit guarantee. The two demonstrated
follow-ups have substantially more headroom. No final standard-profile response
reported output-length exhaustion.

## Evaluation and interpretation

`python -m authentication_agent.validate_autonomy` covers sufficient evidence,
the two useful bounded opportunities, an empty window, missing/conflicting
identity fields, and an absent exact record requested through the existing trusted
interface. The missing exact lookup is explicitly a **host-required** operation,
never credited as optional model retrieval.

Every case records initial events, all model messages and response schemas,
actual assistant JSON, exact optional arguments, provider calls, returned/new
IDs, final evidence, and factual checks. Availability witnesses and expectations
appear only under `evaluation_only`, after the investigation finishes. Model
thinking text and personal hardware information are not recorded.

The strict automated behavior check requires the useful case's new outcome to
reach a later model turn and appear in a non-null, exact grounded annotation.
This deliberately separates a model annotation from facts the host would emit
automatically. It can undercount a different useful investigation or a correct
review followed by `annotations: []`; the raw recordings remain the authority
for describing those distinctions. Sufficient/empty cases need no optional call.
Repeated identical queries fail the behavior check even though the existing
cache prevents another provider query and charges the attempt to the budget.

The fake adapter intentionally does not demonstrate autonomy. Its useful-case
behavior checks fail unless a controlled test explicitly selects a tool. Such
controlled tests validate machinery only, not Qwen's investigative capability.

## Contracts and safeguards

The internal model response gains a bounded `assessment` string. Structured
decoding requests it before action; existing scripted adapter responses and old
recordings that omit it still parse. It never becomes a finding, count, evidence
reference, required operation, or downstream result field. All tool names,
arguments, budgets, and scope checks still pass through `AuthenticationTools`.
The decoder requires `limit` for query/history actions and caps it at the active
`max_events_per_query`; context and decoding use the same argument schema. The
typed provider and required-operation defaults remain unchanged. An adapter
that ignores the decoder and omits an excessive default is still rejected by
the host, as covered by a regression test.

The final source and contract readback compares against merged PR #9. The
`InvestigationResult`, `InvestigationRequest`, `RequiredOperations`, operation
receipts, authentication records, query request/result schemas, and `investigate`
signature remain unchanged. EventStore ownership and read-only provider behavior
remain covered by the original tests. Original EVTX hashes and the processing
package are checked separately; no private material or dataset modification is
part of this work.

The unchanged v2 output retains sticky truncation, explicit missing evidence,
qualified interpretations, final exact-ID readback, and fail-closed operational
errors. A completed result means bounded factual completion. It does not certify
exhaustive coverage, reliable autonomy, a common actor, or confirmed compromise.

## Final validation results

All final `final-v16-*` runs use the same final investigation source. The standard
profile uses Ollama 0.34.3 and `qwen3:8b`, digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`.

| Category | Recorded result | Interpretation |
| --- | --- | --- |
| A. Eight ordinary cases, twice | **16/16** factual/completion checks | Two useful synthetic follow-ups; full/empty windows may correctly finish immediately. |
| B. Dedicated six-case matrix, three repeats | **18/18** factual checks; **12/18** strict behavior checks; **0/6** targeted useful opportunities satisfied | All six useful-case repeats missed the target outcome. Three exact-missing cases include separately identified host requirements. This contradicts a claim of reliable autonomy. |
| C. Trusted required operations | **7/7** checks | Six completed model investigations and one expected pre-inference budget rejection. No missing-ID substitution. |
| D. Retained directed corpus matrix | **6/11**, exit 1 | Five externally prescribed tool exercises were not followed. |
| D. Retained directed synthetic matrix | **11/16**, exit 1 | The same five directed exercises were not followed. Original expectations are unchanged. |
| Experimental thinking, final code | **6/6** factual checks, **4/6** strict behavior checks | Neither useful opportunity satisfied the strict criterion in this final experiment. It does not justify changing defaults. |
| Fake historical corpus / synthetic / ordinary-required matrices | **11/11 / 16/16 / 23/23** | Deterministic harness and contract checks only; no claim of local-model autonomy. |

The ordinary matrix selected 11 optional operations: two added useful evidence,
two were exact duplicates served from cache, and seven added no evidence.
The dedicated synthetic opportunity repeats selected redundant queries instead
of the successful query seen in the ordinary matrix. The recorded prompts,
schemas, runtime configuration and limits are available to inspect this
inconsistency. Fixed temperature and seed did not establish stable selection.

Both final directed totals are below the historical PR #9 totals (7/11 and
15/16). They are model plan-following limitations, not passing regressions.
Every completed final result, including those directed failures, passed separate
factual readback against the actual records. The directed one-slot budget case
finished without the requested tool and therefore failed the exercise; it did
not bypass host budget enforcement.

Earlier thinking experiments demonstrated genuine real-corpus retrieval:
[v13](validation/authentication-autonomy-2026-09-24/thinking-v13-autonomy/useful_corpus.json)
selected an in-window 4625 query and annotated new `S02-SEC-43571` and
`S02-SEC-43573` records. Two of three v14 corpus repeats also retrieved and
annotated failed logons, one over multiple optional queries. That profile failed
two synthetic repeats at its 4,096-token output cap. These are experimental
observations, not a claim that the final default profile reproduces them.

| Automated check | Result |
| --- | --- |
| Full repository suite with original EVTX available | **790 passed, 3 skipped** |
| Authentication unit/regression suite | **178 passed, 1 skipped** |
| Real-corpus integration cases included in full suite | **30 passed**, none skipped |
| Original explicit provider diagnostic | **13 passed** |
| Provider contract module (12 contract cases plus ownership regression) | **13 passed** |
| Explicit live local Ollama smoke | **1 passed, 792 deselected** |
| Dependency consistency | `pip check` passed |

The full-suite skips are the opt-in smoke (run separately) and two Windows
symlink cases. Added tests cover bounded decision summaries, legacy responses,
non-authority of model text, actual post-query review, fake/required-vs-model
attribution, independent availability witnesses, no expectation injection,
missing IDs, active decoder limits and fail-closed adapters that ignore them.
Existing scope, event-type, precise-ID/timestamp, empty, truncation, budget,
duplicate-cache, provider-failure and evidence-reference tests remain intact.

## Reproduce

Use new output directories. The inference runners refuse to overwrite recordings.
Load the installed local model with the established Ollama service; these
commands neither download weights nor use cloud inference.

```powershell
python -m pytest -q --basetemp .test-tmp-autonomy-reproduce
python -m pytest -q authentication_agent/testing/check_processing_contract.py
python -m pytest -q event_processing/tests/test_authentication_provider_contract.py
python -m authentication_agent.validate_investigations --corpus out/corpus --mode ollama --output-dir out/validation/ordinary-required-followup
python -m authentication_agent.validate_autonomy --corpus out/corpus --mode ollama --repetitions 3 --output-dir out/validation/autonomy-followup
python -m authentication_agent.validate_corpus --corpus out/corpus --mode ollama --model qwen3:8b --output-dir out/validation/directed-corpus-followup
python -m authentication_agent.validate_synthetic --mode ollama --model qwen3:8b --num-ctx 8192 --think off --output-dir out/validation/directed-synthetic-followup
python -m authentication_agent.validate_autonomy --corpus out/corpus --mode ollama --think on --max-output-tokens 4096 --timeout 120 --repetitions 1 --output-dir out/validation/thinking-followup
```

The dedicated autonomy and both directed runners exited 1 in this delivery.
Their errors must remain visible; green factual checks do not override them.
See [exact recorded commands and exit codes](validation/authentication-autonomy-2026-09-24/validation-commands.json).

To reproduce the original baseline, use a separate checkout at `4ad96da` and
run `validate_investigations` with the same standard profile. Intermediate
experiments retain their exact model messages/schema, configuration, source
hashes and available prompt/source snapshots. They are not final-source results.

## Recordings

All files are in [the separate follow-up directory](validation/authentication-autonomy-2026-09-24/).
Earlier failed experiments remain intact. Raw source hashes describe each run's
actual file bytes; the final normalized source readback also supports Windows and
Linux line endings. Artifact hashes always cover exact bytes.

CI caught retired role abbreviations in report/evaluator labels after the first
commit. Descriptive labels were corrected without changing any model case file,
reply, tool arguments, expectation, count, or per-case hash. The original
manifest/snapshot bytes remain at commit `3f134a4`; the
[metadata correction record](validation/authentication-autonomy-2026-09-24/naming-metadata-readback.json)
records before/after hashes. Recorded source hashes retain their original values;
only the evaluator's docstring and report scope label changed after inference.
The naming assertion was not weakened or excluded.

Re-run the readbacks from the repository root:

```powershell
python docs/validation/authentication-autonomy-2026-09-24/verify_recordings.py
python docs/validation/authentication-autonomy-2026-09-24/verify_contract.py
```
