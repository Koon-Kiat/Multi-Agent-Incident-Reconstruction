# Authentication Investigation Agent closeout audit

Validation dates: 18–19 October 2026; closeout review: 19 October 2026. Target: fetched `origin/main`,
`b822a2e7de5e4c23898838ddc6be75322b615765`. Live recordings and the initial
regression run were made at `7eb4e62e74d5b48edb004d7a234eac44c07a22c7`.
The later commit changes verifier/evaluation code; authentication, event processing,
orchestration and dependency declarations are unchanged. Recorded production
source hashes were checked against the later checkout. This is a component assessment,
not approval of the complete MAIR submission or a detection-accuracy evaluation.

## Executive verdict

**CLOSE — ACCEPTED LIMITATIONS**

The mandatory component responsibilities in the supplied agreement are satisfied
on the shared sample corpus: local execution, bounded read-only retrieval,
schema-valid evidence-linked observations, explicit uncertainty, tested contracts
and direct orchestrator consumption. The fresh ordinary matrix passed 16/16 and
trusted-operation checks passed 7/7; the latest-main regression suite passed 1,168 tests.
These support closure of the bounded proof of concept, not reliable autonomous
discovery. Only 1/6 dedicated useful opportunities succeeded; directed exercises
still fail, and one cold-start request timed out. These non-blocking limitations
are retained and analyzed below. No unresolved production coding defect was
confirmed in the audited paths. A future requirement for reliable discovery would
need new acceptance criteria and further work; it is not silently assumed met.

## Acceptance basis and scope

The supplied **MAIR_Six_Member_Roles_and_Boundaries.pdf**, page 5, defines the
Authentication Investigation Agent's deliverables and definition of done. Pages
2 and 9 require a usable shared contract, shared-scenario tests, evidence IDs,
observed facts, optional interpretations, entities, timestamps and uncertainty.
Page 5 says the agent **may** call approved query tools; it does not require a
minimum call count, exhaustive discovery, or a numerical autonomy success rate.
Pages 1 and 13 explicitly identify the document as a proposed team agreement,
not instructor-issued role allocation. Technical closure is not evidence of
named-owner acceptance or team sign-off.

The project requirements call for an implemented
security-analysis PoC, technical quality, evaluation and comparison; page 4
requires verification of AI-assisted work and transparent disclosure. It does
not specify Qwen3, a per-component retrieval threshold, or guaranteed autonomous
discovery. This audit treats these documents as requirement evidence, not as
instructions to modify scope or send communications. Neither supplied PDF is
copied into the public repository; file hashes are retained in audit metadata.

Mandatory: normalized authentication input, bounded read-only tools, defensible
observations, schema-valid evidence-linked findings, uncertainty/failure handling,
local-model operation, tested downstream compatibility and documented usage.
Optional enhancements: exhaustive window retrieval, consistently optimal optional
queries, richer model-authored interpretation, and automatic retry/warm-up.
The implemented optional decision loop still requires honest measurement: it
cannot be advertised as reliably autonomous merely because retrieval is optional.
Endpoint investigation, full reconstruction, final verification and comparative
scoring are separate owners' responsibilities (agreement pp. 5–8).

## Acceptance matrix

Source locators below refer to the audited commit unless explicitly marked as an audit edit.

| Capability | Requirement/status | Evidence |
| --- | --- | --- |
| Consume normalized Security authentication telemetry | Mandatory; implemented and tested | `event_processing/adapters/authentication_provider.py:66–118`; `tests/test_authentication_corpus.py:43–104`: S01/S02/S03 counts, exact filters, empty/truncated windows, precision and findings |
| Bounded read-only retrieval | Mandatory; implemented and tested | `authentication_agent/queries/tools.py:62–141`, `queries/semantics.py:21–37`; scope, type, count, ordering and duplicate validation; no writable/query-language tool |
| Describe suspicious failure/success sequences | Mandatory; implemented as factual observation, not attack verdict | `authentication_agent/observations.py:54–93`; `tests/test_agent.py:28–73`; separates missing/conflicting identity dimensions and timestamp ties |
| Facts versus interpretation | Mandatory; implemented | `authentication_agent/agent.py:17–20,92–104`; Python computes observations, model can choose only two qualified interpretation phrases or null |
| Structured evidence-linked output | Mandatory; implemented and tested | `authentication_agent/models.py:128–144,269–288`; `queries/tools.py:143–154`; exact final readback rejects altered/absent evidence |
| Autonomous investigation decisions | Optional follow-up is real, reliability limited | `authentication_agent/agent.py:62–91`; fresh three-repeat opportunity recordings distinguish model, initial and required origins; see individual failures below |
| Incomplete evidence, context and tool failures | Mandatory; bounded behavior verified, token-capacity caveat remains | `agent.py:36–44,79–80,105–117`; `tests/test_agent.py:75–177`; sticky truncation, explicit missing evidence, sanitized errors, no findings on failure |
| Orchestrator compatibility | Mandatory; real production interface integrated, deterministic integration tested | `incident_reconstruction/orchestrator.py:120–145`; `incident_reconstruction/tests/test_orchestrator.py:19–43,145–149,185–211`; `tests/test_orchestration_corpus.py` |
| Designated local Ollama/Qwen3 operation | Mandatory; live execution reproduced | Fresh manifests identify weights, runtime and settings; Python environment repair and first cold timeout recorded separately |
| Meaningful regression tests and documentation | Mandatory; current counts below | Focused actual-corpus tests, provider contracts, full suite and recorded live matrices; stale README connection statement corrected |

## Test summary and reproducibility

All new runs use `out/validation/authentication-closeout-20261018/`; historical
recordings were not overwritten. Portable selected recordings and the detailed
case review are in `docs/validation/authentication-closeout-2026-10-18/`.
Raw model messages, decoder schemas, outputs, operation receipts and provider
responses are evidence; model assessments are untrusted statements, not facts.

The installed system Python 3.15.0 failed before collection with
`ModuleNotFoundError: pydantic_core._pydantic_core`. An isolated ignored venv
using bundled Python 3.12.14 and the unchanged `.[test]` requirements resolved
the environment problem. This is not a repaired agent defect. Packages are
recorded in `packages.txt`. Ollama was initially stopped; this audit started
the installed local service. No model was downloaded.

Current inference uses Ollama **0.40.6**, `qwen3:8b`, digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`, context
8192, output cap 2048, thinking off, temperature 0, seed 0 and a 60-second
per-call timeout. Query limits remain 100 normally and 2 in the existing bounded
opportunity cases; default tool budget is 8. No budget was increased to make
the results pass. Historical final runs used Ollama 0.34.3: same weights and
nominal profile do **not** make these a controlled runtime-version comparison.

| Check | Historical final documentation | Current reproduced result | Evidence / interpretation |
| --- | --- | --- | --- |
| Authentication + real-corpus focused tests | 178 passed + 30 corpus tests, 1 skip | 208 passed, 1 skip, 57.41 s | `focused-tests-python312.txt`; real EVTX normalization exercised |
| Authentication/provider/orchestrator focused contracts | Separate provider checks documented | 283 passed, 1 skip, 6.55 s | `contracts-tests.txt`; overlapping tests, not additive to full-suite total |
| Full repository suite at live baseline | 790 passed, 3 skipped | 1163 passed, 7 skipped, 358.74 s | `full-tests.txt`; repository scope grew since the historical run |
| Latest-main full regression | Not applicable | 1168 passed, 7 skipped, 284.73 s | `full-tests-latest-main.txt`; verifier-only upstream changes integrated, authentication source unchanged |
| Ordinary factual/completion | 16/16 | 16/16 | `investigations/manifest.json`, ordinary category |
| Trusted required operations | 7/7 | 7/7 | Same manifest; includes one expected pre-inference budget rejection, not a runtime failure |
| Dedicated factual completion | 18/18 | 17/18 | `autonomy/manifest.json`; one cold timeout |
| Dedicated strict behavior | 12/18 | 10/18 | Eight individual failures below, including timeout and two missing-context repeats |
| Targeted useful opportunities | 0/6 | 1/6 | One synthetic success; five missed outcomes; no corpus success |
| Directed corpus | 6/11 | 6/11, exit 1 | Five prescribed-plan failures; every result completed |
| Directed synthetic | 11/16 | 11/16, exit 1 | Five prescribed-plan failures; every result completed |

The seven full-suite skips are one opt-in authentication smoke, one opt-in endpoint
smoke, three opt-in verifier cases and two unavailable Windows symlink cases
(`test_ollama_client.py:117`, `endpoint_agent/tests/test_cli.py:109`,
`evidence_verification/tests/test_agent_live.py:26`, processing `test_query.py:444`
and `test_detection_engine.py:399`). Authentication inference is exercised by the
four separate live matrices. No corpus absence skip occurred in the focused run.

Recorded case elapsed totals: autonomy 184.501 s, corpus 55.220 s, synthetic
51.299 s, ordinary/required 133.578 s. These sums exclude setup/preflight and
are not independent latency benchmarks. The autonomy matrix selected 19 optional
operations: 1 added evidence, 10 were cached repeats and 8 added no evidence.
The ordinary/required matrix selected 17: 2 added evidence, 5 cached repeats,
10 added no evidence. The two ordinary synthetic bounded runs both retrieved
the success; the ordinary evaluator does not score strict annotations.
Prompt counters reached 6,887 in autonomy and 7,780 in ordinary/required;
maximum output counts were 583 and 214 respectively. Completed responses in
these matrices reported normal stop, not output-length exhaustion.

Historical comparison is sourced from `docs/AUTHENTICATION_AUTONOMY.md`,
“Final validation results,” and its linked immutable final-v16 recordings.
Current counts are derived from the attached manifests and byte-hash-checked
case files by `summarize.py`; `summary.json` includes every case. An additional
independent factual readback of all 27 directed outputs passed against the real
providers, without their prescribed-action expectations (`audit-metadata.json`).

All runs are development/post-hoc audit evidence, not replacement scores under
the frozen protocol. `docs/EVALUATION_PROTOCOL.md`, section 7, requires keeping
original scores and corrected reruns separate. No private ground truth was read
or supplied to the agent. The useful-outcome witness is computed independently
and appended only after investigation (`validate_autonomy.py:47–65,137–147`).

## Root-cause analysis and finding register

| ID | Classification | Blocking? | Finding, evidence, correction and owner |
| --- | --- | --- | --- |
| A1 | MODEL LIMITATION | No for the supplied bounded PoC contract; yes for a stronger claim of reliable discovery | Fresh identical-case repeats sometimes retrieve a missing outcome and sometimes repeat or stop. This establishes unreliable behavior of the tested model/runtime/prompt combination, not an inherent model-size limit. Agent owner: retain traces and qualify autonomy claims. A new model/prompt study is medium effort and evaluation-sensitive. |
| A2 | DESIGN LIMITATION | No | Account/history or host filters may return the same earliest prefix. Exact repeats are cached but charged; different no-progress filters can still consume budget. `queries/tools.py:81–104`, `prompts.py:36–54`. Tools correctly execute the selected request. A general no-progress strategy is possible but may suppress later useful discovery; medium risk. Do not hardcode the successful query. |
| A3 | EVALUATION LIMITATION | No | Strict opportunity credit requires a later non-null grounded annotation, while production permits `annotations: []`. A useful retrieved/reviewed record and strict credit must be reported separately (`validate_autonomy.py:68–113`; `tests/test_autonomy.py:107–125`). Historical directed tests measure prescribed-plan compliance, not ordinary investigation completeness. Keep their failures visible. |
| A4 | HARDWARE/RUNTIME LIMITATION | No if bounded timeout is accepted; deployment must account for startup | First cold case timed out during loading/prompt processing. Subsequent same-case warm calls completed under the original limit. The exact timeout result contains no findings. Full GPU layer offload was observed; no causal evidence supports blaming model size, RAM exhaustion or insufficient VRAM for optional-query choices. See measurements below. |
| A5 | DESIGN LIMITATION | No on tested sample windows; a scaling risk | `max_context_bytes` bounds bytes, not tokens. `agent.py:79–80` and `llm/ollama_client.py:32–37` do not guarantee the full prompt fits 8192 tokens. A larger/denser window may require token-aware admission or deterministic splitting. Static risk, not proof of observed silent truncation. Low/medium implementation complexity, medium contract/evaluation risk. |
| A6 | ACCEPTED LIMITATION | No | Historical truncation remains sticky after useful follow-up (`queries/tools.py:139`, `agent.py:37–38`). It conservatively warns of incomplete coverage; it does not certify completeness. Exhaustive paging/coverage accounting is a separate enhancement, not needed to preserve evidence integrity. |
| A7 | FIXED | No | README incorrectly said the orchestrator was unconnected. Updated to the existing `corpus_investigators` boundary and handoff. Documentation-only correction; source and runtime behavior unchanged. Older explicitly historical reports remain intact. |
| A8 | INCONCLUSIVE | No for component correctness; prevents causal/accuracy claims | No controlled alternative-model or old-runtime comparison, no independent attack-accuracy score, and no signed team acceptance are established by this audit. Model size/hardware impossibility and predicted examiner grades would be unsupported. |

No confirmed production Python dispatch, filter, budget, reference-validation or
evidence-propagation defect was established in the inspected and exercised paths.
This is scoped evidence, not a claim that no defect exists. The historical omitted
query-limit/default mismatch is already addressed by explicit bounded decoder
limits (`models.py:230–238`, `tests/test_autonomy.py:31–58`); it is not a new fix
attributed to this audit.

### Exact opportunity failures

The synthetic bounded input is `SYN-A`, `[2026-01-10T00:00:00Z,
2026-01-10T00:01:00Z)`, two-record cap. Initial records are `SYN-A-SEC-1` and
`SYN-A-SEC-2` (failures), with truncation. The independent witness shows that
an approved query can retrieve the new success `SYN-A-SEC-4` within the same
window/cap. It is not necessary to expand the window or query limit.

* Repeat 1 queried account history (same two failures), then independently chose
  a success-only query, received `SYN-A-SEC-4`, reviewed it on the next turn and
  annotated the updated observation. This is a genuine model-selected success.
* Repeat 2 repeated the initial query three times, all cached with no new IDs,
  then finished. Repeat 3 repeated it four times, selected account history
  returning the same failures, then finished. Both missed the available success.
  The receipts and subsequent contexts show correct cache, budget and feedback
  behavior; the failure lies in query selection and stopping.

The corpus bounded input is `S02`, `[2026-09-21T02:04:30Z,
2026-09-21T02:06:00Z)`, two-record cap. Initial service successes are
`S02-SEC-43503` and `S02-SEC-43547`. The independent failure-only witness returns
new `S02-SEC-43571` and `S02-SEC-43573`.

* Repeat 1 repeated the initial query, looked up each already-seen success, then
  finished without the available failures. Its internal claim that no additional
  authentication events were available contradicts the witness.
* Repeats 2 and 3 immediately finished, internally claiming no additional events
  were available because the query was truncated. This reverses the documented
  semantics: truncation says more matching records exist. Their 3052-token
  prompts and 57-token outputs completed normally; output exhaustion cannot
  explain these particular decisions.

All six results retained the host-generated incomplete-window warning, including
the successful synthetic follow-up. Unsupported completeness language in an
internal assessment does not enter the exported result. Complete initial/empty
windows may validly stop, and are not classified as missed opportunities.
Every other failed case is separately enumerated in the attached case analysis.
The three repeats of each useful case have identical initial message hashes and
decoder schemas. Their different decisions therefore are not explained by a
changed initial request/schema; runtime state and numerical/cache effects were
not isolated by this experiment.

### Individual remaining failures

All paths in this table are relative to the attached evidence directory. Exact
input messages and expected directed arguments are in `model_calls[0].messages`;
actual decisions are in `model_calls[].reply`, actual responses in
`provider_calls` and `result.metadata.operations`. `case-review.json` collects
these with per-turn budgets, visible IDs, last-tool results and context hashes.

| Case | Expected versus actual; observable consequence | Classification |
| --- | --- | --- |
| `autonomy/sufficient-1.json` | Full synthetic evidence required only a finish; 60-second timeout returned failed/no findings. Repeats 2–3 completed without optional calls. | Runtime latency; A4 |
| `autonomy/useful_synthetic-2.json` | Discover/review an available outcome; three initial-query repeats added nothing, then finish missed the success. | Model selection; A1/A2 |
| `autonomy/useful_synthetic-3.json` | Same opportunity; four initial repeats plus account history added nothing, then finish. | Model selection; A1/A2 |
| `autonomy/useful_corpus-1.json` | Discover available failed logons; initial repeat and two existing-ID lookups added nothing. | Model selection; A1/A2 |
| `autonomy/useful_corpus-2.json` | Same opportunity; immediate finish despite truncation and available budget. | Model selection; A1 |
| `autonomy/useful_corpus-3.json` | Same opportunity and same immediate finish; no new evidence. | Model selection; A1 |
| `autonomy/missing_context-2.json` | Missing identity fields cannot be repaired by fetching the same record; selected `SYN-F-SEC-1` twice, second cached, then finished with factual uncertainty. | Redundancy, not missing-outcome failure; A1/A3 |
| `autonomy/missing_context-3.json` | Same repeated exact lookup, same bounded consequence. | Redundancy; A1/A3 |
| `corpus/get_existing.json` | Requested exact `S02-SEC-43503`; model finished without the lookup; initial evidence already included it. | Prescribed-plan failure; A3 |
| `corpus/get_missing.json` | Requested absent `S02-SEC-999999999`; model finished, so absence was not checked or reported. Trusted required lookup separately passed. | Prescribed-plan failure; A3 |
| `corpus/query_tool.json` | Requested success-only query; selected account history for `mair_user` with both outcomes. Returned already-seen records, then annotated a supported cohort. | Wrong prescribed tool; A1/A3 |
| `corpus/account_history.json` | Requested `SYSTEM` history; selected `mair_user` history instead. Returned already-seen records; no scope/filter implementation error. | Wrong prescribed account; A1/A3 |
| `corpus/tool_budget.json` | Requested an extra lookup after the one allowed initial query; model finished instead. No excess tool execution occurred. | Exercise failure, not budget bypass; A3 |
| `synthetic/get_existing.json` | Requested exact `SYN-A-SEC-1`; immediate finish with already-complete initial evidence. | Prescribed-plan failure; A3 |
| `synthetic/get_missing.json` | Requested absent `SYN-A-SEC-999`; immediate finish omitted the requested absence check. | Prescribed-plan failure; A3 |
| `synthetic/query_tool.json` | Requested success-only query; immediate finish, no tool response. | Prescribed-plan failure; A3 |
| `synthetic/account_history.json` | Requested `demo.user` history; immediate finish, no tool response. | Prescribed-plan failure; A3 |
| `synthetic/tool_budget.json` | Requested an over-budget exact lookup; immediate finish never attempted it. | Exercise failure, not budget bypass; A3 |

The two directed budget cases contain findings because they **completed**, whereas
their exercise expected failure. The check text “failed investigations must
contain no findings” is conditional on that expected outcome; it does not show
that an actually failed investigation leaked findings. Separate required-budget
and deterministic tests enforce rejection and empty findings.

## Fix assessment and experimental integrity

No production prompt, tool, schema, limit or model-selection change was made.
The isolated environment repair allowed real tests; the README correction fixes
an independently verified documentation error. Existing deterministic tests
exercise approved follow-up delivery and required operations; the fresh successful
synthetic query independently demonstrates the live transport/dispatch path.
There is no evidence-based reason to rewrite it simply to increase scores.

Reasonable next experiments are a general no-progress policy and a controlled
runtime/model comparison with the same hidden opportunity witnesses. Neither
would justify replacing frozen measurements. The orchestrator's existing
`FinishGuard` already forces the finish branch after an exact repeat or at zero
budget (`orchestrator.py:75–117`). That bounds loops and preserves results, but
can stop before an alternative useful query. It is host intervention, not an
improvement in autonomous selection. This audit does not add it to standalone
evaluators or relabel guarded completion as autonomous success.

## Hardware and runtime assessment

Local raw diagnostics and utilization samples are retained under the fresh
`out/validation/` directory. Shared findings use resource measurements without
publishing personal hardware model/driver details. The server recorded **37/37
layers offloaded to GPU**, context 8192, and a cold runner startup of about
34 seconds. The first `sufficient-1` call reached the 60-second client deadline
before a complete response; warm repeats completed. This supports startup/runtime
latency as a contributor, not a proven VRAM/RAM capacity defect. GPU utilization
is sampled rather than a per-token causal profile; no CPU-offload or OOM cause
was demonstrated. Lack of an observed OOM does not prove unlimited headroom.
The 180 five-second GPU samples ranged from 18–100% utilization and 30.5–85.5%
allocated device memory. The sampling interval includes inference and later idle
time, and allocations include other desktop processes. These measurements cannot
attribute latency to this model alone. Raw `gpu-samples.csv` and server stderr
remain local; `runtime-observations.json` retains the privacy-safe summary.

The output cap remains unchanged. Per-turn token counters, stop reasons and
timings are retained in recordings. A completed, short response that chooses a
bad query is analyzed separately from a timeout or length failure. Generalizing
from this machine or runtime to all Qwen3 deployments would not be justified.

## Integration and remaining risks

The processing adapter preserves original IDs, raw references, precise timestamps
and fields; queries use the agent's shared matching/bounds functions. Final
readbacks resolve every retrieved event. The orchestrator imports the actual
typed result and calls `investigate` directly, supplies trusted trigger lookups,
and retains uncertainty and failed outcomes. No member-specific result adapter
is needed (`orchestrator.py:22–35,120–145,224–269`).

| Risk | Severity / effect | Mitigation and ownership |
| --- | --- | --- |
| Missed optional evidence | Medium; reduced contextual coverage and possible downstream stage coverage | Preserve uncertainty, distinguish required seed retrieval, disclose measured selection reliability; authentication and evaluation owners |
| Cold start/latency variability | Medium; fail-closed investigation rather than findings | Start and warm the agreed service operationally, retain failed attempts and timing; runtime/orchestration owner |
| Large prompts exceed token capacity | Medium potential; model may see incomplete context | Restrict evaluated windows; test token-aware admission/splitting before broader claims; authentication owner |
| Directed-plan failures mistaken for broken tools | Medium reporting risk | Separate model decisions from tested dispatch and trusted required operations; evaluation owner |
| Overstated academic result | High reporting risk | Do not equate factual consistency with accuracy, autonomous reliability, or comparative improvement; report authors/evaluation owner |

Formal team sign-off, final release packaging and end-to-end comparative scores
remain outside this component verdict. They are not silently assigned to the
authentication developer, nor treated as proof of authentication failure.

## Final quality gate

| Question | Evidence-based answer |
| --- | --- |
| Mandatory responsibilities correct? | Yes for the bounded shared-corpus component contract; acceptance matrix, focused tests and live ordinary/required results support this. |
| Unresolved Python/tool-integration defects? | None confirmed in exercised paths. System Python's dependency failure was isolated and remedied without production changes. |
| Correct evidence-linked findings without autonomous follow-up? | Yes. Complete S01–S03 initial windows and empty cases complete correctly; host computations and final readbacks provide provenance. This is not independent attack accuracy. |
| Missing evidence reported as incomplete? | Yes in exported truncated results. Internal model assessments can falsely imply completeness; the host warning survives and that text is not exported as a finding. |
| Does weak autonomy materially affect required functionality? | It reduces coverage in bounded-prefix opportunities, but does not violate the supplied role's bounded, uncertainty-preserving PoC contract. It prevents claims of reliable discovery. |
| Failed cases individually analyzed? | Yes: all eight autonomy failures and ten directed failures are enumerated with exact recordings; valid stopping is separated from missed opportunities. |
| Reasonable fixes attempted fairly? | Broken local environment repaired; stale connection documentation corrected. Current dispatch and follow-up propagation verified. No speculative production rewrite or score-forcing change was justified. |
| Remaining limitations reproducible? | Yes: commands, model digest/profile, source hashes, actual responses, receipts and individual checks retained. Runtime-version and cache variability explicitly limit exact replay. |
| What does this audit establish? | The bounded authentication component has documented checks and limitations against the written requirements. Whole-system performance and independent reconstruction accuracy are not established by this component audit. |

## IEEE report-ready limitations paragraph

The authentication investigator produced evidence-linked, schema-valid observations
in all 16 ordinary validation runs and satisfied seven trusted-operation checks.
However, in 18 dedicated behavioral trials it achieved 17 factual completions
and ten strict behavioral passes; only one of six bounded retrieval opportunities
produced a newly retrieved, reviewed and annotated target outcome. Failures included
redundant queries and premature stopping despite explicit truncation. One cold-start
request exceeded the 60-second timeout. Host-side provenance checks and incomplete-
coverage warnings bounded these failures, but did not establish exhaustive retrieval
or attack-detection accuracy. These development results used fixed local weights
and nominal settings; runtime-version and caching differences limit direct comparison
with earlier measurements and do not establish an intrinsic model or hardware limit.

## Reproduction commands and artifact index

Use a working Python 3.11+ environment with `python -m pip install -e '.[test]'`.
This audit used `.authentication-runtime/closeout-venv/Scripts/python.exe` for
every successful command below. Ensure installed local Ollama is serving the
recorded model; no weights download is part of the commands. Use a **new** output
root for each repeat; the evaluators refuse to overwrite recordings.

```powershell
python -m pytest -q authentication_agent/tests tests/test_authentication_corpus.py --basetemp .test-tmp-closeout-focused
python -m pytest -q authentication_agent/tests authentication_agent/testing/check_processing_contract.py event_processing/tests/test_authentication_provider_contract.py incident_reconstruction/tests --basetemp .test-tmp-closeout-contracts
python -m pytest -q --basetemp .test-tmp-closeout-full
python -m authentication_agent.validate_autonomy --corpus out/corpus --mode ollama --repetitions 3 --output-dir out/validation/authentication-closeout-20261018/autonomy
python -m authentication_agent.validate_corpus --corpus out/corpus --mode ollama --model qwen3:8b --output-dir out/validation/authentication-closeout-20261018/corpus
python -m authentication_agent.validate_synthetic --mode ollama --model qwen3:8b --num-ctx 8192 --think off --output-dir out/validation/authentication-closeout-20261018/synthetic
python -m authentication_agent.validate_investigations --corpus out/corpus --mode ollama --repetitions 2 --output-dir out/validation/authentication-closeout-20261018/investigations
```

Run inference matrices sequentially to avoid competing local model requests.
The full deterministic suite overlapped the first live matrix; timing is therefore
observational, not an isolated hardware benchmark. Regenerate a missing corpus
with the documented normalization command in `authentication_agent/README.md`;
the manifest digest must match before comparing evidence.

The [evidence directory](validation/authentication-closeout-2026-10-18/) contains
four raw matrices, manifests, test logs, environment package list, `summary.json`,
`case-review.json`, the reproducible summary script, audit metadata and artifact
hashes. Corpus/source digests in the raw manifests identify the actual inputs.
Hardware logs, extracted requirements notes and rendered reference pages remain
in the ignored local output directory. No historical result or frozen score was
replaced. At audit completion, the changes were local and unpublished. Subsequent
delivery through a pull request does not change the recorded validation baseline.
The local main branch was fast-forwarded to the fetched upstream commit.

Readback command (no inference):

```powershell
python docs/validation/authentication-closeout-2026-10-18/verify.py
```

The verifier checks saved artifact/case hashes, current production source hashes,
all 68 typed results, 27 directed factual outputs, truncation warnings and absence
of findings on failure. It does not certify model reasoning or attack accuracy.
