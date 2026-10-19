# Correctness remediation and validation

Recorded 2026-10-19 on `fix/evidence-evaluation-correctness`, based on upstream
`da189892a48cb872808b6d6df2206100fb722ef8`. A subsequent fetch confirmed the same upstream revision.
The proposal, coursework and responsibility boundaries informed the original review. Historical results
remain unchanged; corrected development artifacts are separate under `out/correctness-fix-validation/`.

## Changes against the review

| Finding | Correction |
|---|---|
| R1: invented quote accepted through a shared token | Require contiguous recorded spans with word boundaries and coverage of claim assertions. Incomplete review is unverified. A genuine quote establishes provenance; its semantic relationship still requires validation. |
| R2: incorrect failure/success ordering | Check strict sequence chronology and explicit logon-order wording independently. Check explicit two-failure separation and exaggerated plural counts against source times/counts. |
| R3: mixed, incomplete or stale comparisons | Validate typed artifacts, complete A/B/C/D scenario coverage, identical real model profiles, corpus/triggers, implementation/artifact hashes and report-to-reconstruction binding. Fake/partial inspection stays diagnostic. Verifier call totals are per invocation and included in pipeline totals. Post-hoc outputs are separate and staged atomically. |
| R4: distinct principals conflated | Detection, authentication observations and verification share conservative host/domain/SID correlation. Resolve NULL SID only through an unambiguous exact alias. Account links retain domains. |
| R5: Sysmon process-access account filter lost SourceUser | Normalize Sysmon 10 SourceUser; retain User for other supported Sysmon types. Rebuild the corpus and verify the exact account filter. |
| R6: byte limits did not bound authentication model tokens | Batch complete observations with byte/token guards and output/template reserves. Reconstruct local Qwen2 BPE from installed metadata; use a conservative UTF-8 fallback. Reject unexpected runtime prompt counts. Never clip facts to fit. |
| R7: legitimate verifier evidence omitted | Preserve every referenced record and event-data field, with neutral event-type labels. Remove record/character caps. Overflow is explicitly unverified. Endpoint replies use validated batch indices while final findings retain exact citations. Unchanged retrieval preserves completed review. Production calls inherit task deadlines. |
| R8: evidence overlap called accuracy | Label overlap as alignment/coverage. Add independent human claim/stage reviews bound to exact content. Operational failures never earn an unsupported-claim catch; abstaining on an unsupported claim still reduces recall. Report abstentions separately. |
| R9: scoring agreement and zero-F1 convention unresolved | Version arithmetic as detection-score-v2 (defined-zero precision/recall gives F1 0.0). Require an owner-approved contract and reviewed negative population for final scoring. No approval or independent answer is invented. |

## Validation

The initial corrected-code full run passed **1,228 tests**, with **7 skipped** (535.47 seconds). Its scoring
follow-up passed **49 tests**, including two new operational-abstention cases added after full-suite
collection. Automated and live logs are in `out/correctness-fix-validation/`. Negative regressions cover principals,
chronology, fabricated/omitted quotes, context overflow, full evidence preservation, current-code artifact
binding, model mismatch, missing configurations, independent reviews, abstentions and metric arithmetic.

* Fresh corpus: 6,661 events and 38 detections (9/15/14). Real-corpus regression independently reproduces
  corrected hashes in `DETECTION_RULES.md`; byte-identical reruns pass. Thresholds were unchanged.
* SourceUser: of 447 first-scenario process-access records, 311 name the selected system account. Exact
  account filtering now returns all 311; previously it returned zero.
* Largest live endpoint root: 509 records, findings and exact readbacks; complete coverage, no truncation,
  242.147 seconds, 45 model calls and 8 tool calls, within the 900-second deadline. The indexed prototype
  also completed this root in 648.180 seconds before instructions were shortened. These are local
  development timings, not portable performance guarantees.
* The two formerly unresolved windows retain all 125/117 records under the conservative 8,192-token bound.
  Corrected live runs completed those windows in 81.674/91.558 seconds with complete retrieval and
  exact 125/117 readbacks. Independent anchor-set checks equal the original source-window record sets.
  The corrected authentication smoke completed with 12 exact readbacks in 62.061 seconds. These are
  component smokes, not a fresh real-model A-D comparison.
* Fake CLI runs exercise all three modes/scenarios and HTML reports, using the actual full-mode verifier
  factory with its explicitly fake adapter. These validate plumbing only.
* Editable installation, dependency consistency, PowerShell parsing and the evaluation wrapper's fresh
  corpus/detection preparation pass. Original evidence, historical outputs and report documents are unchanged.
* Live development probes use Qwen3 8B, Ollama 0.34.4, context 8192, temperature/seed 0 and thinking off;
  model digest `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`.
  Observed prompt counts stay below preflight bounds. Previously used benchmarks, including their
  historical held-out cases, are in-sample regression evidence now. Faithful paraphrases can still be
  downgraded; invalid replies remain operational abstentions. The final 24-case development run confirmed
  10/12 faithful claims, downgraded one faithful paraphrase and abstained on one invalid reply. Among 12
  embellished claims, 11 received content downgrades and one an operational abstention; none confirmed.
  An abstention is not a successful semantic catch. These initial, reused examples establish regression behavior,
  not real-world accuracy. Semantic verification is not perfect.

## Independent evaluation still required

A search including ignored/hidden files across the entire project found only the review's synthetic CSV.
No real scenario CSVs or private runbooks were available. Place the original package under
`ground_truth/private/` and `runbooks/private/`, or pass its actual path. See `ground_truth/README.md`.

After fresh A/B/C/D runs, `evidence_verification.evaluation.prepare_review` generates unanswered forms.
An independent reviewer completes claim support/stage annotations against original records and the lab
key; dataset/detection/evaluation owners complete the scoring contract. Then score into a new directory.
`scripts/run-evaluation.ps1` documents these stages. Missing inputs, incomplete matrices and simulated
models cannot become a final score.

The initial fixes left unreliable authentication follow-up selection and verifier false alarms. The
follow-up below addresses these implementation/behavior issues. No real A-D accuracy or owner approval
is claimed; deterministic extraction and mandatory operations never establish autonomous reasoning.

## Follow-up: retrieval and semantic verification

Artifacts for this follow-up are separate under `out/m3-m6-quality-2026-10-19/`. The model name, digest,
Ollama version, context, temperature, seed, thinking mode and output/tool budgets match the profile above.
Authentication retains its 60-second per-call limit. The recording wrapper now forwards the real
adapter's token counter, matching production context admission rather than applying its UTF-8 fallback.

Authentication prompt v17/configuration v5 uses `public-query-menu-v1`. The host generates legal questions
only from public scope, observed records and receipts. The model chooses a query or finishes. The menu
excludes equivalent prior operations and exact re-fetches of known records; a complete initial inventory
permits finishing only. Indexed replies review every supplied observation, with null interpretations
still permitted. The host never supplies an expected query, witness, hidden record or answer label.

The fresh baseline completed all 18 cases factually, but passed only 6 strict behavior checks and
demonstrated useful retrieval in 0/6 opportunities. The revised production policy passed all 18 checks
and all 6 useful opportunities, retrieving, reviewing and explicitly annotating new relevant records.
The three repeated synthetic and three corpus opportunity runs each used seven optional queries,
exhausting the bounded budget; this demonstrates useful selection, not optimal query efficiency or
unrestricted planning. No mandatory retrieval earns this credit. Source hashes stayed stable in each run.

New self-authored synthetic cases were hashed before implementation changes or first live execution:
`tests/quality_cases_new.py`, SHA-256 `902a15a804aa3ed9135b4026094d5ec6cb59b27b29f2769989911ea149151219`.
All eight authentication cases passed factual and behavior checks; all four valid useful opportunities
were retrieved, reviewed and annotated. The predeclared fifth opportunity was invalid: lexicographic
tie ordering already put its desired success in the initial prefix. Its records/labels remain unchanged;
the harness records the defect and evaluates that case factually only, excluding it from useful credit.

Verifier version 3/prompt v5 partitions the original claim without dropping non-whitespace text. Every
clause requires a support judgment backed by host-bound source fact IDs. Ordinary replies select proofs
before their short reason; compact replies summarize source fields first. Both choose support last.
Repeated citations add no weight and are normalized as a set. The model cannot omit an assertion or manufacture a quotation.
One format-only repair supplies no expected label; both calls count. Incomplete review remains an
operational abstention. Counts, comparisons and compound facts may use multiple original records.

The first new verifier run accepted 7/8 faithful claims and downgraded all 8 embellishments without
operational failures. It exposed sentence punctuation being included in a Windows path; the generic
token check now handles terminal punctuation while still rejecting unrecorded paths. The first
revised development prototype also regressed on three embellishments before proof/reason-first
responses corrected it. All failed prototype recordings are retained. These cases are development
regressions after use, not an untouched external test set.

Real-corpus component checks exposed two further integration defects: reconstruction still stripped
domains when creating account links, and large complete verifier views exceeded context. Stage links
now retain qualified names and avoid plain aliases bridging distinct domains. A lossless default/override
prototype fitted but still produced real-corpus semantic false alarms. It was replaced by grouped facts:
identical field/value pairs explicitly name their original record indices. Every value is reconstructible,
metadata and same-named source fields stay distinct, and absent fields stay absent. No record is dropped.
The prompt distinguishes primary cited activity from surrounding contextual events and their timestamps;
the clause splitter preserves object phrases such as "access to lsass.exe".

The ordinary evidence representation keeps its validated instructions. The compact representation adds
format-specific instructions about grouped values, primary versus context records and timestamp
semantics. Citations can include related records outside the stated span; those records remain visible
but are not automatically part of an assertion describing activity within it. The compact view supplies
exact in-span counts and elapsed times computed from recorded metadata timestamps, with
no semantic labels. A shared-instruction prototype regressed on a faithful "within" duration and was
discarded; the recordings remain available. The source-computation tests include 100 ns precision.
For clarity, the bounded view first keeps complete in-span records together and groups surrounding
context. If that cannot fit, it groups all facts. Both presentations retain every value. This prevents
coherent file/time observations from being scattered across an unnecessarily fragmented table.

The follow-up full suite passed **1,256 tests**, with **7 skipped**, in 573.23 seconds. The final
43 focused proof/reconstruction/principal checks also passed, including the source-computation/context tests
added after full-suite collection. Earlier focused verifier and integrated checks passed 194 and
284 tests respectively. The latest release-focused run passed **478 tests**, with **4 skipped**, after
the final decoder/normalization changes. Skips remain explicit opt-in live tests and Windows symlink cases; actual
local-model runs are recorded separately. These totals overlap and are not added together.

## Remaining items and PR assessment

No blocking data-integrity, scope-control or scoring defect was found by the final automated checks.
The following are explicit follow-ups, not claims that all model behavior or final evaluation is complete:

* **Conservative model judgments.** The final live component run consulted all 17 newly generated real-corpus
  template claims: 13 confirmed, two partially supported and two unverified, with zero operational failures
  and zero format retries. The lowered claims are S01-CLM-02, S02-CLM-03, S02-CLM-06 and S03-CLM-06. They
  need independent semantic review; template generation is not an independent truth label. Model judgments
  remain fallible, and repeated development runs varied. This is nonblocking for reviewing the implementation
  improvements, but prevents claiming the verifier's real-world accuracy is established.
* **Query efficiency.** Useful capped-prefix authentication runs used all seven optional calls. Useful selection
  is demonstrated in these cases; optimal stopping and general unrestricted autonomy are not established.
* **Final project evaluation.** Original private lab keys/runbooks, independent claim/stage reviews and owner
  agreement on the scoring contract remain required before a defensible A-D comparison. These are external
  evaluation prerequisites, not values the implementation can invent. The current PR supplies the checks/forms;
  it does not replace the missing package or approvals.

The 40 small synthetic regression/generalization cases accepted all 20 faithful claims and lowered all 20
embellishments without operational failures. Their recorded ordinary prompts and schemas are byte-equivalent
to the final implementation; subsequent changes affect only overflowing views or harmless citation repetition.
These are development results, not an independent accuracy estimate. All nine current fake mode/scenario
artifact sets pass binding validation and remain labelled plumbing only. Original evidence and historical scores
are preserved. Current live traces and the aggregate audit remain in the ignored local output directories.
