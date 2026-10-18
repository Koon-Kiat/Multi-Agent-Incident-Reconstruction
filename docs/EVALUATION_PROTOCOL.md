# Evaluation protocol

Owner: Evidence Verification & Evaluation. Status: **frozen** at the commit that introduces this file.

This protocol fixes every definition and parameter of the four-configuration comparison **before any
scored run exists**, so no result can be said to have shaped the scoring rule. Every results file records
the SHA-256 of this document, the code revision, and whether the verifier code was modified after the
protocol was committed. A change after scored runs begin is an *amendment* (section 10), dated and kept
beside the original, never an edit in place.

This document is human-facing. It states rules and contains no expected label, stage or record mapping;
those stay in `ground_truth/private/`, which no investigation component reads.

## 1. What is compared

| | Configuration | Produced by |
|---|---|---|
| A | Rules/statistics only | `python -m event_processing detect` |
| B | Single generalist LLM | `python -m incident_reconstruction --mode single-agent` |
| C | Specialist agents + reconstruction, no verification | `--mode multi-agent` |
| D | C + independent verification | `--mode full --verifier evidence_verification.agent:make_agent_verifier` |

```powershell
python -m event_processing normalise --datasets datasets --out out/corpus
python -m event_processing detect --corpus out/corpus --out out/detections
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode single-agent --out out/runs
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode multi-agent  --out out/runs
$env:MAIR_VERIFIER_LLM = "ollama"
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode full --out out/runs --verifier evidence_verification.agent:make_agent_verifier
python -m evidence_verification.evaluation --corpus out/corpus --runs out/runs --detections out/detections --out out/evaluation
```

## 2. Held constant

Scenario data (one corpus revision, identified by `corpus_manifest_sha256` in every file); the detection
triggers; the read-only providers and limits; the local model and its settings (Qwen3 8B, temperature 0,
seed 0, context 8192, thinking off) for every model role including the verifier; the timing points; and
the machine. One scored run per configuration per scenario.

## 3. Parameters fixed here

| Parameter | Value |
|---|---|
| Single-agent tool budget | 16 calls (the orchestrator's default); to be confirmed by the Incident Reconstruction Orchestrator owner before scored runs |
| Verifier | `evidence-verifier` version 1; model-layer prompt `evidence-verifier-prompt-v2` (v1 superseded by Amendment 2) |
| Time tolerance for cited records outside a claim's stated span | 120 seconds |
| Verifier agent consulted for | claims the deterministic checks confirmed, and no others |
| Verifier agent authority | may lower a verdict; may never raise one or reject; the verdict is decided by code from the assertions the model lists, never by the model |

The tolerance was set from plumbing runs, never from the answer key, because the orchestrator spans a stage
by its trigger events and legitimately cites related records slightly outside that span.

## 4. Units

* **Reconstruction:** the ground-truth stage.
* **Evidence support:** the claim.
* **Detection:** the evidence ID.
* **Latency:** wall-clock seconds per scenario per configuration, from the pipeline's own timing points.

## 5. Claim alignment

Alignment is by cited evidence, never by claim text. Each claim is exactly one of:

* **aligned**: it cites at least one record the key attributes to a ground-truth stage.
* **neutral**: not aligned, and resting only on activity deliberately outside the scored stages: records
  outside the declared scenario window (the operator's own session, which verified and exported the logs),
  logon-session records for non-person identities (service and virtual-session accounts), or records
  Dataset & Ground Truth Management designated contextual. Neutral claims are counted separately; they are
  neither a match nor a false positive.
* **unaligned**: anything else. These are the extra claims that count against precision.

A claim that cites a reference which does not resolve can never be neutral.

## 6. Metrics

All are raw counts with their denominators. A rate with a zero denominator is undefined (`n/a`), not zero.

* **R1 stages matched:** stages with at least one aligned claim, over all stages.
* **R2 order:** among matched stages, pairs whose claims appear in the key's order, over pairs whose claims
  differ in position. A claim matching two stages is a tie and is excluded, not counted as an error. Order is
  scored separately from R1.
* **R3 claim precision:** aligned over (aligned + unaligned). Neutral claims leave the denominator.
* **R4 stage coverage:** for matched stages, the share of the stage's records the best matching claim cites.
* **R5 assessment agreement:** for matched stages, whether the claims' own reading (`requires_review` versus
  `benign_possible` / `insufficient_evidence`) agrees with the stage's expected label. Reported as four counts.
* **R6 technique agreement:** whether a matched stage's expected technique, exact or at parent level, appears
  among its claims' supported or tentative mappings. Diagnostic only: the orchestrator's technique catalogue
  does not contain every technique the key names, so a miss may reflect the catalogue, not the agent.
* **S1 verdict counts:** the four verdicts, never folded into one "supported" figure.
* **S2 fabricated-reference claims:** claims citing a reference that is malformed, absent, or from another
  scenario.
* **S3 support versus key:** verdicts cross-tabulated against alignment, because a claim can be fully supported
  by real records and still describe activity the key does not attribute to any stage. Support is not correctness.
* **S4 comparability:** one deterministic verifier scores every configuration's claims, so B, C and D are
  compared on the same rule. For D the pipeline's own verdicts (including the model layer) are reported beside it.
* **V1 verifier model layer:** how many verdicts it lowered, and how those claims sit against the key.
* **L1 latency:** total and per-phase seconds; D's verification time is its added cost.
* **D1 detection (A):** event-level precision, recall and F1 using the Event Processing & Detection Engine's own
  scorer unchanged. Two label views are produced: primary (scaffolding excluded and tallied separately) and
  strict (scaffolding counts as false positives).

**Provisional:** the detection definitions are the Event Processing & Detection Engine's draft
(`DETECTION_METRICS_PROPOSAL.md`), awaiting agreement from Dataset & Ground Truth Management and Evidence
Verification & Evaluation. Every D1 figure is labelled provisional until that agreement is recorded here.

## 7. Run discipline

1. A run that used a fake model is never scored; the harness refuses it unless explicitly told to inspect
   plumbing, and then labels every output.
2. No prompt, threshold, tolerance, definition or verifier rule changes after the first scored run.
3. A scored run may be repeated only when it failed for a reason unrelated to the system under test (the model
   server did not start, ran out of memory, or a cold-start timeout produced no output). Both attempts and the
   reason are recorded.
4. A defect found after scoring is reported as a finding. Any corrected re-run is reported beside the original,
   labelled post-hoc, and never replaces it.
5. The evaluator reads the key only after a run has been written, and never modifies it. The key comes from
   the lab record, not from any AI output.

## 8. Reporting

* Raw counts with denominators, per scenario and in total. No scenario-level percentage is a headline: three
  scenarios cannot estimate one.
* Report what did not improve. The multi-agent design is not assumed to outperform the baselines.
* Failed, truncated or unresolved investigations are reported as gaps, never as clean results.

## 9. Limitations, stated before any result exists

* **L1: the rules baseline may saturate.** The attack scenario and its benign lookalike differ mainly by a
  countable field, so a threshold rule may score at or near ceiling on event-level detection. Event-level
  detection must not be the headline; stage reconstruction and claim-level evidence support must carry the
  comparison.
* **L2: three scenarios and a small number of stages.** Results are anecdotal at this size; no significance
  claim is made. One run per configuration, so run-to-run variance is unmeasured.
* **L3: no benign counterpart for the endpoint-led scenario.** The endpoint agent's false-positive behaviour on
  legitimate activity resembling that scenario cannot be measured here.
* **L4: structural claim checks apply only to known claim types.** The single-agent baseline labels its claims
  freely, so for it only the generic checks (references, times, entities, stated event types, techniques)
  apply. This favours neither side but does limit what is verified for B.
* **L5: the model layer sees retrieved records, not live telemetry.** The verifier agent judges the records the
  verifier retrieved for the claim; it does not run its own free-form queries.
* **L6: one machine, one model.** Latency depends on hardware and on local model start-up and caching.
* **L7: historical endpoint context gaps.** The original agent left two S02/S03 windows unresolved even after
  splitting. The endpoint-only [2026-10-18 correction](ENDPOINT_CONTEXT_COVERAGE.md) adds bounded model
  batches and retrieval recovery; previous outputs remain historical and must not be relabelled as repaired.
  Fresh runs must record the new endpoint prompt/configuration versions. Query budgets, oversized individual
  observations and model/deadline failures can still leave explicit gaps. Scoring definitions are unchanged.

## 10. Amendments

Each amendment is dated and recorded before any scored run. None changes a definition or parameter above.

**Amendment 1 (2026-10-17): detection triggers bound what any configuration can reconstruct.**
Configurations B, C and D take their triggers and windows from the same detection rules as configuration A.
The harness exercise with deterministic fake models (never scored) showed that, for at least one scenario, none
of the records the key attributes to its stages is a detection trigger. Activity no rule flags is never put in
front of the specialist agents or the reconstruction, so a low stage-match count there describes the rule
baseline's coverage as much as the agents' quality. Results are interpreted with that in mind, and a stage the
rules never flagged is reported as a coverage gap, not as an agent miss. The single-agent baseline may still find
such activity, because it queries the window around its triggers. No definition, parameter or rule changed.

**Amendment 2 (2026-10-17, before any scored run): the verifier's model layer, prompt v1 to v2.**
A smoke test of the model layer against the real local model showed it letting embellished claims through. It was
measured on a 14-claim synthetic benchmark (`evidence_verification/tests/benchmark_cases.py`): 6 faithful claims
and 8 embellished ones (a stated intent, cause, consequence, wrong account, wrong order or vague count the
records do not state), every one of which passes the deterministic checks, so only the model layer can catch an
embellishment. Prompt v1, which asked the model for an overall judgement, caught 4 of 8 with 0 of 6 false alarms.
Prompt v2 asks the model to split the claim into assertions and, for each, cite a retrieved record and copy its
words; code then decides: an assertion is shown only if the cited record was shown and the quote shares words with
it, an assertion the model added that is not about the claim is ignored, and any not-shown assertion lowers
`confirmed` to `partially_supported` (all not-shown: `unverified`). Prompt v2 caught 8 of 8 with 0 of 6 false
alarms, no failed calls, at a mean of 23.2 s per consulted claim.

Caveats, stated plainly: the benchmark is synthetic (no scenario data, no answer key, no scored run was
involved) but it was also used to choose between prompts, over three iterations of the grounding rule, so these
are development figures, not an independent validation, and 14 cases demonstrate that the layer can catch the
failure, not how often. The first draft of v2 wrongly flagged correct assertions because the code's quote
matching was too strict about formatting; that was a defect in the code, fixed before the figures above. The
deterministic checks, tolerance, authority limits, definitions and all other parameters are unchanged.

## 11. Post-scoring findings

Recorded on 2026-10-17 after the first scored run. Findings describe how the verifier behaved; none changes a
definition, a parameter, the verifier or a scored result. A correction to anything below could only be reported
as a labelled post-hoc re-run beside the original, never in its place (section 7).

**Finding 1: the single-agent baseline was downgraded only by the ATT&CK check.** Every claim the deterministic
verifier lowered in configuration B was lowered because a technique the single-agent model attached is not
indicated by that claim's own cited records. No claim failed on a reference, entity, time or stated event type.
The multi-agent configurations pass the technique check largely by construction, since the orchestrator derives a
claim's techniques from the detection rule that fired. The comparison on this check therefore measures a design
difference (rule-derived versus freely chosen mappings) as much as model quality, and the technique check is
stricter than anything a claim's text asserts.

**Finding 2: the model layer produced false alarms on real claims.** Of the claims it lowered in configuration D,
at least two were demonstrably supported: one asserted a duration that follows by arithmetic from the records'
timestamps, and in another the model had been shown the supporting records and still found the claim not stated.
The "0 of 6 false alarms" in Amendment 2 came from a small synthetic benchmark that was also used to choose the
prompt and that contained no faithful claim resting on a derived fact (a duration, a count, an ordering), so it
understated the false-alarm rate on real claims. The grounding rule asks for a quotable statement, which
penalises assertions that are true only by inference. Prompt v2 was not changed after scoring.

**Finding 3: a lowered verdict is a signal to audit, not a measured error.** Because the layer can only lower a
verdict and produced demonstrable false alarms, its downgrades must be read against the records rather than
counted as detected errors. The evaluation reports where each downgraded claim sits against the key so that
reading is possible.

**Note on one post-scoring edit.** After scoring, the repository's naming test showed that the first line of
`evidence_verification/evaluation/detection.py` used a retired role label. The docstring was reworded to the
component name. Its executable code is identical to the scored version (compared as a syntax tree with docstrings
removed), so no behaviour changed, but the SHA-256 recorded for that file in the scored results no longer matches
the file. The verifier modules that produced the verdicts (`checks.py`, `verifier.py`, `agent.py`, `facts.py`) are
byte-identical to the scored versions.

## 13. Amendment 3: post-hoc verifier revision (2026-10-18)

Made after scoring, in response to the review in `VERIFIER_FALSE_ALARM_REVIEW.md`. It is a labelled post-hoc re-run
beside the scored result. **The scored run is unchanged and remains the primary result.** Prompt v2 (the scored
prompt) is still the default and is byte-identical to the one used.

**What was done.** An opt-in prompt v3 (`MAIR_VERIFIER_PROMPT=v3`) tells the model that facts which follow from the
records by arithmetic or comparison are shown, and to split compound sentences into atomic assertions. A held-out set
(6 faithful claims resting on derived facts, 4 new embellishments) was written before v3 was run, and v3 was run on it
once. The saved claims of the full-MAIR configuration were then re-verified with v3 into a separate directory
(`reverify`); the claims, investigations and every other phase are exactly as scored, so any difference is the
verifier's alone.

**Results (stated plainly; v3 is not a clear improvement).**

| Measure | v2 (scored) | v3 (post-hoc) |
|---|---|---|
| Real claims lowered by the model layer, of 17 | 5 | 3 |
| Of those, supported by the records on audit (false alarms) | 5 | 3 |
| Of those, genuinely unsupported (true catches) | 0 | 0 |
| Original synthetic embellishments caught, of 8 | 8 | 6 |
| Held-out synthetic embellishments caught, of 4 | 3 | 3 |
| Synthetic faithful claims flagged, of 12 | 0 | 0 |
| Verification time, seconds | 763 | 710 |

v3 cleared four of the five original false alarms but introduced two new ones, and it lost two embellishments the
scored prompt caught. All three claims it lowered were supported on audit. Neither prompt caught a real unsupported
claim in this run, and neither caught a wrong derived fact ("ten seconds apart") in the held-out set.

**A defect found during the audit, not fixed here.** The records the verifier shows the model come from a fixed list
of fields that omits some a claim can legitimately rest on (for example the target server and target info of an
explicit-credential logon). One v3 downgrade was caused by that omission: the model was never shown the field that
states what the claim says. Fixing it would be a second post-hoc revision evaluated on the same 17 claims, which
risks fitting the verifier to the evaluation set; it is recorded as a defect and left for a decision.

**Limits of this evidence.** The 17 claims are the same set the false alarms were found on, so v3's improvement on
them is in-sample. The synthetic held-out set did not reproduce the real false alarms under either prompt, so it
cannot validate a fix for them. No conclusion about the model layer's real precision should be drawn from 17 claims.

## 12. Outstanding scoring agreements

Recorded 2026-10-18. This table lists every definition the evaluation depends on that is not yet agreed by the
other owners it concerns. **Proposed** means Evidence Verification & Evaluation's position; it is not an agreement
until the named owner confirms it here. Nothing below has been confirmed by anyone other than its proposer.

| # | Item | Proposed position (Evidence Verification & Evaluation) | Needs | Status |
|---|---|---|---|---|
| 1 | Unit of detection scoring | The evidence ID. One action seen on two channels counts twice at event level; a once-per-action view is the stage-level reconstruction score, not this metric. | Event Processing & Detection Engine, Dataset & Ground Truth Management | Proposed |
| 2 | Positive label | An event cited by a malicious ground-truth stage. An event cited only by a benign stage is explicitly negative; an event cited by both is positive. | Dataset & Ground Truth Management | Proposed; implemented as the label file the harness writes |
| 3 | Benign-lookalike scenario | Scored in the same precision pool, and also reported per scenario. Its false positives are the reason it exists. | Event Processing & Detection Engine | Proposed |
| 4 | First scenario | In scope with its own labels. Records Dataset & Ground Truth Management designated contextual are excluded, not negative. | Dataset & Ground Truth Management | Proposed; the exclusion list is private |
| 5 | Scaffolding | Headline view excludes records outside the declared scenario window and the contextual records, tallying them separately; a strict view counts them as false positives. Both are always reported. | Event Processing & Detection Engine | Proposed; both views are implemented |
| 6 | F1 when precision and recall are both defined but zero | 0.0, not undefined. Undefined only when precision or recall itself has a zero denominator. The engine currently reports undefined; this is a request to change that convention. | Event Processing & Detection Engine | **Disputed**: differs from the engine's current behaviour |
| 7 | Per-rule recall | Measured against all positives, so per-rule figures are not additive and are not a partition. No per-rule expected population is invented. | Event Processing & Detection Engine | Proposed (matches the engine's current behaviour) |
| 8 | Single-agent tool budget | 16 calls, the orchestrator default. The scored run used it; the baseline used 3 to 5 of the 16, so the budget did not bind. | Incident Reconstruction Orchestrator | **Awaiting confirmation**; evidence from the scored run supports it being adequate |
| 9 | Non-person session records as neutral claims | Claims resting only on service and virtual-session logons are neutral in claim scoring. Not assumed for detection scoring. | Dataset & Ground Truth Management | Proposed |

Until items 1 to 7 are confirmed, every detection figure is labelled provisional. Until item 8 is confirmed, the
single-agent configuration is reported with its budget stated. A disagreement on any item is resolved by amending
this section and, where a definition changes, by a labelled re-scoring beside the original (section 7).

