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
| Verifier | `evidence-verifier` version 1, prompt `evidence-verifier-prompt-v1` |
| Time tolerance for cited records outside a claim's stated span | 120 seconds |
| Verifier agent consulted for | claims the deterministic checks confirmed, and no others |
| Verifier agent authority | may lower a verdict; may never raise one or reject |

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
* **L7: unresolved endpoint windows.** Two endpoint investigation windows exceed the agent's context even at
  the smallest split; their detections are covered by neighbouring windows and the gap is recorded by the run.

## 10. Amendments

None.
