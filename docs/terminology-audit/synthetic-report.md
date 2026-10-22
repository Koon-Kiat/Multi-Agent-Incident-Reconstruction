# MAIR evaluation results

> **SYNTHETIC TEST FIXTURE ONLY.** No model was executed. Every event, claim, review and score below is synthetic; this is a report-layout and contract demonstration, not an experimental result.

> **SYNTHETIC UNIT TEST ONLY.** The original scored run is the primary result; this table must be reported beside it, never in place of it.

## Provenance

- Corpus manifest SHA-256: `e067ade583891651ee2e2e75b6df8c0de753f7d4d6bf980f96fdf59bad8a8050`
- Code revision: `852168c29584e7d839cc2202d5f7eab13d31f95e`; verifier code unmodified since commit: `False`
- Verifier version 3, prompt `evidence-verifier-prompt-v5`, span tolerance 120 s
- Evaluation protocol SHA-256: public `d9aa549d26e0e6ce7f74b331e952da002e5d6ef4ae3ebb8796b84fa37e6bcd19`, private `None`
- Hardware: synthetic fixture; None logical CPUs; No host hardware details included

## Evidence alignment and coverage (unit: ground-truth stage)

Stages matched = stages with at least one claim citing a record the key attributes to them. Order counts pairs of matched stages by whether their claims appear in the key's order (ties excluded). These are evidence-overlap diagnostics, not semantic reconstruction accuracy.

| Configuration | Scenario | Stages matched | Order concordant | Claims aligned | Neutral | Unaligned | Mean stage coverage |
|---|---|---|---|---|---|---|---|
| Single-Agent Generalist Baseline | SYN-V1 | 1/1 | 0/0 | 1 | 0 | 0 | 1.000 |
| **Single-Agent Generalist Baseline** | **all** | **1/1** | **0/0** | **1** | **0** | **0** |  |
| Specialist-Agent Incident Reconstruction | SYN-V1 | 1/1 | 0/0 | 1 | 0 | 0 | 1.000 |
| **Specialist-Agent Incident Reconstruction** | **all** | **1/1** | **0/0** | **1** | **0** | **0** |  |
| Specialist-Agent Incident Reconstruction with Independent Evidence Verification | SYN-V1 | 1/1 | 0/0 | 1 | 0 | 0 | 1.000 |
| **Specialist-Agent Incident Reconstruction with Independent Evidence Verification** | **all** | **1/1** | **0/0** | **1** | **0** | **0** |  |

## Independently reviewed reconstruction correctness

Only separate human annotations bound to these exact claims and the private lab key establish correctness. The verifier is not its own answer key. Missing review means not measured. Operational verification abstentions are separate: they never earn an unsupported-claim catch, and abstaining on an unsupported claim remains a miss in recall.

| Configuration | Scenario | Correct stages | Stage recall | Unsupported TP | False alarms | Unsupported FN | Supported TN | Audit precision | Audit recall | Operational abstentions |
|---|---|---|---|---|---|---|---|---|---|---|
| Single-Agent Generalist Baseline | SYN-V1 | 1/1 | 1.000 | 0 | 0 | 0 | 1 | n/a | n/a | 0 |
| Specialist-Agent Incident Reconstruction | SYN-V1 | 1/1 | 1.000 | 0 | 0 | 0 | 1 | n/a | n/a | 0 |
| Specialist-Agent Incident Reconstruction with Independent Evidence Verification | SYN-V1 | 1/1 | 1.000 | 0 | 0 | 0 | 1 | n/a | n/a | 0 |

## Does the system tell the benign lookalike from the attack? (aligned stages only)

`true_flag`/`true_benign` are stages the claims judged as the key labels them; `under_call` is an attack stage the claims called benign or insufficient; `over_call` is a benign stage the claims flagged for review.

| Configuration | true_flag | under_call | over_call | true_benign |
|---|---|---|---|---|
| Single-Agent Generalist Baseline | 1 | 0 | 0 | 0 |
| Specialist-Agent Incident Reconstruction | 1 | 0 | 0 | 0 |
| Specialist-Agent Incident Reconstruction with Independent Evidence Verification | 1 | 0 | 0 | 0 |

## Evidence support (unit: claim; one verifier scored every configuration)

The same deterministic verifier checked every configuration's claims, so the counts are comparable. Support is not correctness: a claim can be fully supported by real records and still describe activity the key does not attribute to any stage.

| Configuration | Claims | confirmed | partially_supported | unverified | rejected | Fabricated-reference claims |
|---|---|---|---|---|---|---|
| Single-Agent Generalist Baseline | 1 | 1 | 0 | 0 | 0 | 0 |
| Specialist-Agent Incident Reconstruction | 1 | 1 | 0 | 0 | 0 | 0 |
| Specialist-Agent Incident Reconstruction with Independent Evidence Verification | 1 | 1 | 0 | 0 | 0 | 0 |

### Specialist-Agent Incident Reconstruction with Independent Evidence Verification: verifier verdicts by evidence alignment

Rows are what the key says about the claim; columns are the verdict the pipeline recorded.

| Claim vs key | confirmed | partially_supported | unverified | rejected |
|---|---|---|---|---|
| aligned | 1 | 0 | 0 | 0 |
| neutral | 0 | 0 | 0 | 0 |
| unaligned | 0 | 0 | 0 | 0 |

Claims whose verdict the model layer lowered below the deterministic verdict: **0** of 1.

## Latency

Wall-clock seconds per scenario. One run per configuration on one machine; local model start-up and caching add variability.

| Configuration | Scenario | Total s | Investigation s | Reconstruction s | Verification s | Model calls |
|---|---|---|---|---|---|---|
| Single-Agent Generalist Baseline | SYN-V1 | 2.000 |  |  |  | 1 |
| Specialist-Agent Incident Reconstruction | SYN-V1 | 2.000 |  |  |  | 1 |
| Specialist-Agent Incident Reconstruction with Independent Evidence Verification | SYN-V1 | 2.000 |  |  |  | 1 |

## Rules-only Detection Baseline (unit: evidence ID)

**AGREED - versioned owner-approved scoring contract.**

| Label view | Flagged | TP | FP | FN | Flagged-excluded | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| primary | 0 | 0 | 0 | 3 | 0 | n/a | 0.000 | n/a |
| strict | 0 | 0 | 0 | 3 | 0 | n/a | 0.000 | n/a |

## Investigation gaps recorded by the runs

- none
