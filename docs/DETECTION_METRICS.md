# Detection metrics

This reference describes `event_processing/metrics.py` and `detection-score-v2`.
The evaluation definitions and recorded owner agreements are in
[Evaluation protocol](EVALUATION_PROTOCOL.md#12-outstanding-scoring-agreements).
Final comparisons require an approved scoring contract and independently reviewed
claims under protocol Amendment 4. Diagnostic arithmetic is not a final score.

## Unit and arithmetic

The unit is one original, scenario-scoped `evidence_id`. The flagged set is the
union of detection `trigger_evidence_ids`, deduplicated across rules. Windows do
not flag their surrounding records. Security and Sysmon views remain separate
events; stage-level coverage is reported separately by the evaluation harness.

| Quantity | Definition |
| --- | --- |
| TP | Flagged IDs labelled positive |
| FP | Flagged IDs neither positive nor excluded |
| FN | Positive IDs not flagged |
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 | Harmonic mean of defined precision and recall; 0.0 when both are zero |

Precision or recall with a zero denominator is `null`; F1 is `null` if either
input is undefined. Unlisted IDs are negative. Excluded IDs are tallied as
`flagged_excluded` and `unflagged_excluded`, outside precision/recall denominators.
The evaluator produces primary and strict scaffolding views according to the
protocol. Labels come from the independent key and owner-designated exclusions,
never from detector output or a verifier verdict.

Reports include overall, per-scenario and per-rule counts, including rules with
zero hits. Each rule's recall uses all positives, so per-rule recalls are not
additive. The engine performs arithmetic; it cannot approve the negative population
or decide which real records should be excluded.

## Label files and command

CSV requires `evidence_id,label`, with optional `reason`. JSON accepts a list or
an object containing `labels`. Labels are exactly `positive`, `negative`, or
`excluded`. Example using invented records:

```csv
evidence_id,label,reason
SYN-SEC-1,positive,independently labelled activity
SYN-SEC-3,negative,benign retry
SYN-SEC-6,excluded,owner-designated context
```

Malformed or duplicate IDs, extra fields, unknown labels, missing corpus records,
duplicate scenario runs and inconsistent corpus revisions are rejected. The CLI
checks detection manifest digests against the supplied corpus.

```powershell
python -m event_processing score --corpus out/corpus --detections out/detections --labels out/labels.csv --out out/detection-score
```

For a synthetic flagged set `{1, 2, 3, 4, 6}`, positives `{1, 2, 5}` and
excluded `{6}`, TP=2, FP=2, FN=1, precision=0.5, recall=2/3 and F1=4/7.
This is an arithmetic example, not a measured corpus result.

Use the [evaluation workflow](FINAL_EVALUATION_HANDOFF.md) for a final comparison.
The low-level scoring command alone does not establish approval or independence.
Regression coverage is in `event_processing/tests/test_metrics.py`.
