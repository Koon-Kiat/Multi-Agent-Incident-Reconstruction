# M2 Detection Metrics Proposal (DRAFT)

> **DRAFT — not agreed. The baseline must not be scored until this is agreed.**
>
> M2 owns the scoring *code*, not the definitions. The unit, the positive label and the excluded
> category below are M2's proposal for the joint M2 + M1 + M6 call that
> `docs/M6_TO_M2_INTERFACE_NOTE.md` item 5 asks for. Until that call agrees them, no result of
> `python -m m2 score` is a reportable number: the code is implemented and tested
> (`m2/metrics.py`, `m2/tests/test_metrics.py`), the real baseline is **not** scored, and task
> T4.3 in `task_plan.md` stays BLOCKED.

Owner: M2 (Data Processing & Detection). Status: proposal for the M2/M1/M6 call.
Related: [`M2_DETECTION_RULES.md`](M2_DETECTION_RULES.md) (the baseline and its counts),
[`M6_TO_M2_INTERFACE_NOTE.md`](M6_TO_M2_INTERFACE_NOTE.md) item 5 (M6's ask and its two corpus
observations).

## Contents

* [What M2 needs from the call](#what-m2-needs-from-the-call)
* [The proposal](#the-proposal)
* [The excluded category](#the-excluded-category)
* [The label file M2 will read](#the-label-file-m2-will-read)
* [Worked example](#worked-example)
* [Open questions for the call](#open-questions-for-the-call)
* [What M2 will not do](#what-m2-will-not-do)

## What M2 needs from the call

Three definitions, before the baseline can be scored:

1. **The unit** — what one counted item is.
2. **A positive** — which events count as the activity the baseline was supposed to find.
3. **The excluded category** — which events are out of scope and tallied separately.

The scoring code is deliberately arithmetic-only: it takes a list of `evidence_id` labels and the
detection artefacts and returns precision, recall and F1 with raw counts. It makes no judgement
about whether a label is right, and it cannot invent or widen a definition.

## The proposal

**The unit is one `evidence_id`.** Every metric is computed over evidence IDs, not over detections,
not over windows and not over scenarios. A detection *flags* exactly the IDs in its
`trigger_evidence_ids` and nothing else (see
[window detections](#window-detections-count-only-their-trigger-ids)).

**A positive is an event cited by a malicious ground-truth stage.** The label is produced by
M1/M6 from the scenario ground truth; M2 never sees, requests or derives it. An event is positive
when the ground-truth material attributes it to a stage the evaluation counts as malicious — the
call should confirm that "cited by a malicious stage" is the whole test, and that an event cited by
a benign or scaffolding stage is not positive (see [the excluded category](#the-excluded-category)).

**TP / FP / FN are set operations over the evidence IDs, deduplicated.**

| Term | Definition |
|---|---|
| flagged | the union of `trigger_evidence_ids` over every detection of every rule and scenario, deduplicated |
| TP | `flagged ∩ positive` |
| FP | `flagged − positive − excluded` |
| FN | `positive − flagged` |

`excluded` is the category below. An event that is neither listed positive nor listed excluded is
**negative**, so any flagged event that is not a positive or an excluded one is a false positive.
That is what makes "any evidence_id not listed = negative" work without listing the whole corpus.

The metrics, each reported with its raw counts and its denominator:

* precision = `TP / (TP + FP)`
* recall = `TP / (TP + FN)`
* F1 = `2 · precision · recall / (precision + recall)`

A metric with a zero denominator is reported as `null` (**undefined, not zero**): a rule that
flagged nothing has no precision, and a label file with no positives has no recall. Reporting `0`
for either would look like a measured failure instead of an absent measurement. Results are
reported **overall**, **per scenario** and **per rule**; an event two rules both flag is one
flagged event overall (the deduplicated figure is the headline), and it is attributed to each of
the rules that flagged it in the per-rule table. The per-rule TPs therefore do not sum to the
overall TP.

### Window detections count only their trigger IDs

A detection is a group of events, and some of its
triggers may not be labelled positive — the failures that confirm a brute force, the benign
parent process, the surrounding enumeration binaries. The unit is one evidence ID, so only the
triggers M1/M6 label positive can be TPs; the rest are FPs unless labelled excluded. The call
should confirm this, because the alternative (scoring a whole detection window as one item) would
turn an unlabelled auxiliary event into a scored unit.

## The excluded category

M6 proposed this in `docs/M6_TO_M2_INTERFACE_NOTE.md` item 5. M2 agrees, with two parts:

* **Operator / scaffolding activity outside the declared scenario window.** M6's note measures
  that roughly half of each lab export is the operator's own session that verified and exported
  the logs (S02: 178 of 349 Security events; S03: 189 of 352). The normalised event carries
  `in_scenario_window`, derived from the neutral scenario metadata, so these events can be
  identified without any label work. A flagged event with `in_scenario_window == false` is a
  candidate for exclusion, and the call should adopt that rule if it agrees.
* **The runbook's own Security 1102 audit-log clear.** Each lab export holds exactly one, and
  R-LOG-01 fires on it in **every** scenario (see the baseline run in `M2_DETECTION_RULES.md`).
  It is a textbook T1070.001 indicator and a real artefact of the runbook, not of an attack. M6
  proposes treating it as scaffolding; M2 proposes labelling it `excluded` rather than deleting
  the rule, so the detection is visible and the choice is recorded.

Excluded events are **tallied separately and reported, never hidden**: the report carries
`flagged_excluded` (excluded events a rule flagged — the noise the exclusion is absorbing) and
`unflagged_excluded` (excluded events no rule flagged) for every scope, and they never enter
precision or recall. If the call prefers to count scaffolding as a false positive instead, that is
a definition change: the code takes the label as given, so the same corpus with scaffolding
labelled `negative` yields the stricter number. The two numbers should both be produced for the
report, and the call should say which one is headline.

## The label file M2 will read

The format M2 implements and tests. M1/M6 produce the file; M2 reads it and nothing else. The
evidence IDs below are synthetic — this document states no labels for any real event.

CSV, with a header row:

```csv
evidence_id,label,reason
SYN-SEC-1,positive,stage 3 interactive logon
SYN-SEC-3,negative,benign retry
SYN-SEC-6,excluded,operator session outside the scenario window
```

or JSON, either a list of objects or `{"labels": [...]}`:

```json
{
  "labels": [
    {"evidence_id": "SYN-SEC-1", "label": "positive", "reason": "stage 3 interactive logon"},
    {"evidence_id": "SYN-SEC-3", "label": "negative"},
    {"evidence_id": "SYN-SEC-6", "label": "excluded"}
  ]
}
```

Rules the loader enforces, so an ambiguous file fails closed instead of scoring something
unclear: `label` is exactly `positive`, `negative` or `excluded`; `reason` is optional; an
`evidence_id` that is not a well-formed evidence ID is rejected; the same `evidence_id` may not
appear twice; no other column or field is accepted.

Three checks make a mislabelled or partial input an error rather than a quietly wrong number:

* A label for a **scenario with no detection run** in the scored set is rejected. This needs no
  corpus, so it is never optional: without it, a scenario-ID typo in the label file would be
  scored as a new scenario full of false negatives.
* The label file is validated against **the corpus** (`python -m m2 score --corpus …`, which
  supplies the evidence IDs the corpus actually holds): a label naming an event the corpus does
  not hold is rejected, so a record-number typo cannot become a silent false negative.
* The run set must be **one corpus revision with one run per scenario**: two runs for one scenario
  (the per-scenario table would keep one while the per-rule table unioned both), or runs naming
  different `corpus_manifest_sha256` values, are rejected instead of merged.

## Worked example

Six example events and a label file, to pin the definitions before the call:

| evidence_id | label | flagged by |
|---|---|---|
| `SYN-SEC-1` | positive | R-AUTH-01 |
| `SYN-SEC-2` | positive | R-AUTH-01 |
| `SYN-SEC-3` | negative | R-AUTH-01 |
| `SYN-SEC-4` | *(not listed)* | R-AUTH-01 |
| `SYN-SEC-5` | positive | *(nothing)* |
| `SYN-SEC-6` | excluded | R-AUTH-01 |

flagged = `{1, 2, 3, 4, 6}` (5 events). TP = `{1, 2}` = 2. FP = flagged minus positive minus
excluded = `{3, 4}` = 2. FN = positive minus flagged = `{5}` = 1. `flagged_excluded` = 1,
`unflagged_excluded` = 0. precision = 2/4 = 0.5, recall = 2/3 ≈ 0.667, F1 = 0.571…
`m2/tests/test_metrics.py` pins the same arithmetic on a different fixture, including the
excluded-event tallies and the undefined-metric cases.

## Open questions for the call

1. **Security + Sysmon views of one action.** S02's 02:05:58 discovery activity appears twice —
   `S02-SEC-43662` (Security 4688) and `S02-SYS-25814` (Sysmon 1). At the event level they are two
   events and can be two TPs. Should one action count **once** (deduplicate the two channel views
   before scoring) or **twice** (score every event)? M2's position: the unit is the event, so
   twice, and any deduplication is a separate reported view — but this is a definitions question,
   not a code question.
2. **Is the benign-lookalike scenario scored at event level only?** If a scenario exists mainly to
   produce false positives, do its events enter the same precision pool, or are they reported
   separately? M2 has no rule that special-cases a scenario and will not add one without the call's
   decision.
3. **How are S01 events labelled?** S01 is a different host and year from S02/S03, so its
   `scenario_id`, its manifest shape and its timestamps differ, and M6's note says the record-ID
   collisions do not involve it. Is S01 in scope for the event-level metric, in scope with its own
   labels, or reported separately? Nothing in M2's code assumes an answer.
4. **Scaffolding as FP or as excluded?** M2 proposes `excluded` (tallied separately); the stricter
   alternative is `negative` (counted as FP). The call should pick the headline view.
5. **Is `F1 = None` when precision = recall = 0 the convention M1/M6 want?** Mathematically
   `2PR/(P+R)` is `0/0` there. M2 reports `null` for every metric with a zero denominator, and
   `F1` is left `null` whenever `P + R = 0`, so a rule with `TP = 0` and `FP > 0` (precision 0.0,
   recall 0.0) shows `F1 = null` rather than `0.0`. `null` means "not measured"; `0.0` would mean
   "measured and zero", which would put an undefined ratio into a per-rule table. The code follows
   the convention already; the call should confirm it, because it changes how those rows read.
6. **Per-rule recall is measured against the whole positive population.** Each rule's TP/FP/FN is
   computed over **all** positives, not over the positives that rule was "supposed" to find (M2 has
   no per-rule expected-population mapping). So per-rule recalls are shares of the same denominator:
   they are **not** additive, must not be summed, and are not comparable with the overall recall.
   The per-rule table is an attribution of flags, not a partition of the positives. If the call
   wants a per-rule "coverage" number instead, that needs an agreed mapping from positives to rules,
   which is a definitions decision and not something M2 will infer.
7. **Does M5 want the merged R-AUTH-02 span in the rationale?** A chained uncovered burst can be
   merged into one detection spanning more than the 300 s window, so the span is not implied by the
   threshold. M2 has added it to the rationale as `window_span_seconds=…`, exact to the 100 ns,
   without moving any detection ID (task_plan.md T5.0, amendment A2). The call should say whether M5
   needs the span as a **structured field** on the detection instead — that would be an additive
   schema change and is not done yet.

## What M2 will not do

* M2 will **not** locate, request or open the answer key or a private label file. It reads the
  label file it is given and nothing else.
* M2 will **not** score the real baseline until this proposal is agreed and a labels file path is
  provided (task T4.3 is BLOCKED with that unblock condition).
* M2 will **not** tune a threshold or a rule to change a metric. Thresholds are frozen constants;
  a change is a rule change with a version bump, justified in the progress log.
* M2 will **not** report a precision, recall or F1 from this document. There are no numbers here
  because there are no agreed labels, and inventing an example on real evidence IDs would be
  exactly the contamination the blind-design rule forbids.
