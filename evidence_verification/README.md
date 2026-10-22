# Evidence Verification & Evaluation

Two jobs, kept apart on purpose:

* **Verify** (`verifier.py`, `agent.py`, `checks.py`): decide whether the claims a reconstruction makes are
  supported by the recorded events. Plugs into the orchestrator's `--verifier` hook. Never reads an answer key.
* **Evaluate** (`evaluation/`): score written runs against the private ground truth and compare the four
  configurations. The only code that reads `ground_truth/`, and only after a run has been written.

The scoring rules are fixed in [`docs/EVALUATION_PROTOCOL.md`](../docs/EVALUATION_PROTOCOL.md) before any
scored run.

## Use it

```powershell
# Full MAIR with the deterministic verifier only (no model needed):
python -m incident_reconstruction --corpus out/corpus --llm ollama --mode full --out out/runs `
    --verifier evidence_verification.verifier:make_verifier

# Full MAIR with the deterministic verifier plus the independently prompted model layer:
$env:MAIR_VERIFIER_LLM = "ollama"      # or "fake" for plumbing; there is deliberately no default
python -m incident_reconstruction --corpus out/corpus --llm ollama --mode full --out out/runs `
    --verifier evidence_verification.agent:make_agent_verifier

# Score every written run against the private key:
python -m evidence_verification.evaluation --corpus out/corpus --runs out/runs `
    --detections out/detections --out out/evaluation-corrected `
    --claim-reviews out/review/claim_reviews.json --scoring-contract out/review/scoring_contract.json
```

`MAIR_VERIFIER_MODEL` (default `qwen3:8b`), `MAIR_VERIFIER_NUM_CTX` (8192) and `MAIR_VERIFIER_TIMEOUT` (180 s)
tune the model layer; temperature 0, seed 0 and thinking off are fixed to match every other model role.

## How a claim gets a verdict

The verifier resolves every cited and context ID through `EventStore.lookup` itself, so it never trusts an
identifier, time or entity a claim supplies. Each check has a grade, and the verdict is the worst failed grade:

| Grade of a failed check | Verdict | Meaning |
|---|---|---|
| `reject` | `rejected` | a reference is malformed, absent, or from another scenario; or the evidence contradicts the claim |
| `insufficient` | `unverified` | every reference resolves, but the cited records do not show the activity the claim names |
| `partial` | `partially_supported` | the core activity is shown, but a time, entity, event type, technique, link or ordering is not |
| none failed | `confirmed` | supported as stated |

`confirmed` is **not** a judgement that the activity is malicious. A benign lookalike whose records are real
and as described is confirmed.

| Check | Catches |
|---|---|
| `reference_resolves` | fabricated, malformed or cross-scenario references (record numbers repeat across scenarios) |
| `span_is_valid`, `span_endpoints_recorded`, `cited_events_inside_span` | a claim whose stated times the records do not attest |
| `entities_recorded`, `host_agrees` | an account, host, process, GUID or file no record names; a host the evidence contradicts |
| `text_*` | a stated time, event type, file/process name or failed-logon count that the cited records do not show |
| `claim_type_structure` | cited records that are real but do not show the claimed activity (known claim types only) |
| `attack_*` | a technique marked `supported` with no defining observable, or `tentative` with no consistent one |
| `link_*`, `timeline_order` | a claimed shared account, process or lineage the records do not show; claims out of order |

## The model layer can only lower a verdict

`agent.py` adds an independently prompted model, consulted only for claims the deterministic checks confirmed.
The host partitions the claim into clauses without dropping any non-whitespace text, including causal and
purpose clauses. The model sees the whole claim and judges every clause against complete source facts.
Each metadata/event-data value has a host-assigned fact ID bound to its original record. The model selects
those IDs and gives a short source summary before marking support; it cannot rewrite or omit an inconvenient clause.
Multiple facts can jointly support arithmetic, chronology and compound observations.

**Code maps the model's support assessments to verdicts.** All clause keys must occur exactly once;
supported/partial clauses need valid source fact IDs. Repeated citations add no weight and are normalized
as a set. Unknown IDs, invented quote fields and missing
clauses fail validation. Valid provenance does not establish semantic correctness: the model can still
misjudge a fact's relevance. Any unsupported/partial clause lowers `confirmed` to `partially_supported`;
if no clause has support, to `unverified`.

Its prompt holds the claim's text, type, stated span, entities and technique IDs plus the records the verifier
retrieved. It never holds the reconstruction's rationale, its own assessment, its uncertainty notes, detection
or finding IDs, links, an orchestration trace, agent reasoning or any answer key.

It can never raise a verdict and can never reject, because rejection needs a failed reference or a contradiction
that code has verified. If the model is unavailable, its reply is invalid, or complete evidence cannot fit,
the result is explicitly `unverified` with `verification_incomplete`; this is an operational limitation,
not evidence that the claim is false. A verifier's judgement is never its own ground truth.

Verifier version 3 defaults to prompt v5 with the indexed-fact reply contract. Every referenced record and every event-data field is retained;
there is no 14-record cap or field clipping. Event-type labels explain the source IDs without adding
an attack interpretation. The complete prompt must fit both serialization and token budgets. Historical
v2/v3/v4 prompt text remains selectable; reproducing historical behavior requires its Git revision too.
Legacy v4 uses contiguous copied spans. The v5 contract has one format-only repair attempt after an invalid
reply, with no expected verdict supplied. Runtime/context failures are not retried. Metadata records every
actual model call and `agent_format_retries`; failed repair is an operational abstention. Independent
annotations measure semantic judgments separately.

When the ordinary view overflows, v5 first keeps complete in-span records together and groups the context.
If that cannot fit, it groups all identical field/value pairs with explicit record indices,
preserving every original value and distinguishing metadata from same-named event-data fields.
Each group states exactly which records contain that value; absent fields stay absent.
Exact source computations provide counts and elapsed times for records whose metadata timestamps fall
inside the claim's stated span, without claim-support labels. Cited records may themselves include context
outside that span. Activity and its stated span remain distinct from contextual
records and file-internal timestamps. Overflow after compression still abstains explicitly.
Compact replies summarize source fields before selecting proof IDs; their decoder requires a nonempty
proof list for supported/partial assessments. Every format chooses the support label last.

## Corrected comparison workflow

Use `scripts/run-evaluation.ps1 -Out out/corrected-01` to generate fresh four-configuration artifacts. The script
defaults to generation only. Put Dataset & Ground Truth Management's private files under `ground_truth/private/` as described in
[`ground_truth/README.md`](../ground_truth/README.md), then generate unanswered review forms:

```powershell
python -m evidence_verification.evaluation.prepare_review --corpus out/corrected-01/corpus `
    --runs out/corrected-01/runs --ground-truth ground_truth/private --out out/corrected-01/review
```

An independent reviewer fills each claim's support label, notes, and correct stage IDs after reading the
original records and lab key. Dataset, detection and evaluation owners complete the scoring contract.
Neither command invents approvals or labels. Use those files with the scoring command above, pointing it
at the same corpus/runs/detections. `--allow-partial` is diagnostic only; `--allow-fake` additionally labels
simulated models as plumbing. Final scoring checks the full scenario/configuration matrix, identical real
model profiles, corpus and trigger hashes, current implementation, exact artifact contents and reviews.

Evidence overlap is labelled alignment/coverage. Semantic correctness comes only from the separate
claim reviews. Review and contract fingerprints include the private CSVs and `scoring_exclusions.json`.

To see every input that is still missing, with its owner, before scoring:

```powershell
python -m evidence_verification.evaluation.readiness --root out/corrected-01
```

It reports READY only after the scorer itself has accepted the inputs in a throwaway directory. The
remaining inputs and their order are in [`docs/FINAL_EVALUATION_HANDOFF.md`](../docs/FINAL_EVALUATION_HANDOFF.md).

### Blind review of a component run

`component_review` checks a set of claims, such as the real-corpus template claims, without the answer key and
outside the four-configuration score. `prepare` shuffles every claim under a neutral code. It writes a reading packet of
claim text and cited/context records, an unanswered label form and a sealed code-to-claim mapping. It never
shows claim IDs or verdicts. After a named reviewer has labelled every assertion and claim, `score` checks
that the claims, corpus and packet are unchanged. It then unblinds the codes and compares each label with the
verifier's recorded verdict, using outcome rules printed in the packet before labelling: justified, false
alarm, correct, missed or unresolved. A human labelling blind records `blind_human_review`. A model other than
the verifier's records `model_review` and must disclose what it knew beforehand. The 2026-10-20 review of the
real-corpus template claims is a model review: [`docs/SEMANTIC_CLAIM_REVIEW.md`](../docs/SEMANTIC_CLAIM_REVIEW.md).

```powershell
python -m evidence_verification.evaluation.component_review prepare --corpus <corpus> --runs <runs> --out out/semantic-review
python -m evidence_verification.evaluation.component_review score --packet out/semantic-review --corpus <corpus> `
    --runs <runs> --verdicts docs/validation/correctness-2026-10-20.json --out out/semantic-review-result
```

An opt-in test measures the layer on 14 synthetic claims that all pass the deterministic checks (6 faithful, 8
embellished), because only the model layer can catch an embellishment:

```powershell
$env:MAIR_TEST_VERIFIER_OLLAMA = "1"; python -m pytest evidence_verification/tests/test_agent_live.py -q
```

## Tests

```powershell
python -m pytest evidence_verification/tests -q
```

Each verifier test breaks one thing in an otherwise supported claim and asserts the verdict and the check that
caught it. The record-number collision between two real scenarios is tested on the real corpus (skipped when
the EVTX exports are not present, like the other corpus tests). The harness tests use a made-up key over
synthetic events; the real answer key appears in no test.

## Limits

* Structural checks cover the claim types the orchestrator produces. A free-form type from the single-agent
  baseline gets the generic checks only.
* The model layer sees retrieved records; it runs no free-form queries of its own.
* The verifier judges support, not truth. A fully supported claim can still describe activity the key does not
  attribute to any stage; the evaluation reports both.
