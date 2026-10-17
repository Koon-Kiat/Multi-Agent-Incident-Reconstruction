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
    --detections out/detections --out out/evaluation
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
The deterministic checks cannot read a sentence; the model does exactly one job: split the claim into its
separate assertions and, for each, name the retrieved record that states it and copy the words. A claim's
embellishments (an intent, a cause, a consequence, an extra detail) are precisely what records fail to state.

**The model never decides the verdict; code does.** An assertion counts as shown only if the model cites a
record it was actually shown and quotes words that appear in it. Naming no record, or quoting words the record
does not contain, leaves it not shown. An assertion the model added that is not about the claim is ignored. Any
not-shown assertion lowers `confirmed` to `partially_supported`; if none is shown, to `unverified`.

Its prompt holds the claim's text, type, stated span, entities and technique IDs plus the records the verifier
retrieved. It never holds the reconstruction's rationale, its own assessment, its uncertainty notes, detection
or finding IDs, links, an orchestration trace, agent reasoning or any answer key.

It can never raise a verdict and can never reject, because rejection needs a failed reference or a contradiction
that code has verified. If the model is unavailable or replies invalidly, the deterministic verdict stands and
says so. A verifier's judgement is never accepted as its own ground truth.

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
