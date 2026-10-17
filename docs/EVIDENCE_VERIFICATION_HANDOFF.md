# Evidence Verification & Evaluation handoff

## Owner

Evidence Verification & Evaluation

## Locations

### Verifier (connects to the orchestrator)
- evidence_verification/verifier.py (`make_verifier`: deterministic checks)
- evidence_verification/agent.py (`make_agent_verifier`: deterministic checks plus the model layer)
- evidence_verification/checks.py, evidence_verification/facts.py

### Evaluation
- evidence_verification/evaluation/ (scoring harness)
- docs/EVALUATION_PROTOCOL.md (definitions and parameters, fixed before any scored run)
- scripts/run-evaluation.ps1 (the whole comparison, end to end)

### Documentation
- evidence_verification/README.md

## Intended Handoffs

Incident Reconstruction Orchestrator:
- Connect the verifier with `--mode full --verifier evidence_verification.verifier:make_verifier`, or
  `evidence_verification.agent:make_agent_verifier` for the model layer (set `MAIR_VERIFIER_LLM` to `ollama`).
- One `VerificationDecision` per claim in the existing `verification-report-v1` format, unchanged from the
  contract in `incident_reconstruction/verification.py`. No schema change.
- Displayed unchanged: a verdict is never discarded, downgraded or overridden. A disagreement is raised as an
  interface issue, not resolved by editing the verdict.

Whole team:
- Verdict definitions below are the ones scored.
- Results and comparison tables follow from `scripts/run-evaluation.ps1`.

## What the verifier needs from a claim

- `evidence_ids` and `context_evidence_ids` must be scenario-scoped (`<scenario>-SEC|SYS-<record>`). Record
  numbers repeat across scenarios, so an unscoped or cross-scenario reference cannot be verified and is rejected.
- `claim_id` stable for a given run, so decisions join back to claims.
- For the structural check, `claim_type` from the orchestrator's catalogue. A free-form type gets the generic
  checks only.

## Verdicts

| Verdict | Meaning | Grounds |
|---|---|---|
| `confirmed` | supported as stated | no check failed |
| `partially_supported` | the core activity is shown; a secondary assertion is not | a time, entity, stated event type, technique, link or ordering failed |
| `unverified` | references resolve but the cited records do not show the claimed activity | the claim-type structure check failed |
| `rejected` | a reference is malformed, absent or from another scenario, or evidence contradicts the claim | a reference failed or a host or span is contradicted |

`confirmed` is not a judgement that the activity is malicious: a benign lookalike whose records are real and as
described is confirmed. `unverified` is a limit of the cited records, not necessarily a fault in the claim;
`rejected` means the claim cited something that does not exist or is wrong.

## Important Boundary

The verifier receives claims and read-only corpus access only: no orchestration trace, agent reasoning,
detection label or answer key. It resolves every reference itself and never trusts an identifier, time or entity
a claim supplies. The model layer sees the claim and the records the verifier retrieved, never the
reconstruction's rationale or its own assessment, can only lower a verdict, and can never reject. If the model is
unavailable the deterministic verdict stands and says so.

The evaluation reads the private ground truth only after a run is written and never modifies it.

## Validation

Run:

    python -m pytest evidence_verification/tests -q

Expected: all tests pass; the real-corpus module skips when the EVTX exports are not present.

To exercise the whole comparison:

    powershell -ExecutionPolicy Bypass -File scripts/run-evaluation.ps1

## Change Control

The verifier and protocol are frozen before scored runs. A change after that is a dated amendment in
docs/EVALUATION_PROTOCOL.md, never an edit in place. A change to the decision fields or verdict values is an
interface change: update the orchestrator contract, the tests and this document together, and tell the
Incident Reconstruction Orchestrator owner first.

## Time Standard

All timestamps are UTC with full 100 ns precision preserved.
