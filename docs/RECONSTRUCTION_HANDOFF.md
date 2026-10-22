# Reconstruction and run-mode handoff for Evidence Verification & Evaluation

This note is for the owner of Evidence Verification & Evaluation. It covers what the Incident
Reconstruction Orchestrator and Reconstruction Agent produce, how to connect the verifier, and
what the three run modes hold constant for scoring. Module details are in the
[package README](../incident_reconstruction/README.md).

## What you receive

Each run writes to `<out>/<mode>/`, one set of files per scenario:

| File | Schema | Contents |
| --- | --- | --- |
| `<scenario>.reconstruction.json` | `reconstruction-v1` | Ordered claims; the unit you verify and score |
| `<scenario>.pipeline.json` | `pipeline-run-v1` | Mode, model, per-phase seconds, total latency, model calls, claim and verdict counts |
| `<scenario>.orchestration.json` | `orchestration-run-v1` | Multi-agent and full only: windows, agent results, coverage |
| `<scenario>.verification.json` | `verification-report-v1` | Full only: your decisions, stored unchanged |
| `<scenario>.report.html` | — | Human-readable timeline with evidence and verdicts |

Load them with the package models so a malformed file fails loudly:

```python
from incident_reconstruction import Reconstruction
from incident_reconstruction.pipeline import PipelineSummary
from incident_reconstruction.verification import VerificationReport

claims = Reconstruction.model_validate_json(open("out/runs/full/S02.reconstruction.json", encoding="utf-8").read()).claims
```

## The claim contract

| Field | Meaning |
| --- | --- |
| `claim_id` | `<scenario>-CLM-<nn>`; stable for a given orchestration run, so decisions join back to claims |
| `position` | 1..n in time order (first cited event) |
| `claim_type` | Stage label, e.g. `failed_logons_then_success`, `discovery_commands`, `payload_written` |
| `claim_text`, `rationale` | What was observed and why the records belong together |
| `assessment` | The reconstruction's own reading: `requires_review`, `benign_possible`, `insufficient_evidence`. Not a verdict |
| `first_utc`, `last_utc` | Stage span, canonical 7-digit UTC |
| `entities` | Accounts, hosts, process images and GUIDs, files |
| `evidence_ids` | The records the claim text relies on |
| `context_evidence_ids` | Every record the stage was built from; `evidence_ids` is always a subset |
| `detection_ids`, `supporting_finding_ids` | The detections and agent findings the stage came from (may be empty for single-agent claims) |
| `attack` | Tentative ATT&CK mappings: `technique_id`, `status` (`supported` / `tentative` / `uncertain`), `justification`, `evidence_ids` |
| `related_claims` | Links to other claims with the reason (shared account, same process, process lineage) |
| `uncertainty` | Gaps that affect this claim (failed or truncated investigations, template text) |
| `narrative_source` | `model`, or `template` when the model reply failed host checks |
| `verification_status` | Always `not_verified`; your report carries the verdicts |

Every evidence ID resolves through `EventStore.lookup` on the same corpus. Claims never contain
answer-key material, and nothing in the pipeline reads `ground_truth/`.

## Connecting the verifier

A verifier is any object with two methods:

```python
from incident_reconstruction.verification import VerificationDecision

class EvidenceVerifier:
    def metadata(self) -> dict:
        return {"verifier": "evidence-verifier", "version": "1"}

    def verify(self, reconstruction, store):
        for claim in reconstruction.claims:
            missing = [e for e in claim.evidence_ids if store.lookup(e).event is None]
            yield VerificationDecision(
                claim_id=claim.claim_id,
                verdict="rejected" if missing else "unverified",   # confirmed | partially_supported | unverified | rejected
                reason="cited evidence does not exist" if missing else "deterministic checks passed; not yet judged",
                checked_evidence_ids=tuple(claim.evidence_ids),
                conflicts=tuple(missing),
            )

def make_verifier():
    return EvidenceVerifier()
```

Run it with `--mode full --verifier your_package.module:make_verifier`. The factory is called
with no arguments. The verifier receives the claims and read-only corpus access only: no
orchestration trace, agent reasoning or answer key. To re-verify saved runs without dispatching
the agents again, add `--reconstruct-only`.

The pipeline guards integrity but never changes a verdict:

* a claim with no decision becomes `unverified` with reason `no_decision_returned`;
* a decision for an unknown claim, or a second decision for one claim, is set aside;
* a verifier that raises, or returns something other than `VerificationDecision`, leaves every
  claim `unverified` with `verifier_failed:<Type>`;
* each case is listed in `integrity_notes`, and the CLI exits `1`.

Until the verifier is connected, `PendingVerifier` marks every claim `unverified` with reason
`independent verifier not connected`, and the report says verification is pending.

## Run modes for the comparison

| `--mode` | Configuration | Phases timed |
| --- | --- | --- |
| *(Event Processing & Detection Engine `detect`)* | Rules-only Detection Baseline | — |
| `single-agent` | Single-Agent Generalist Baseline | detection, single_agent |
| `multi-agent` | Specialist-Agent Incident Reconstruction | detection, investigation, reconstruction |
| `full` | Specialist-Agent Incident Reconstruction with Independent Evidence Verification | detection, investigation, reconstruction, verification |

Held constant across the generalist and both specialist approaches: corpus revision (`corpus_manifest_sha256` in every file), the
detection triggers, the read-only providers and limits, the local model and its settings
(temperature 0, seed 0, context 8192, thinking off), and the timing points. The clock starts
immediately before triggers are read and stops after the last phase. The single-agent baseline
has a 16-call tool budget by default (`--single-agent-tool-calls`); agree the value before scored
runs. Latency depends on hardware: run every scored configuration on one machine and record it.

Scoring notes:

* Claims are the unit for evidence-support rates. Single-agent claims have
  `context_evidence_ids == evidence_ids`; multi-agent claims also carry stage context.
* `uncertainty` and `investigation_gaps` record why evidence may be incomplete; keep them in
  error analysis rather than treating missing claims as clean scenarios.
* Fake-model runs (`"runtime": "fake"` in `llm`) check plumbing only and must not be scored.

## Commands

```powershell
python -m event_processing normalise --datasets datasets --out out/corpus
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode single-agent --out out/runs
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode multi-agent --out out/runs
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode full --out out/runs --verifier your_package.module:make_verifier
python -m incident_reconstruction.report --corpus out/corpus --runs out/runs
```

Exit codes: `0` complete; `1` written but incomplete (an investigation window stayed unresolved,
the single-agent run ended early, or the verifier failed); `2` invalid input; `3` model or
verifier setup failed.

## Known limitations

* No scored run has used local weights yet; all current outputs come from deterministic fake
  models.
* Historical runs on the original endpoint agent had two unresolved S02/S03 context windows.
  The endpoint-only [2026-10-18 correction](ENDPOINT_CONTEXT_COVERAGE.md) batches model review
  and recovers capped retrieval within existing budgets. Historical run records remain unchanged;
  rerun investigations to use the correction. Retrieval caps, oversized individual observations
  and model/deadline failures remain explicit limitations.
* R-FILE-01 fires on PowerShell's own `__PSScriptPolicyTest_*.ps1` files in S02 and S03, a likely
  benign lookalike; the reconstruction keeps it as a claim for the verifier and scorer to judge.
