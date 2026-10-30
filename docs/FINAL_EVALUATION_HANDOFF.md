# Final evaluation workflow

Use this checklist for a new comparison on the current implementation. Readiness
is specific to the selected output directory; an old status table or diagnostic
run does not establish that a new comparison is complete. The authoritative
definitions and approval requirements are in [protocol Amendment 4](EVALUATION_PROTOCOL.md#13-amendment-4-corrected-code-comparisons).

## Check the selected run

```powershell
python -m evidence_verification.evaluation.readiness --root out/final-current
```

The command exits 0 only when every prerequisite passes and the scorer accepts
the inputs in a temporary directory; 1 means missing or invalid inputs, and 2
means invalid arguments. `--json` emits structured gates. Override private input
locations with `--ground-truth` and `--runbooks`, or review locations with
`--claim-reviews` and `--scoring-contract`.

## Inputs and responsibilities

| Input | Supplied or completed by |
| --- | --- |
| Verified corpus and rules-only detections for every scenario | Comparison operator |
| Original ground-truth CSVs and any contextual exclusions | Dataset & Ground Truth Management |
| Original private runbooks | Dataset & Ground Truth Management |
| All nine scenario/mode runs, bound to the current implementation and one real model profile | Comparison operator |
| Claim support, correct stage IDs and review notes for every claim | Independent human reviewer |
| Negative-population review and dataset, detection and evaluation approvals | Respective owners |

Put the original private inputs in [ground_truth/private](../ground_truth/README.md)
and [runbooks/private](../runbooks/README.md). These directories are ignored by Git.
Do not derive missing inputs from detections, model output or verifier verdicts.
AI preliminary labels and model component reviews cannot replace human review.

## Generate, review and score

1. Freeze the implementation and commit reviewed changes before final generation.
   Select a new output directory; never overwrite historical runs. Python source
   changes under any runtime package change the implementation fingerprint and
   require fresh runs and reviews. Keep the recorded protocol and runtime profile
   with the resulting artifacts.
2. Install dependencies into `.venv` and fetch the public Git LFS evidence as in
   the [root setup guide](../README.md). The PowerShell wrapper uses
   `.venv/Scripts/python.exe`. Start the intended local Ollama runtime with the
   model already installed, or pass `-OllamaExe` if the wrapper must start it.
   The wrapper never downloads weights. All active model roles must use one
   model/digest, runtime and temperature/seed/context/thinking profile. Record a
   changed runtime as a separate experiment; do not silently mix historical profiles.

   ```powershell
   ./scripts/run-evaluation.ps1 -Out out/final-current
   ```

   The default stages are `prep`, `generalist`, `specialist` and
   `verified-specialist`. They generate corpus, detections and runs only. Use
   `-Only generalist,specialist,verified-specialist` when the fresh prep outputs
   already exist. Incomplete pipeline results remain visible and must be resolved
   or reported diagnostically before final scoring.
3. Once the private key and runs exist, generate unanswered forms:

   ```powershell
   ./scripts/run-evaluation.ps1 -Out out/final-current -Only review
   ```

4. An independent human reviewer completes `review/claim_reviews.json` against
   original records and the key, including their identity and independence
   declaration. Retain partial and uncertain labels. Each owner completes their
   own approval in `review/scoring_contract.json`; the dataset owner confirms
   the negative population and contextual exclusions. Never fill these on
   another person's behalf. Forms bind the exact key and run contents.
5. Run readiness, then score using the same root:

   ```powershell
   python -m evidence_verification.evaluation.readiness --root out/final-current
   ./scripts/run-evaluation.ps1 -Out out/final-current -Only score `
       -ClaimReviews out/final-current/review/claim_reviews.json `
       -ScoringContract out/final-current/review/scoring_contract.json
   ```

The wrapper refuses to overwrite a stage's output. `-AllowDirty` is for documented
development runs. `-AllowPartial` produces diagnostic output, never a final score.
Use the Python module entry points in [the verifier manual](../evidence_verification/README.md)
outside Windows, preserving the same inputs and settings.

## Interpretation

A completed comparison measures these three scenarios under one profile. It does
not establish generalization, run-to-run repeatability, optimal query efficiency
or unrestricted model autonomy. Evidence alignment is distinct from independently
reviewed semantic correctness. Keep failed attempts and limitations alongside
successful outputs. Dated component measurements are indexed in
[documentation history](README.md#historical-reports-and-evidence).
