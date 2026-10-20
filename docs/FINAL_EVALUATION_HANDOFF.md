# Final A/B/C/D evaluation: handoff checklist

Recorded 2026-10-20. **No final score exists.** This document lists every remaining input, who supplies it and
the order of work. It does not supply or assume any of them: no answer key, review label or owner approval is
derived from detections, model claims or verifier verdicts. The rules are in `EVALUATION_PROTOCOL.md`
Amendment 4; the gate is `evidence_verification.evaluation` (the scorer).

## Check what is still missing

```bash
python -m evidence_verification.evaluation.readiness --root out/final-01
```

`--root` is the folder `scripts/run-evaluation.ps1 -Out` writes. The report names each missing input and its
owner, and says READY only after the scorer itself has accepted every input in a throwaway directory. On
2026-10-20, run against a fresh corpus with no comparison runs, it reported: corpus and configuration A
ready (6,661 events, 38 detections); answer key, runbooks, the nine B/C/D runs, claim reviews and scoring
contract missing.

## Inputs and owners

| # | Input | Owner | Status on 2026-10-20 |
|---|---|---|---|
| 1 | `S01/S02/S03_ground_truth.csv` in `ground_truth/private/` (format in `ground_truth/README.md`), optional `scoring_exclusions.json` | Dataset & Ground Truth Management | Not in the repository; never committed |
| 2 | Original scenario runbooks in `runbooks/private/` | Dataset & Ground Truth Management | Not in the repository; never committed |
| 3 | `EVALUATION_PROTOCOL.md` section 12 items 1, 2, 4 and 9, and the scoring exclusions | Dataset & Ground Truth Management | Proposed; item 1 confirmed by the engine only |
| 4 | Section 12 items 3, 5, 6 and 7 | Event Processing & Detection Engine | **Agreed** 2026-10-19 |
| 5 | Section 12 item 8, the single-agent tool budget | Incident Reconstruction Orchestrator | Awaiting confirmation |
| 6 | Fresh runs of configurations A, B, C and D on one model profile | Whoever runs the comparison | Not run on the current implementation |
| 7 | Independent claim support and stage annotations for every claim of every B/C/D run | An independent reviewer | Not started; needs 1 and 6 |
| 8 | Scoring contract with `negative_population_reviewed` and all three approvals | Dataset, detection and evaluation owners | Not started; needs 1 and 3 |

## Order of work

1. **Freeze the implementation.** Merge every pending code change first. The scorer binds each run to the
   implementation fingerprint, so any later change to `event_processing`, the agents, `incident_reconstruction`
   or `evidence_verification` makes existing runs stale and forces a rerun.
2. **Run A/B/C/D** on the merged commit with a clean tree, without `-AllowDirty`. Use the same machine, Ollama
   installation and model as the corrected-code development runs: Ollama 0.34.4, `qwen3:8b` digest
   `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`, context 8192, temperature 0, seed 0,
   thinking off. The script never downloads weights.

   ```powershell
   ./scripts/run-evaluation.ps1 -Out out/final-01
   ```

   This needs no answer key and can run before it arrives. The script is Windows-only; elsewhere, run the
   `python -m` commands it lists with identical arguments. Every active role across B, C and D must share one
   model profile, or the scorer refuses the set.
3. **Deliver the answer key and runbooks** (inputs 1 and 2). Changing either file later invalidates every
   review and approval bound to it.
4. **Generate the unanswered forms** once inputs 1 and 6 exist:

   ```powershell
   ./scripts/run-evaluation.ps1 -Out out/final-01 -Only review
   ```

5. **Independent claim review** (input 7). Someone who did not build the verifier or the reconstruction labels
   each claim in `review/claim_reviews.json` against the original records and the answer key: support, the stage
   IDs it correctly describes and a note. They set `reviewer` and `independent_of_verifier: true`. Partial and
   uncertain labels stay as they are; they are never rounded to supported or unsupported.
6. **Scoring contract** (inputs 3, 5 and 8). Each owner fills their own `approved_by` entry in
   `review/scoring_contract.json`. Dataset & Ground Truth Management confirms the negative population review.
   No entry is filled on another owner's behalf.
7. **Check, then score into a new folder:**

   ```bash
   python -m evidence_verification.evaluation.readiness --root out/final-01
   ```

   ```powershell
   ./scripts/run-evaluation.ps1 -Out out/final-01 -Only score `
       -ClaimReviews out/final-01/review/claim_reviews.json `
       -ScoringContract out/final-01/review/scoring_contract.json
   ```

## What a final score will and will not establish

A scored run measures one execution of each configuration on three lab scenarios against one answer key. It
will not establish:

* **Optimal authentication query efficiency.** The capped-prefix runs that showed useful follow-up selection
  used all seven optional queries. Optimal stopping and unrestricted autonomous planning are not established
  (`CORRECTNESS_REMEDIATION.md`).
* **Generalization beyond the development cases.** The synthetic cases and reused benchmarks are regression
  evidence. They are not an independent held-out evaluation.
* **Repeatability.** Repeated development runs varied, and a single run per configuration does not measure
  that variation.

## Related

* The verifier's lowered real-corpus claims have a separate blind review, which is not part of the A/B/C/D
  score: `component_review` in `evidence_verification/evaluation/`.
* `ground_truth/README.md` and `runbooks/README.md`: where the private inputs go and who may read them.
