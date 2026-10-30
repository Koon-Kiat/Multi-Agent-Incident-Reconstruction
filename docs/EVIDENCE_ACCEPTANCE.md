> **Historical acceptance record (2026-09-21).** The package assessment and open
> actions below apply to that delivery. Use the [current evaluation workflow](FINAL_EVALUATION_HANDOFF.md)
> and readiness command for a selected run; this record is not a scoring approval.

# Evidence Verification & Evaluation Ground-Truth Acceptance

## Owner

Evidence Verification & Evaluation - Evidence Verification & Evaluation Engineer

## Status

**ACCEPTED** - the Dataset & Ground Truth Management private ground-truth package is accepted as the evaluation
answer key for S01-S03, with the interface actions and documented limitations
below.

Date of verification: 2026-09-21
Package verified: the archived ground-truth evidence handoff.

This document is public to the team. It deliberately contains **no** expected
labels and **no** stage-to-record mappings. Those remain in
`ground_truth/private/`, which is gitignored and withheld from Event Processing & Detection Engine/Authentication Investigation Agent/Endpoint Investigation Agent/Incident Reconstruction Orchestrator.

> **Human-facing document - exclude from agent context.** The discussion of
> evaluation gaps below cannot describe which capability is untested without
> implying something about a scenario's character. Investigation agents receive
> `datasets/` only: raw telemetry and neutral metadata. Nothing in `docs/` is
> agent input, and this file in particular must never be placed in an agent's
> context window or retrieval corpus.

## Acceptance Criteria

### 1. Private ground-truth package received - MET

The package was received and contains all nine expected files: three
ground-truth tables, three scenario runbooks, S01 curation notes, the Dataset & Ground Truth Management
scenario plan and the private README.

All three ground-truth tables carry the full agreed column set required by the
`Ground-truth record (Dataset & Ground Truth Management -> Evidence Verification & Evaluation only)` interface contract: `scenario_id`,
`stage_id`, `stage_order`, `time_utc`, `actual_activity`, `actor`, `host`,
`expected_label`, `security_record_ids`, `sysmon_record_ids`,
`mitre_technique`, `notes`.

The package is staged locally at `ground_truth/private/`. It is confirmed
untracked by git and excluded by `.gitignore`.

### 2. Stages can be mapped to Event Record IDs - MET

Verified mechanically, not by inspection. Every Event Record ID cited by the
answer key was resolved against the public EVTX evidence that the investigation
agents will receive.

| Measure | Result |
|---|---|
| Scenarios | 3 |
| Ground-truth stages | 13 |
| Event Record IDs cited | 34 |
| Event Record IDs resolved to a real event | 34 |
| Unresolved / fabricated references | 0 |
| Stages citing no evidence | 0 |
| Timestamp mismatches against the cited record | 0 |
| Host mismatches against the cited record | 0 |
| SHA-256 mismatches against the manifests | 0 |

Beyond existence, each cited record was inspected to confirm it is the event the
answer key describes - correct Windows Event ID, correct account, correct
process image or target filename, and a coherent parent/child chain where the
stage claims one. The mapping is sound in both directions.

Reproduce with:

```bash
powershell -ExecutionPolicy Bypass -File scripts/verify-ground-truth.ps1
```

### 3. Scenario set is sufficient for evaluation - MET, with recommendations

The set satisfies the agreed scope of two multi-stage incidents plus one benign
lookalike, and all four evaluation configurations (Rules-only Detection Baseline, Single-Agent Generalist Baseline,
Specialist-Agent Incident Reconstruction, and Specialist-Agent Incident Reconstruction with Independent Evidence Verification) can run against it unchanged.

Both telemetry channels are present and parseable in all three scenarios.
One scenario exercises the Authentication Agent and the Endpoint Agent jointly,
giving Incident Reconstruction Orchestrator a genuine cross-source correlation to get right. One scenario provides
a deep endpoint artifact chain. One provides the benign lookalike needed to
measure false positives on the authentication path.

It is sufficient to proceed. Three limitations are recorded in
`## Documented Limitations` below; one optional additional recording is
recommended but is **not** a blocker.

## Tooling Delivered

| Path | Purpose |
|---|---|
| `scripts/verify-ground-truth.ps1` | Deterministic evidence validator. Seven checks; exits non-zero on any failure. Emits machine-readable JSON with `-JsonOut`. |
| `scripts/test-verify-ground-truth.ps1` | Negative tests. Injects known faults into a throwaway copy of the answer key and asserts the validator catches each one. |

The validator checks: dataset integrity against the manifests; ground-truth
schema; stage-to-record resolution; event-type, host and timestamp consistency;
stage ordering and chronology; scenario-window containment; cross-scenario
record-ID uniqueness; and answer-key containment.

The negative tests currently assert detection of a nonexistent record ID,
timestamp drift, host mismatch, an evidence-free stage and broken stage
ordering, and that unmodified ground truth still passes. All six pass.

Neither script modifies the datasets or the answer key.

## Action Required From Other Members

### A1 - Event Processing & Detection Engine: evidence_id must be scoped per scenario (blocking for Event Processing & Detection Engine)

Windows Event Record IDs are **not unique across the MAIR corpus**. The two lab
scenarios were recorded from the same VMware snapshot, so Windows restarted
record numbering from the same point in each. The Security channel shares 335
record IDs between them and the Sysmon channel shares 1526.

These are not duplicate events - the same number denotes a completely different
event in each scenario. A claim citing a record number alone will silently
resolve to the wrong evidence, which is precisely the failure the shared
evidence-ID contract exists to prevent.

`evidence_id` must therefore be derived from **scenario + channel + record ID**,
for example `S02-SEC-<record_id>`, not from the record ID alone. The validator now
reports this collision as a standing warning so the constraint cannot be
forgotten.

Evidence Verification & Evaluation will reject any claim whose evidence reference cannot be resolved to exactly
one event in exactly one scenario.

### A2 - Dataset & Ground Truth Management: manifest schema differs between scenarios (non-blocking)

`S01/metadata/manifest.json` uses `schema_version`, `generated_at_utc`,
`file_count`, `relative_path` and `source_channel`. The S02 and S03 manifests
use `collection_time_utc`, `collection_host`, `source` and `channel`, and carry
no `schema_version`.

Both satisfy the minimum fields of the raw-log-bundle contract, but Event Processing & Detection Engine has to
write two code paths to read them. Aligning them on one schema is cheap now and
awkward later.

### A3 - Dataset & Ground Truth Management/Event Processing & Detection Engine/Evidence Verification & Evaluation: confirm the scoring exclusions

The private evaluation-protocol note records which corpus activity is designated
non-scored lab scaffolding and which genuine activity is deliberately outside
the scored stage set. These exclusions materially change reported precision, so
they must be agreed **before** any configuration is run, not after results are
seen. Details are in the private verification evidence note (withheld).

## Documented Limitations

Recorded now, before any results exist, so they cannot be rationalised later.

**L1 - Conventional baseline may saturate.** The malicious lab scenario and its
benign lookalike are separable by a single trivial threshold on one countable
field. The Rules-only Detection Baseline is therefore likely to score at or near ceiling on
scenario-level classification, leaving no headroom to demonstrate added value
from agent specialisation. Scenario-level classification accuracy must not be
the headline metric. Stage-level reconstruction accuracy and claim-level
evidence-support rates should carry the comparison, since those measure whether
the system reconstructs *what happened and why it is supported*, which a
threshold rule does not attempt.

**L2 - Small sample.** Three scenarios and thirteen stages. Scenario-level
percentages are anecdotal at this n and will not be reported as if they were
estimates. Metrics will be reported as raw counts with the denominator stated,
at the stage and claim unit of analysis.

**L3 - Endpoint false positives are unmeasured.** The benign lookalike mirrors
the authentication-led scenario. There is no benign counterpart for the
endpoint-led scenario's technique, so the Endpoint Agent's false-positive
behaviour on legitimate administrative activity that resembles that technique
cannot be measured from S01-S03.

## Recommendation (optional, non-blocking)

One additional benign recording - legitimate administrative activity that
resembles the endpoint-led scenario's technique - would close L3 and is the
single highest-value addition to the set. It would let the Endpoint Agent be
scored on false positives the way the Authentication Agent already can be.

This is a specific, named telemetry gap of the kind Dataset & Ground Truth Management's scenario plan
anticipated. Evidence Verification & Evaluation recommends it but does not require it: S01-S03 support a
defensible evaluation without it, and L3 will be reported as a stated limitation
if the recording is not made.

## Evidence Verification & Evaluation Confirmation

Evidence Verification & Evaluation confirms the scenario plan and the ground-truth package, subject to A1 being
implemented by Event Processing & Detection Engine and A3 being agreed by Dataset & Ground Truth Management/Event Processing & Detection Engine/Evidence Verification & Evaluation.

the dataset scenario plan records `Evidence Verification & Evaluation confirmation: PENDING`. Dataset & Ground Truth Management should update that
line to reflect this acceptance.
