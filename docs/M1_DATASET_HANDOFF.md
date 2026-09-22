> Historical handoff/report: numbered role labels and recorded results are preserved.
> See [component names and current architecture](ARCHITECTURE.md) and the
> [current authentication integration report](AUTHENTICATION_CORPUS_INTEGRATION.md) for current status.

# M1 Dataset Handoff

## Owner

M1 - Security Dataset & Ground Truth Engineer

## Public Dataset Locations

### S01
- datasets/S01/raw/Security.evtx
- datasets/S01/raw/Sysmon.evtx
- datasets/S01/metadata/manifest.json
- datasets/S01/metadata/scenario_metadata.json

### S02
- datasets/S02/raw/Security.evtx
- datasets/S02/raw/Sysmon.evtx
- datasets/S02/metadata/manifest.json
- datasets/S02/metadata/scenario_metadata.json

### S03
- datasets/S03/raw/Security.evtx
- datasets/S03/raw/Sysmon.evtx
- datasets/S03/metadata/manifest.json
- datasets/S03/metadata/scenario_metadata.json

## Intended Handoffs

M2:
- All public S01-S03 telemetry and metadata
- Used for parsing, normalization and baseline processing

M3:
- Windows Security telemetry from S01-S03
- S02 and S03 contain useful authentication records

M4:
- Sysmon telemetry from S01-S03
- Contains process and file activity suitable for endpoint analysis

M6:
- All public datasets
- Private ground truth supplied separately by M1 for evaluation only

## Important Ground-Truth Boundary

Investigation agents must not receive:

- ground_truth/private/
- scenario answer keys
- stage labels
- expected classifications
- detailed private runbooks

These are withheld until evaluation.

## Dataset Validation

Run:

    powershell -ExecutionPolicy Bypass -File scripts/validate-datasets.ps1

Expected result:

    ALL DATASET CHECKS PASSED

## Integrity

EVTX files are stored through Git LFS.

Each scenario manifest contains SHA-256 hashes for its source evidence.

## Time Standard

Scenario timestamps are recorded in UTC.
