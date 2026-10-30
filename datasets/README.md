# MAIR Security Datasets

This directory contains the security telemetry prepared for the MAIR
(Multi-Agent Incident Reconstruction) project.

## Dataset Inventory

| Scenario | Telemetry | Source |
|---|---|---|
| S01 | Windows Security + Sysmon | Curated external security dataset |
| S02 | Windows Security + Sysmon | Controlled Windows 11 VMware lab |
| S03 | Windows Security + Sysmon | Controlled Windows 11 VMware lab |

Each scenario contains:

- `raw/Security.evtx`
- `raw/Sysmon.evtx`
- `metadata/manifest.json`
- `metadata/scenario_metadata.json`

## Evidence Integrity

SHA-256 hashes for the original EVTX exports are stored in each scenario's
`metadata/manifest.json`.

EVTX files are stored using Git LFS.

## Ground Truth

Ground-truth labels, expected stages, detailed scenario actions and answer keys
are intentionally excluded from the public dataset directories.

Investigation components should operate only on the raw telemetry and neutral
metadata during inference.

Ground truth is supplied only to post-run evaluation. Investigation, reconstruction
and the independent verifier must never read it or the private runbooks. See
[private input handling](../ground_truth/README.md).

## Time

Scenario timestamps are recorded in UTC.

## Validation

Run:

    powershell -ExecutionPolicy Bypass -File scripts/validate-datasets.ps1

The validator checks:

- expected dataset files exist
- JSON metadata is parseable
- EVTX files can be opened
- SHA-256 hashes match the manifests

## S01 Source Provenance

S01 was curated from an external controlled security dataset.

- Provider: Splunk Attack Data / CAPAttack
- Source repository: https://github.com/splunk/attack_data
- Source capture ID: `4fd47dac-6090-451c-977e-2da96af05d6b`

The exact source repository commit used for S01 is recorded in
`S01/metadata/scenario_metadata.json`.

The original EVTX evidence retained by MAIR is independently verified using the
SHA-256 values in `S01/metadata/manifest.json`.

Detailed ground-truth interpretation is intentionally withheld from the public
dataset documentation.
