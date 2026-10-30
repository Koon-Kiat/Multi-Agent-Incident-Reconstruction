# Documentation guide

Maintained guides describe the current checkout. Dated reports describe their
recorded revisions and are retained for provenance; their old commands, test
counts and model results are not current acceptance evidence.

## Start here

| Task | Guide |
| --- | --- |
| Install and run the pipeline | [Project README](../README.md) |
| Understand component boundaries | [Architecture](ARCHITECTURE.md) |
| Find package, command and schema names | [Interfaces and naming](COMPONENT_NAMING.md) |
| Contribute and validate a change | [Contributing](../CONTRIBUTING.md) |
| Run and approve an evaluation | [Evaluation workflow](FINAL_EVALUATION_HANDOFF.md) and [protocol](EVALUATION_PROTOCOL.md) |

## Component manuals and contracts

| Component | Maintained references |
| --- | --- |
| Datasets | [Dataset inventory and integrity](../datasets/README.md), [private ground truth](../ground_truth/README.md), [private runbooks](../runbooks/README.md) |
| Processing and detection | [Manual](../event_processing/README.md), [event schema](EVENT_SCHEMA.md), [query API](EVENT_QUERY_API.md), [rules](DETECTION_RULES.md), [metrics](DETECTION_METRICS.md) |
| Authentication | [Manual](../authentication_agent/README.md), [provider contract](AUTHENTICATION_PROVIDER_HANDOFF.md), [programmatic integration](ORCHESTRATOR_HANDOFF.md) |
| Endpoint | [Manual](../endpoint_agent/README.md), [provider and integration contract](ENDPOINT_PROVIDER_HANDOFF.md) |
| Reconstruction | [Manual](../incident_reconstruction/README.md), [artifacts and verifier interface](RECONSTRUCTION_HANDOFF.md) |
| Verification and evaluation | [Manual](../evidence_verification/README.md), [protocol](EVALUATION_PROTOCOL.md), [evaluation workflow](FINAL_EVALUATION_HANDOFF.md) |

## Historical reports and evidence

These records support reproducibility and explain implementation decisions. Use
the recorded revision for historical reproduction. Preserve raw logs, hashes,
failures and measurements rather than rewriting them to match new code.

| Record | Scope |
| --- | --- |
| [Ground-truth acceptance](EVIDENCE_ACCEPTANCE.md) | September 2026 package assessment; not final scoring approval |
| [Synthetic authentication validation](AUTHENTICATION_SYNTHETIC_VALIDATION.md) | Earlier synthetic experiments |
| [Authentication corpus integration](AUTHENTICATION_CORPUS_INTEGRATION.md) | September 2026 integration and model limitations |
| [Authentication follow-up](AUTHENTICATION_AUTONOMY.md) | September 2026 bounded retrieval experiments |
| [Authentication closeout](AUTHENTICATION_CLOSEOUT_AUDIT.md) | 18 October 2026 audit |
| [Endpoint implementation](ENDPOINT_IMPLEMENTATION.md) | Initial delivery review |
| [Endpoint context coverage](ENDPOINT_CONTEXT_COVERAGE.md) | 18 October 2026 batching and retrieval measurements |
| [Correctness remediation](CORRECTNESS_REMEDIATION.md) | 19–20 October 2026 corrections and development validation |
| [Verifier false alarms](VERIFIER_FALSE_ALARM_REVIEW.md) | 18 October 2026 review |
| [Semantic claim review](SEMANTIC_CLAIM_REVIEW.md) | 20 October 2026 disclosed model review, not human annotations |
| [Generalist context correction](GENERALIST_CONTEXT_CORRECTION.md) | 21 October 2026 diagnostic experiment |
| [Terminology audit](terminology-audit/REPORT.md) | 22 October 2026 inventory and fingerprints |

`docs/validation/` contains the retained measurement artifacts, including older
failed attempts and completion audits. `docs/terminology-audit/` is a frozen
audit snapshot, including its explicitly synthetic report fixture. Paths and
revision status inside those snapshots describe the original checkout and may
refer to documentation since consolidated. Current usage belongs in the manuals.

## Maintenance

Update the owning manual when an interface or workflow changes. Link to that
reference instead of creating another delivery-status note. Keep empirical
results dated and separate from current instructions. Check relative links,
CLI options and the corresponding contracts before claiming documentation is
current. Keep private inputs and generated run output out of public guides.

The October 2026 cleanup consolidated redundant dataset, provider, processing
and verifier handoffs into the references above, folded authentication PR advice
into Contributing, and replaced the superseded metrics proposal with the agreed
metrics reference. The removed versions remain available in Git history.
