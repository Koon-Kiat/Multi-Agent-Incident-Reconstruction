# Component interfaces and naming

All active components are named for their responsibilities. The project owner
explicitly requested this migration across internal interfaces as well as
user-facing text. Downstream consumers must adopt the names below; no retired
package or command aliases are retained.

| Responsibility | Current interface |
| --- | --- |
| Event corpus loading and querying | `event_processing.query.EventStore` |
| Authentication corpus adapter | `event_processing.adapters.authentication_provider.CorpusAuthenticationProvider` |
| Authentication investigation | `authentication_agent.investigate` |
| Endpoint corpus adapter | `event_processing.adapters.endpoint_provider.CorpusEndpointProvider` |
| Endpoint investigation | `endpoint_agent.investigate` |
| Endpoint request/result models | `endpoint_agent.models` |
| Endpoint corpus CLI | `python -m endpoint_agent` or `mair-investigate-endpoint` |
| Authentication request/result models | `authentication_agent.models` |
| Local model transport | `authentication_agent.llm.ollama_client.OllamaClient` |
| Event-processing CLI | `python -m event_processing` or `mair-events` |
| Synthetic authentication CLI | `python -m authentication_agent` or `mair-authentication` |
| Real-corpus authentication CLI | `python -m authentication_agent.investigate_corpus` or `mair-investigate-authentication` |
| Investigation dispatch | `incident_reconstruction.IncidentOrchestrator` |
| Claim timeline | `incident_reconstruction.reconstruct`, models in `incident_reconstruction.claims` |
| Run modes | `incident_reconstruction.pipeline.Pipeline` |
| Verifier connection | `incident_reconstruction.verification` |
| Pipeline CLI | `python -m incident_reconstruction` or `mair-orchestrate` |
| Report CLI | `python -m incident_reconstruction.report` or `mair-report` |
| Test dataset-root override | `MAIR_DATASETS_DIR` |
| Local generated runtime directory | `.authentication-runtime/` |

The distribution is `mair-incident-reconstruction` 0.2.0. Reinstall it with
`python -m pip install -e '.[test]'`. Update imports, subprocess commands,
configuration and schema consumers; regenerate derived corpus manifests,
detection output and investigation findings. There is no event parser or storage
migration: raw exports, original scenario IDs and evidence IDs are unchanged.

Active version identifiers:

- `security-event-v1`: normalised event format.
- `security-corpus-v1`: corpus manifest.
- `detection-run-v1`: conventional detection runs.
- `detection-score-v2`: detection scoring output (defined-zero precision/recall gives F1 0.0).
- `authentication-result-v2`: investigation result envelope, adding operation receipts and readback counts to the v1 fields.
- `authentication-config-v5` and `authentication-prompt-v17`: agent configuration and prompt revisions.
- `endpoint-result-v1`, `endpoint-config-v3` and `endpoint-prompt-v3`: additive endpoint result, configuration and prompt contracts.

Finding IDs use `AUTH-` plus the existing deterministic digest; their identity
namespace changed while supporting evidence IDs did not. Historical results and
commits remain unchanged in Git history. Current reports contain newly executed
results, not renamed historical model replies.

Component consumers use these imports and result identifiers. The integrated
Incident Reconstruction Orchestrator provides dispatch, window retries
and end-to-end reconstruction in `incident_reconstruction/`, adding
`orchestration-run-v1`, `reconstruction-v1`, `pipeline-run-v1` and
`verification-report-v1`; claim IDs take the form `<scenario>-CLM-<nn>`.

## Evaluation terminology

Documentation and generated reports use meaningful experiment names:

| Evaluation approach | Stable pipeline interface |
| --- | --- |
| Rules-only Detection Baseline | `python -m event_processing detect` |
| Single-Agent Generalist Baseline | `--mode single-agent` |
| Specialist-Agent Incident Reconstruction | `--mode multi-agent` |
| Specialist-Agent Incident Reconstruction with Independent Evidence Verification | `--mode full` with the verifier factory |

These names describe evaluation approaches, not team-member numbers or rankings. Private answer keys, original event IDs, and previously recorded evidence remain unmodified. Evaluate new implementation revisions with their own recorded provenance.

### Evaluation result schema and command compatibility

New scores use `evaluation-results-v3`. The `configuration` fields in `runs`,
reconstruction/support metrics and `claims.csv`, and the keys in `totals`, use:

| Pipeline mode | Result identifier |
| --- | --- |
| `single-agent` | `single_agent_generalist_baseline` |
| `multi-agent` | `specialist_agent_incident_reconstruction` |
| `full` | `specialist_agent_incident_reconstruction_with_independent_evidence_verification` |

The rules-only score is stored under `rules_only_detection_baseline`.
`incident_reconstruction.terminology` supplies the canonical display names for
both Markdown evaluation tables and HTML incident reports.

The old result identifiers `B_single_agent`, `C_multi_agent_no_verifier`,
`D_full_mair` and `configuration_A_rules_only` are accepted only by the read-only
v1/v2 report display adapter. New producers never emit them. External JSON/CSV
consumers must select the v3 identifiers; no old scores or run fingerprints are
rewritten. Rendering a historical result is not validation against current code.

Pipeline modes `single-agent`, `multi-agent` and `full` remain stable because they
are embedded in reconstruction and pipeline schemas, review bindings, artifact
paths and existing CLI calls. `full` means the independently verified specialist
approach. `MODES` remains a normal Python collection name, not an experiment label.

Use `scripts/run-evaluation.ps1 -Only generalist,specialist,verified-specialist`
for model runs. The legacy stage aliases `B`, `C`, and `D` remain accepted for
existing automation and normalize to those descriptive stages before dispatch.
New log filenames are `generalist.log`, `specialist.log` and
`verified-specialist.log`; saved pipeline directory names remain unchanged.
Readiness JSON gate names now use descriptive names too; consumers of the old
human-readable gate strings must update their lookups. Status values and exit
codes are unchanged.

See [the terminology audit](terminology-audit/REPORT.md) for the complete inventory,
fingerprint comparison, preserved evidence and verification results.
