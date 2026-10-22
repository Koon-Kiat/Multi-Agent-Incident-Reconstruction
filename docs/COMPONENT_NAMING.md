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
- `detection-score-v1`: scoring output.
- `authentication-result-v2`: investigation result envelope, adding operation receipts and readback counts to the v1 fields.
- `authentication-config-v3` and `authentication-prompt-v16`: agent configuration and prompt revisions.
- `endpoint-result-v1`, `endpoint-config-v1` and `endpoint-prompt-v1`: additive endpoint result, configuration and prompt contracts.

Finding IDs use `AUTH-` plus the existing deterministic digest; their identity
namespace changed while supporting evidence IDs did not. Historical results and
commits remain unchanged in Git history. Current reports contain newly executed
results, not renamed historical model replies.

External component owners must adopt the imports and result identifiers before
connecting the Incident Reconstruction Orchestrator. Its dispatch, window retries
and end-to-end reconstruction are now in `incident_reconstruction/`, adding
`orchestration-run-v1`, `reconstruction-v1`, `pipeline-run-v1` and
`verification-report-v1`; claim IDs take the form `<scenario>-CLM-<nn>`.

## Evaluation terminology

Documentation and generated reports use meaningful experiment names:

| Evaluation approach | Stable pipeline interface |
| --- | --- |
| Rules-only detection baseline | `python -m event_processing detect` |
| Single-agent generalist baseline | `--mode single-agent` |
| Specialist-agent incident reconstruction without independent verification | `--mode multi-agent` |
| Specialist-agent incident reconstruction with independent evidence verification | `--mode full` with the verifier factory |

These names describe evaluation approaches, not team-member numbers or rankings. Private answer keys, original event IDs, and previously recorded evidence remain unmodified. Evaluate new implementation revisions with their own recorded provenance.
