# Component names and current architecture

Components use responsibility names in packages, imports, commands, schemas,
reports and presentation material. Original scenario and evidence identifiers
remain unchanged.

| Component | Current location |
| --- | --- |
| Dataset & Ground Truth Management | `datasets/`, dataset scripts |
| Event Processing & Detection Engine | `event_processing/` |
| Authentication Investigation Agent | `authentication_agent/` |
| Endpoint Investigation Agent | `endpoint_agent/`, through `CorpusEndpointProvider` |
| Incident Reconstruction Orchestrator and Reconstruction Agent | `incident_reconstruction/` |
| Evidence Verification & Evaluation | Separate evaluation workflow; connects through `incident_reconstruction.verification` |

```mermaid
flowchart TD
  D[Dataset & Ground Truth Management: public EVTX exports] --> P[Event Processing & Detection Engine]
  P --> C[Verified normalised corpus / EventStore]
  P --> T[Detection triggers]
  T --> O[Incident Reconstruction Orchestrator: route, window, dispatch]
  C --> A[Read-only authentication provider]
  A --> I[Authentication Investigation Agent]
  L[Local Ollama adapter] --> I
  O --> I
  I --> F[Structured findings with exact evidence references]
  C --> EP[Read-only Sysmon provider]
  EP --> E[Endpoint Investigation Agent]
  L --> E
  O --> E
  E --> EF[Endpoint findings and cited process relationships]
  F --> R[Reconstruction Agent: stages, links, ATT&CK, narration]
  EF --> R
  C --> R
  L --> R
  R --> CL[Claims: reconstruction-v1, not_verified]
  CL -. verifier interface .-> V[Evidence Verification & Evaluation]
  V -. decisions stored unchanged .-> RP[HTML report]
  CL --> RP
```

Solid edges are implemented and exercised end to end on S01–S03 with deterministic fake
models; local-weights runs of the full pipeline are still to be recorded. The dashed edges
are the verifier connection: the interface, placeholder and integrity checks exist, while the
independent verifier itself is a separate delivery. No evaluation answer keys or scenario
runbooks enter model context. Processing baseline scoring is separate from integration testing.

The orchestrator turns detections into bounded, merged windows per agent, supplies trigger
evidence as trusted retrieval, records every outcome (including timeouts and context overflows,
which it retries on smaller windows) and never treats a failed investigation as clean. The
Reconstruction Agent builds stages, links findings and stages deterministically, and asks the
local model only to narrate each stage from enumerated evidence; every reply is re-checked. Three
run modes (`single-agent`, `multi-agent`, `full`) share triggers, providers, model and timing
points for the evaluation comparison. See the [package README](../incident_reconstruction/README.md)
and the [verification and evaluation handoff](RECONSTRUCTION_HANDOFF.md).

Endpoint retrieval and deterministic findings are also exercised on the public
corpus using the fake model. Its local Ollama adapter reuses the existing transport;
Qwen3:8b smoke tests also completed on small public S01-S03 windows. These
validate integration, not autonomous investigation quality (see
[validation scope](ENDPOINT_IMPLEMENTATION.md#validation-scope)). The callable
boundary is `endpoint_agent.investigate`, backed by
`event_processing.adapters.endpoint_provider.CorpusEndpointProvider`.
Its installed command is `mair-investigate-endpoint`, result schema is
`endpoint-result-v1`, and finding IDs begin `ENDPOINT-`. See the
[endpoint handoff](ENDPOINT_PROVIDER_HANDOFF.md).

The public entry point is `authentication_agent.investigate`. The read-only
provider is `event_processing.adapters.authentication_provider.CorpusAuthenticationProvider`.
The installed distribution is `mair-incident-reconstruction` version 0.2.0;
commands are `mair-events`, `mair-authentication` and
`mair-investigate-authentication`.

Schema identifiers describe content: `security-event-v1`, `security-corpus-v1`,
`detection-run-v1`, `detection-score-v1`, `authentication-result-v2`,
`endpoint-result-v1`, `orchestration-run-v1`, `reconstruction-v1`, `pipeline-run-v1`
and `verification-report-v1`. Pipeline commands are `mair-orchestrate` and `mair-report`.
Finding IDs now begin `AUTH-`. Original evidence IDs such as `S02-SEC-43584`
and scenario IDs such as `S01` remain unchanged.

This is an intentional interface migration requested by the project owner.
Update downstream imports/configuration and regenerate derived corpora and
findings. No compatibility aliases for retired names are introduced. Earlier
recordings remain immutable in Git history; current artifacts are regenerated.
See the [migration guide](COMPONENT_NAMING.md) for the complete active interface.

Within the Authentication Investigation Agent, trusted application requirements
execute through the same bounded tools as optional model choices. The initial
query remains mandatory; the optional typed `RequiredOperations` list is not a
cross-agent plan. After it completes, the local model chooses whether to query
further, reviews results and selects tentative interpretations. Python computes
facts and validates references. Operation receipts distinguish these roles.
Exact duplicate operations reuse the immutable invocation snapshot and still
consume budget. See the [call boundary](ORCHESTRATOR_HANDOFF.md).
