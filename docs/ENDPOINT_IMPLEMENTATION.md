# Endpoint implementation review

## Role alignment

Source references: `MAIR_Six_Member_Roles_and_Boundaries.pdf`, the M4
Endpoint Investigation Agent section (p. 6), joint workflow and completion rule
(p. 2), shared finding fields (p. 9), and change control (p. 13); and
`SecurityAnalytics_Proposal.docx`, sections 3.1 and 3.2. These are the user's
local project documents, not runtime inputs or evaluation answer keys.

The team role agreement's Endpoint Investigation Agent section assigns a
separate, locally hosted, read-only Sysmon investigator. The joint investigation
step means the authentication and endpoint developers each investigate their
own telemetry and return evidence-referenced findings. The proposal's sections
3.1 and 3.2 preserve that separation and reserve cross-source reconstruction and
independent verification for downstream components.

The implementation therefore covers process creation, parent-child relationships,
user/host fields, timing, related process/file/registry observations, constrained
local-model interpretation, structured findings and focused tests. It uses the
shared normalizer and evidence IDs. Dataset generation, authentication-chain
analysis, the final incident timeline, final ATT&CK mappings and independent
verification are outside this component's ownership.

## Pre-PR audit and acceptance status

Reviewed against base commit `7c43011` on 2026-09-24. The component is ready
for code and interface review, not an assertion that the whole M4 assignment
has received team acceptance. The PDF explicitly calls itself a proposed team
agreement (p. 1); its cross-component acknowledgement cannot be supplied by
automated tests or by this implementation alone.

| Source requirement | Implementation evidence | Status |
| --- | --- | --- |
| PDF p. 6: same local model family and Python environment as M3 | Shared `OllamaClient`, `OllamaConfig`, `Limits`; Qwen3:8b live tests; additive package in the same Python environment | Implemented |
| PDF p. 6: consume M2 Sysmon data, preserve process/host/user/time relationships | `CorpusEndpointProvider`, unchanged `NormalisedEvent`, GUID/host/scenario corroboration in `observations.py` | Implemented and tested |
| PDF pp. 6, 9: evidence IDs, observed facts, optional interpretations, entities, timestamps and uncertainty | Typed `Finding` keeps the common outer fields; exact readbacks and fail-closed reference checks | Implemented; endpoint payload requires consumer review |
| PDF p. 6: process-chain, benign-administration, missing-parent, absent-ID and schema tests | `endpoint_agent/tests/` plus `tests/test_endpoint_corpus.py` | Implemented and locally passing |
| Proposal section 3.1: separate investigators, read-only tools, local model and independent downstream reconstruction/verification | Separate endpoint prompt/tools; no authentication analysis, final timeline, ATT&CK mapping or support verdicts | Boundaries preserved |
| PDF pp. 2, 13: usable downstream contract and affected-member acknowledgement | Callable interface and handoff documentation; no M5/M6 implementation exists here to certify acceptance | Pending team integration/sign-off |
| Proposal section 3.2: malicious/benign comparison and quantitative reconstruction/support evaluation | Source-consistency and smoke tests only; no answer-key access during inference | M5/M6 integration/evaluation remains pending |

### Preservation and intentional limitations

No existing file is deleted. Existing authentication code/tests, event-processing
parser/schema/query methods, detection rules, datasets, evidence IDs, CI workflows,
dependency requirements and CLI entry points are unchanged. The adapter is a new
file; packaging adds the endpoint package, command and test discovery. Existing
documentation is extended and its endpoint-placeholder descriptions are updated.
There was no endpoint agent implementation in the base commit to replace.

The following are new component constraints, not removals from the original:

- Sysmon 1/10/11/13 only; other types remain in the corpus but are not investigated.
- Exact, case-sensitive entity/GUID filters; account filtering follows normalized
  `user`, not a fallback to Sysmon 10 `SourceUser`. Both user fields remain visible
  in findings when present.
- Relationships require corroborating process GUID, host and scenario evidence;
  PID-only, ambiguous, conflicting and out-of-window parents are not linked.
- Default budgets are 100 events per query, 8 investigative tool calls and a
  one-hour authorized window. Truncation remains explicit even after a follow-up.
- Model interpretations are optional fixed tentative categories, not unrestricted
  narrative explanations or attack classifications. Every retrieved supported
  record still receives a deterministic finding.
- The context guard measures bytes, not the model tokenizer's actual tokens;
  large windows can exceed useful 8192-token context. Narrow caller-authorized
  windows are needed; this is not a whole-corpus investigation guarantee.
- Failures return no partial findings. Cold model loading can exceed the default
  timeout. Runtime/model binaries and generated results remain under ignored `out/`.

Before merge, M2 should acknowledge the additive provider; M5/M6 should review
the endpoint payload, shared-envelope consumption and preservation of uncertainty.
No shared schema has been silently replaced, and no team acknowledgement is claimed.

## Corrections to the initial plan

1. The existing authentication finding envelope is a useful interface pattern,
   but its strict payload types and `agent_type` literal are authentication-only.
   The endpoint adds its own typed payload under the same envelope without
   changing the existing contract. Downstream integration review remains needed.
2. Existing process GUID helpers search a whole scenario and apply their own cap.
   A direct model wrapper would violate bounded investigation semantics or lose
   records when filtering after truncation. The endpoint provider filters the
   immutable corpus snapshot by scope and GUID before limiting.
3. Process creation is the core deliverable. Sysmon 10/11/13 add related recorded
   endpoint activity from the existing corpus, without requiring new telemetry.
   Each observation retains limits on what its event type proves.
4. Process relationships are computed from corroborating evidence, not invented
   by the model. The local model retains responsibility for optional follow-up
   tool selection and tentative interpretation. Fake-model tests demonstrate
   the pipeline, not model investigation quality.
5. The first delivery includes the corpus adapter, CLI and programmatic handoff
   so another component can exercise it. It does not claim an integrated
   orchestrator or verified final report.

## Delivered files

- `endpoint_agent/`: request/result models, deterministic observations, role
  prompt, bounded tools, fake adapter, CLI and manual.
- `event_processing/adapters/endpoint_provider.py`: shared-corpus adapter.
- `endpoint_agent/tests/` and `tests/test_endpoint_corpus.py`: synthetic,
  failure-boundary, CLI and actual-public-corpus coverage.
- `pyproject.toml`: packaging, installed CLI and default test discovery.
- `docs/ENDPOINT_PROVIDER_HANDOFF.md`: input/output contracts and consumer example.

## Validation scope

Validation uses public S01-S03 telemetry and synthetic fixtures. The private
answer key and detailed runbooks are not used. Reference checks demonstrate
that cited records resolve and that selected fields and relationships agree;
they do not measure detection accuracy, malicious/benign classification or
independent evidence support.

The public capture windows can exceed the default 100-event cap. This is
reported through metadata, operation receipts, uncertainty and CLI exit 3.
Caller-supplied trigger IDs can retrieve relevant records beyond the initial
prefix. Narrow detection windows and scoped model follow-ups remain necessary
for practical context sizes. Parents outside the authorized window stay missing.

Local validation on 2026-09-24 installed standalone Ollama 0.34.4 and
`qwen3:8b` (digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`).
The server uses loopback only, cloud disabled, and ignored project-local model
storage. The downloaded runtime archive passed its published SHA-256 check.

- Full regression suite: **897 passed, 4 skipped**. The skips were two opt-in
  model tests and two unavailable Windows symlink tests.
- Pre-PR no-EVTX/CI-shaped local run: **847 passed, 54 skipped**. The additional
  skips explicitly require Git LFS evidence; the original datasets were untouched.
- Both opt-in model tests passed separately against the installed Qwen model:
  the endpoint CLI test and the existing authentication transport smoke test
  (shared 8192-context, thinking-off profile). The final endpoint unit rerun
  was **102 passed, 1 opt-in skip**; its explicit live rerun was **1 passed**.
  The endpoint smoke test passed on a warm model.
  Its first cold run timed out at 60 seconds (server loading alone took about
  49 seconds), returning no findings. The optional test now explicitly allows
  180 seconds; production retains its configurable 60-second default.
- Live public-corpus checks below each completed with five findings, five
  evidence readbacks, no truncation and one model call. The model finished
  without follow-up tools or annotations. These establish live integration,
  **not** autonomous investigation quality or attack detection accuracy.
- All 15 findings were checked against exact source IDs, timestamps, hosts,
  users, images and process GUIDs in the verified corpus. No parent-child links
  were asserted in these small windows. Broader relationship coverage is in
  the synthetic and actual-corpus regression tests.
- A separate S02 test with `--max-events 1` elicited a model-selected process
  GUID filter, but it returned the already-seen `S02-SYS-25036` and no new
  evidence. The run retained `truncated: true` and incomplete-coverage
  uncertainty. This demonstrates bounded tool selection, not useful evidence
  expansion; autonomous retrieval quality remains a follow-up evaluation task.
- `pip check` reported no broken requirements; `git diff --check` passed.

| Scenario | Inclusive start | Exclusive end | Anchor evidence IDs |
| --- | --- | --- | --- |
| S01 | `2022-08-31T17:46:44.0979536Z` | `2022-08-31T17:46:44.1111241Z` | `S01-SYS-35811494`, `35811495`, `35811498`, `35811499`, `35811500` (same prefix) |
| S02 | `2026-09-21T02:03:50.0103815Z` | `2026-09-21T02:03:56.1085434Z` | `S02-SYS-25036`, `25037`, `25048`, `25049`, `25090` (same prefix) |
| S03 | `2026-09-21T02:24:23.1651489Z` | `2026-09-21T02:24:23.7089555Z` | `S03-SYS-24880`, `24881`, `24882`, `24883`, `24885` (same prefix) |

Reproduce each row with `python -m endpoint_agent --corpus out/corpus
--scenario <scenario> --start <start> --end <end> --mode ollama
--model qwen3:8b --timeout 180`. Local generated results are in
`out/endpoint-live/`; they are not committed and require the public corpus.
