# Incident Reconstruction Orchestrator and Reconstruction Agent

The orchestrator routes conventional detections to the Authentication and Endpoint Investigation
Agents as bounded time windows, dispatches them with deadlines, and records every outcome in one
`orchestration-run-v1` document per scenario. The Reconstruction Agent turns that record into an
ordered, evidence-referenced `reconstruction-v1` timeline of claims with tentative ATT&CK
mappings. Independent verification consumes the claims; it is not part of this module.

```
EventStore ──► DetectionEngine.triggers_for(scenario)
                   │
                   ▼
           plan_investigations ── route by rule ─► merge padded spans per agent ─► seeds
                   │
                   ▼
           IncidentOrchestrator.run ── per task: worker thread + deadline
                   │                     context_size_limit ─► split window in half, retry
                   ▼
           OrchestrationRun (tasks, results, coverage, timing)
                   │
                   ▼
           build_stages ── group detections ─► link findings ─► correlate stages   (deterministic)
                   │
                   ▼
           narrate each stage ── local model, enumerated evidence/techniques ─► host checks
                   │                     invalid reply or model failure ─► template text
                   ▼
           Reconstruction (claims, ATT&CK, links, gaps; all not_verified)
```

## Run

```powershell
python -m event_processing normalise --datasets datasets --out out/corpus
python -m incident_reconstruction --corpus out/corpus --llm fake --plan-only
python -m incident_reconstruction --corpus out/corpus --llm fake --mode single-agent --out out/runs
python -m incident_reconstruction --corpus out/corpus --llm fake --mode multi-agent  --out out/runs
python -m incident_reconstruction --corpus out/corpus --llm fake --mode full         --out out/runs
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode full --out out/runs --scenario S02
python -m incident_reconstruction --corpus out/corpus --llm ollama --mode full --out out/runs --reconstruct-only
```

`--llm` is required so a run never silently uses the deterministic fake; `--llm ollama` runs the
installed-weights preflight before any evidence is sent and uses one model for every role.
`--reconstruct-only` (multi-agent/full) re-reads `<out>/<mode>/<scenario>.orchestration.json`, so
narration and verification can be repeated without re-running the investigation agents. Exit
codes: `0` complete, `1` written but incomplete (an investigation stayed unresolved, the
single-agent run ended early, or the verifier failed), `2` invalid input, `3` model or verifier
setup failed. `mair-orchestrate` is the installed script name.

## Run modes

| `--mode` | Evaluation configuration | Phases (timed separately) | Files in `<out>/<mode>/` |
| --- | --- | --- | --- |
| `single-agent` | B: one generalist LLM | detection, single_agent | `pipeline`, `reconstruction` |
| `multi-agent` | C: specialists + reconstruction, no verifier | detection, investigation, reconstruction | + `orchestration` |
| `full` | D: C + independent verification | ... + verification | + `verification` |

The rules-only detection baseline is the Event Processing & Detection Engine's `detect` baseline.
Every mode reads the same triggers from `DetectionEngine`, uses the same providers, limits and
local model, and starts and stops its clock at the same points; `<scenario>.pipeline.json`
(`pipeline-run-v1`) records the mode, per-phase seconds, total latency, model calls, claim count
and verdict counts. All modes emit `reconstruction-v1` claims, so one scorer handles all three.

**Single-agent baseline.** One model gets the triggers and a window spanning them (±60 s, at most
3600 s) and may call `query_authentication`, `query_endpoint` and `get_event` on the same corpus
providers the specialists use (default budget 16, `--single-agent-tool-calls`), then finishes with
claims. It gets no stage building, finding linkage, correlation or ATT&CK strength table. The host
enforces only bounds: queries stay in the window, each turn's reply schema enumerates the records
retrieved so far as the only citable IDs, techniques must be catalogued, overclaiming drops a claim,
and claims are ordered by their cited records' time. A failed or invalid model reply ends the
run with whatever valid claims exist and the reason in `investigation_gaps`; it is not repaired.

**Verification.** `full` passes each reconstruction to a verifier loaded with
`--verifier package.module:factory` (an object with `metadata()` and
`verify(reconstruction, store) -> Iterable[VerificationDecision]`). Decisions (`claim_id`,
`verdict` ∈ confirmed / partially_supported / unverified / rejected, `reason`,
`checked_evidence_ids`, `conflicts`) are stored unchanged in `verification-report-v1`; claims stay
`not_verified`. A missing decision becomes `unverified` (`no_decision_returned`), decisions for
unknown or repeated claims are set aside, and a verifier that raises leaves every claim
`unverified`; each case is listed in `integrity_notes`. Until the Evidence Verification &
Evaluation verifier is connected, the default `PendingVerifier` marks every claim `unverified`.

## Report

Every pipeline run ends by writing `<out>/<mode>/<scenario>.report.html` for each saved run and
`<out>/index.html`, which compares the configurations per scenario. Regenerate them at any time,
for example after re-running verification:

```powershell
python -m incident_reconstruction.report --corpus out/corpus --runs out/runs
```

Each page is one self-contained file (inline CSS, no scripts or external resources) and works
offline in the light or dark system theme. It shows the run facts and per-phase timing; the
verification banner; investigation gaps (failed, truncated or unresolved investigations and
unattached findings); and the timeline. Every claim card shows its assessment, the verifier's
verdict and reason exactly as returned, template-text use, entities, ATT&CK mappings with status
and justification, links to related claims, uncertainty, and an expandable evidence table that
looks each cited ID up in the corpus and shows its recorded fields and raw EVTX reference. An ID
missing from the corpus is flagged rather than hidden. All event values are HTML-escaped.
`mair-report` is the installed script name.

## Routing

| Rule | Agents | Reason |
| --- | --- | --- |
| `R-AUTH-01`, `R-AUTH-02` | authentication | logon failure/success sequences |
| `R-AUTH-03` (4648) | authentication, endpoint | explicit credentials are usually process-driven |
| `R-EXEC-*`, `R-FILE-*`, `R-CRED-*`, `R-PERSIST-*` | endpoint | process, file, registry and access activity |
| `R-LOG-*` (1102) | authentication, endpoint | log clearing removes context for both sources |
| any other rule | both | a new rule is never dropped silently |

Each detection's closed span is padded (authentication ±60 s, endpoint ±15 s; Sysmon is far
denser) and padded spans for the same agent are merged while the window stays within its bound
(3600 s / 600 s). Trigger IDs become trusted seeds only where the receiving agent's tools can
retrieve them: Security 4624/4625 as authentication required operations, Sysmon 1/10/11/13 as
endpoint seeds. Other triggers still define the window and are kept in `detection_ids`.

Seeds consume the agents' tool budget, so each task's `max_tool_calls` is
`1 + seeds + --model-tool-calls` (default 7), never below the base limit.

## Outcomes

| `status` | Meaning | Findings |
| --- | --- | --- |
| `completed` | agent completed | used |
| `failed` | agent returned `failed`; its `error_code` is kept | none |
| `timeout` | exceeded `--task-timeout`; the worker thread is abandoned | none |
| `error` | agent raised (`agent_exception:<Type>`, no message text) or returned a result of the wrong type/window (`agent_contract_violation`) | none |
| `not_run` | `--run-timeout` was exhausted first | none |

A `context_size_limit` failure is retried as two half windows, keeping only halves that still
hold a trigger, up to `--max-split-depth` (default 3). The parent keeps its failed result and
lists its children in `split_into`. `coverage` marks a detection investigated only when a
completed task covered it; `uninvestigated_detection_ids()` must be reported, never presumed
clean. `findings()` returns findings of completed tasks, de-duplicated by `finding_id`.

## Reconstruction

**Stages.** Detections in time order; consecutive detections of one rule no more than 120 s apart
form one stage, and a different rule in between starts a new one. Each stage reads its trigger
events through `EventStore` (4648, 4688 and 1102 triggers have no agent finding of their own).

**Linking.** A finding *directly* supports a stage when it cites a trigger, or when it is the
Sysmon creation of a Security 4688 trigger's process (same image within 2 s — the cross-source
join). A finding is *related* when it is the same process as a trigger, that process's parent
creation or a child it created (within 60 s), or an authentication finding for a non-system
account in the stage (within 120 s). A related finding joins only its nearest stage and never
one another stage owns directly. At most 25 findings per stage; omissions are recorded.

**Correlation.** Stages are linked (both directions) when they share a non-system account or a
process, or when a process in one was started by a process in the other. SYSTEM, LOCAL/NETWORK
SERVICE, DWM-n, UMFD-n and machine accounts never link stages.

**Narration.** The model sees one bounded stage (≤14 KB) and replies with `claim_text`,
`rationale`, `assessment` (`requires_review` / `benign_possible` / `insufficient_evidence`),
`cited_evidence_ids` and `technique_ids`; the decoder schema enumerates the stage's evidence and
candidate techniques. The host re-checks every field and rejects overclaiming language
(`verified`, `confirmed compromise`, `proven`, `definitely malicious`). On any failure the claim
uses deterministic template text, `narrative_source="template"`, and the reason as uncertainty.

**ATT&CK.** Candidates are the detection's primary technique plus a secondary for R-AUTH-01
(T1078) and R-EXEC-03 (T1059). Each mapping records a justification and the trigger evidence.
`supported` needs a *defining* observable (1102 → T1070.001, lsass access → T1003.001, discovery
binary → its discovery technique, 4697/4698/Run key → persistence); *indicative* observables
(failed logons → T1110, 4648 → T1078, script in temp → T1105) are at most `tentative`. A mapping
the model did not select, or on a stage judged `insufficient_evidence`, is `uncertain`.

Every claim is `verification_status="not_verified"`. `evidence_ids` is always a subset of
`context_evidence_ids`; `investigation_gaps` and per-claim `uncertainty` carry failed, truncated
or unresolved investigations forward.

## Current results (fake models, 2026-10-15)

| Scenario | Detections | Tasks | Unresolved | Uninvestigated detections |
| --- | --- | --- | --- | --- |
| S01 | 9 | 3 | 0 | 0 |
| S02 | 15 | 13 | 1 | 0 |
| S03 | 14 | 10 | 1 | 0 |

The two unresolved leaves are 6–9 s endpoint windows inside a benign EdgeWebView burst (115
Sysmon events in 6 s, command lines around 2.8 KB) that exceed the Endpoint Investigation
Agent's context bound even at the minimum split. Their detections are still covered by sibling
windows. Fake-model runs check plumbing only; they say nothing about investigation quality.

Reconstruction yields 3 / 8 / 6 claims for S01 / S02 / S03, using about 10 of 208–421 findings
per scenario. In S02 the failed-then-successful logons for `mair_user` link by account to the
payload write and discovery stages, and the discovery processes were started by the PowerShell
process from the payload stage (process lineage).

## Known limitations

* A timed-out agent call cannot be cancelled; its daemon thread is abandoned.
* Tasks run sequentially against one local model, by design, for reproducible latency.
* Stage grouping is by rule; two different rules describing one action stay separate stages,
  joined only by links.
* Template narratives are factual but generic; only model narration distinguishes benign
  lookalikes, and that has not yet been measured on local weights.
* Truncated agent queries (more than 100 events) are kept as the agent's own uncertainty, not
  split: splitting on truncation would multiply local model calls.
