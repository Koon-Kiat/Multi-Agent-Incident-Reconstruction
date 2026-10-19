# Endpoint Investigation Agent

This component investigates recorded Sysmon activity and returns evidence-referenced
endpoint findings for reconstruction and independent verification. It reads the
shared `EventStore` through `CorpusEndpointProvider`; it has no EVTX parser or
live-host connection. Authentication remains a separate investigation component.

## Run locally

From the repository root, using Python 3.11 or later:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
git lfs pull --include='datasets/S01/raw/*.evtx,datasets/S02/raw/*.evtx,datasets/S03/raw/*.evtx'
.\.venv\Scripts\python.exe -m event_processing normalise --datasets datasets --out out/corpus
.\.venv\Scripts\python.exe -m endpoint_agent --corpus out/corpus --scenario S02 --start 2026-09-21T02:04:30Z --end 2026-09-21T02:06:30Z --mode fake
```

`fake` exercises retrieval, process facts, evidence references and JSON output
without inference. Its model always finishes without annotations; it cannot
demonstrate reasoning quality or autonomous tool selection.

With the shared model already installed in a running local Ollama service:

```powershell
.\.venv\Scripts\python.exe -m endpoint_agent --corpus out/corpus --scenario S02 --start 2026-09-21T02:04:30Z --end 2026-09-21T02:06:30Z --mode ollama --model qwen3:8b
```

For a new machine, install Ollama from its [official Windows download](https://ollama.com/download/windows)
or [standalone release](https://github.com/ollama/ollama/releases), start
`ollama serve`, and run `ollama pull qwen3:8b`. These are explicit setup steps,
never agent tools. Allow about 5.2 GB for model weights plus runtime files.
On this development machine the standalone executable is
`out/tools/ollama/ollama.exe`, with weights in `out/ollama-models/`.
To restart that project-local server from PowerShell:

```powershell
$env:OLLAMA_HOST = '127.0.0.1:11434'
$env:OLLAMA_MODELS = Join-Path (Get-Location) 'out/ollama-models'
$env:OLLAMA_NO_CLOUD = '1'
& .\out\tools\ollama\ollama.exe serve
```

Do not start another server if port 11434 is already serving Ollama. Cold model
loading counts toward the request deadline; use `--timeout 180` if necessary.
The first cold validation timed out at the 60-second default; warm smoke tests
passed. See [measured validation](../docs/ENDPOINT_IMPLEMENTATION.md#validation-scope).

The installed `mair-investigate-endpoint` command and
`python -m endpoint_agent.investigate_corpus` invoke the same entry point.
`--schema` exports `endpoint-result-v1`. `--evidence-id` may be repeated to
request exact Sysmon trigger records from the caller. These IDs must belong to
the requested scenario and their records must lie in the authorized window.
Every seed consumes a tool slot in addition to the initial query; insufficient
seed budget fails before retrieval. Missing IDs remain explicit missing lookups.
After seeds, bounded overlapping tail queries recover a capped initial window
when budget permits. Each recovery query consumes a tool slot and has a
`coverage` operation receipt. No events at the cursor timestamp are skipped.

The shared local profile is `qwen3:8b`, context 8192, thinking off, temperature 0,
seed 0. `--model` / `MAIR_OLLAMA_MODEL`, `--endpoint` / `MAIR_OLLAMA_ENDPOINT`,
`--num-ctx` and `--timeout` configure it. The existing loopback-only transport
and model preflight are reused from the Authentication Agent; its prompts,
authentication logic and event models are not used. Preflight checks installed
model metadata, rejects cloud aliases and records the model digest. Nothing
downloads weights or starts a server.

JSON is printed to stdout. Exit codes are:

| Exit | Meaning |
| --- | --- |
| 0 | Completed, possibly empty; retain uncertainty |
| 1 | Investigation failed; typed error result without findings |
| 2 | Invalid configuration, absent scenario, unusable corpus or unavailable local model |
| 3 | Completed with truncated retrieval; coverage remains incomplete |

An empty window is not evidence that no activity occurred. Unknown scenarios
are rejected by the CLI; the provider's unknown-scenario query returns empty.

## What is investigated

| Sysmon Event ID | Observed facts |
| --- | --- |
| 1 | Process creation, image/command line, reported parent and GUID relationships |
| 10 | Source/target process fields and access mask; no assertion of credential extraction |
| 11 | File creation and originating process when corroborated |
| 13 | Registry value set and originating process when corroborated |

Other Sysmon types are outside this version's investigation allowlist. Exact
provider lookup preserves any Sysmon event, but agent tools reject unsupported
types before findings. Security-channel events never enter endpoint findings.
The normalizer's `user` stays unchanged; Sysmon 10's `SourceUser` and `TargetUser`
are exposed separately as reported identities because the shared normalized
`user` may be absent. The `account` query filter still uses normalized `user`.

The five approved tools query a window, retrieve an exact event, find a process
creation, find children or retrieve process activity. GUID tools use a host/GUID
pair already seen in evidence. All filters are exact and case-sensitive. The
provider filters before limiting, including `SourceProcessGUID` for event 10.
The agent independently checks every result's scenario, window, type, ordering,
duplicates and limit. All follow-ups remain in the original `[start,end)` window.

Parent links require matching scenario, host and nonzero ProcessGuid values,
a unique process-creation record, compatible reported image/PID fields and
consistent timing. PID equality alone never forms a link. Missing parents,
ambiguous identities, cycles, conflicting fields and parents outside the window
produce uncertainty. Equal timestamps can have a GUID relationship but do not
prove temporal precedence. Full 100 ns timestamps and original evidence IDs
are retained. The process-access target is reported, not linked to a target
creation record in this version.

## Findings and model decisions

Python produces one observation per retrieved supported event, plus any
corroborating process-creation reference. The common finding envelope is
`finding_id`, `agent_type: endpoint`, `scenario_id`, `observed_events`,
`interpretation`, `timestamps`, `entities`, `evidence_ids` and `uncertainty`.
The endpoint-specific payload includes process fields and typed relationships
whose two evidence IDs are also present in the finding's citations.

The model may choose bounded follow-up queries and tentative interpretations
of existing observations. It cannot change facts, merge evidence lists or add
relationships. Its schema restricts annotations to existing finding/evidence
pairs, and Python validates them independently. All observations remain in the
output even if the model annotates none. Interpretations include contextual
review and legitimate administration as a possible explanation; none assigns
malicious/benign labels, final ATT&CK techniques or verification verdicts.

Model context contains only the allowlisted field projection. Raw XML, arbitrary
event messages, private ground truth, expected classifications and runbooks are
excluded. Command lines and paths are explicitly untrusted data and cannot
authorize execution. Final exact-ID readback checks that retrieved events have
not disappeared or changed. This is reference consistency, not independent
claim verification or an accuracy measurement.

The model reviews consecutive batches of the complete retrieved snapshot. Python
computes process links across that entire snapshot before batching, and returns
every observation after every batch finishes. No command line, path, timestamp,
identity or citation is clipped to make a batch fit. Repeated scope/uncertainty is
carried once, unavailable null fields are omitted, and the model sees the latest
operation summary; the complete query audit remains in result metadata. Each
annotation must match an observation in the current batch. Any follow-up rebuilds
the global observations and restarts review, discarding stale annotations.

`metadata.context_batches` records each attempted model call's observation and
evidence IDs, snapshot revision and serialized context size. If the adapter exposes
`num_ctx`, batches additionally reserve `max_output_tokens` and use a conservative
UTF-8 input token bound with chat-template headroom for the shared Qwen tokenizer.
`context_strategy` identifies this behavior; historical results still parse with
the original strategy default.

## Limits and tests

Defaults match the existing runtime budgets: eight tool attempts, 100 events per
query, a one-hour window, 262144 context bytes, 16384 bytes per source event,
32768 response bytes, 2048 output tokens and a 60-second model request timeout.
CLI overrides include `--max-tool-calls`, `--max-events`, `--max-window-seconds`
and `--timeout`. Programmatic `Limits` exposes the remaining budgets.
Duplicate queries reuse the invocation snapshot but still consume budget.
The initial query supplies `metadata.window_total_matched`; every retrieved event
must lie in that window. `window_coverage_complete` becomes true only when the
distinct retrieved count equals that total. `metadata.truncated` and incomplete
inventory uncertainty clear only at that point; individual operation receipts
retain their original truncation flags. Thus a completed root window does not
silently replace the evidence formerly recovered by time splitting with a prefix.

Recovery stops at the tool budget or a tail query that cannot advance. A page
filled by one timestamp may prevent progress through this timestamp-only
API; raise the authorized `--max-events` cap if appropriate, or retain the explicit
gap. A single observation plus fixed instructions/schema that cannot fit still
fails with `context_size_limit` and no partial findings. Custom adapters without
`num_ctx` get the byte guard only. Batching increases model calls and latency;
it does not give the model simultaneous free-form reasoning over all batches.
See the [S02/S03 investigation and validation](../docs/ENDPOINT_CONTEXT_COVERAGE.md).

```powershell
.\.venv\Scripts\python.exe -m pytest -q endpoint_agent/tests tests/test_endpoint_corpus.py --basetemp .test-tmp-endpoint
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp-full
```

Default tests require no model. Real-corpus tests use only public telemetry and
skip explicitly when original Git LFS files are absent. The optional local-model
test requires `MAIR_TEST_ENDPOINT_OLLAMA=1` and the selected model already installed.
Tests cover process chains, administrative activity, missing parents, PID reuse,
GUID ambiguity, equal timestamps, malformed schemas, nonexistent references,
scope violations, altered evidence, untrusted text and operational failures.

The model timeout covers each model request, not corpus loading, custom providers
or the whole investigation. Async callers use `asyncio.to_thread`; orchestration,
whole-run cancellation and cross-source reconstruction remain downstream work.
See the [provider and orchestrator handoff](../docs/ENDPOINT_PROVIDER_HANDOFF.md)
and [implementation review](../docs/ENDPOINT_IMPLEMENTATION.md).

Correctness amendment (2026-10-19): prompt/config v3 uses batch-local annotation indices to reduce model
response overhead. Python expands each valid index to the original immutable finding and evidence IDs;
unknown, duplicate or mixed references fail validation. All evidence facts and global process links remain
in the prompt/result. Local installed Qwen2 BPE counting replaces the byte bound when available; unsupported
tokenizers retain the conservative bound. Unchanged tool results keep completed batches; new evidence
invalidates prior annotations. The production orchestrator also bounds each call by the task's remaining
deadline and prevents later calls after expiry. Custom uncooperative providers/extensions still require
their own cancellation support. See [correctness remediation](../docs/CORRECTNESS_REMEDIATION.md).
