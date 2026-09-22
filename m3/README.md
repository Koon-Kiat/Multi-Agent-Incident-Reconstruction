# Authentication Investigation Agent

The agent describes bounded Windows Security authentication evidence and lets a
local model select optional tentative interpretations. It now runs against the
Event Processing & Detection Engine's corpus through `M2AuthenticationProvider`.
The public `investigate(request, provider, llm, limits)` API, synthetic CLI,
schemas and IDs are unchanged. The orchestrator has not been connected.

## Real-data entry point

```powershell
python -m pip install -e '.[test]'
git lfs pull --include='datasets/S01/raw/*.evtx,datasets/S02/raw/*.evtx,datasets/S03/raw/*.evtx'
python -m m2 normalise --datasets datasets --out out/corpus
python -m m3.investigate_corpus --corpus out/corpus --scenario S02 --start 2026-09-21T02:04:30Z --end 2026-09-21T02:06:00Z --model qwen3:8b
```

`mair-investigate-authentication` invokes the same entry point. `--corpus`,
`--scenario`, `--start` and `--end` are required. Windows use UTC `[start,end)`;
all seven fractional digits survive retrieval and findings. Unknown scenarios
are rejected by this CLI; known scenarios with empty windows return completed
empty results with uncertainty.

Defaults: Ollama mode, `qwen3:8b`, endpoint `http://127.0.0.1:11434`, context 8192,
thinking disabled, temperature 0, seed 0. `--model`/`MAIR_OLLAMA_MODEL` and
`--endpoint`/`MAIR_OLLAMA_ENDPOINT` select local configuration. `--num-ctx` overrides
context. Preflight checks installed model metadata and rejects cloud-backed
aliases before sending evidence; nothing downloads weights. Endpoints must be
loopback; proxies and redirects are disabled. Use a trusted local Ollama service.
No private evaluation content enters model context.

`--mode fake` runs the same corpus/provider/investigation boundary without a
model server. `--schema` prints the unchanged result schema. JSON goes to stdout:

| Exit | Meaning |
| --- | --- |
| 0 | Completed, possibly empty; observations, not accuracy or compromise verdicts |
| 1 | Investigation failed; typed result, error code, no partial findings |
| 2 | Invalid setup, missing/altered corpus, absent scenario or failed model preflight; compact diagnostic, not `InvestigationResult` |
| 3 | Completed with truncation; typed result and explicit uncertainty; coverage incomplete |

Argparse usage errors also exit 2 with usage on stderr.

## Existing synthetic development

```powershell
python -m m3 --mode fake --scenario SYN-A --start 2026-01-10T00:00:00Z --end 2026-01-10T00:01:00Z
python -m m3 --mode ollama --model qwen3:8b --num-ctx 8192 --think off --scenario SYN-A --start 2026-01-10T00:00:00Z --end 2026-01-10T00:01:00Z
python -m m3.examples.invoke_m3
```

`mair-m3`/`python -m m3` still load only packaged synthetic fixtures and retain
their original exit codes. The synthetic Ollama CLI requires explicit model
selection and defaults to context 32768/thinking auto; the flags above select the
validated profile. Invented fixtures cover missing/conflicting fields, timestamp
ties, empty windows and scope failures.

## Provider and findings

`EventStore.load()` verifies corpus digests. Supply the same `Limits` to
`M2AuthenticationProvider` and `investigate`. Only Security 4624/4625 are exposed.
Exact lookup returns `None` for missing or unsupported authentication records.
The agent checks scenario, window, event type and consistency after retrieval,
then resolves cited records again before returning findings. See the
[provider handoff](../docs/M3_TO_M2_HANDOFF.md) for compatibility differences.

Query filters are exact and case-sensitive. Account uses non-null `user`, otherwise
a string `TargetUserName`. Empty values remain distinct from null. Records sort
by integer 100ns timestamp then evidence ID; ties imply no causal precedence.
`raw_reference` is preserved and never dereferenced by the agent.

Python constructs counts, timestamps, entity associations and evidence IDs.
Cohorts distinguish account, reported account, domain, host, source address,
workstation and logon type. Missing, malformed or conflicting identity dimensions
keep records separate and add uncertainty. Repeated failures before success are
an arithmetic observation, not an attack classification or baseline detector.

Each finding includes `finding_id`, `agent_type: authentication`, `scenario_id`,
`observed_events`, `timestamps`, `entities`, ordered `evidence_ids`, `uncertainty`
and nullable `interpretation`. The model may select `may_warrant_review`,
`context_required` or null for an existing observation with exact ordered IDs.
Python renders qualified text. Unsupported references fail the investigation;
no free-form model narrative becomes a finding.

Results contain status, request, findings, error code, uncertainty and metadata.
Empty results do not prove absence of activity. Failures contain no partial
findings. Truncated results cover only retrieved evidence, with no pagination or
completeness claim. Independent verification remains a separate responsibility.

## Limits and failure behavior

| Limit | Default |
| --- | ---: |
| Approved tools, including initial retrieval | 8 |
| Events per query | 100 |
| Window | 3600 seconds |
| Context bytes | 262144 |
| Event bytes | 16384 |
| Model response bytes | 32768 |
| Model output tokens | 2048 |
| Deadline per model request | 60 seconds |

CLI overrides: `--max-tool-calls`, `--max-events`, `--max-window-seconds`,
`--timeout`. `Limits` exposes all settings. Tool arguments cannot expand scope.
Mandatory retrieval remains deterministic because Qwen3 does not reliably follow
directed tool plans. Actions use the existing structured JSON protocol; native
Ollama function calling is not claimed.

Final exact-ID reads are outside the model tool count and bounded by the retrieved
union. The model deadline covers each HTTP request, not the whole investigation
or provider calls. Async callers must use `asyncio.to_thread`. Request construction,
preflight and corpus loading can raise before dispatch; failures inside
`investigate` return sanitized error codes. A custom provider's blocking call
cannot be forcibly cancelled by this synchronous protocol. Returned JSON includes
the evidence-derived entities requested by the caller.

## Tests and handoff

```powershell
python -m pytest -q --basetemp .test-tmp/full
python -m pytest -q tests/test_authentication_corpus.py --basetemp .test-tmp/integration
python -m pytest -q m3/testing/check_processing_contract.py --basetemp .test-tmp/compatibility
python -m m3.validate_corpus --corpus out/corpus --mode fake --output-dir out/validation/fake
python -m m3.validate_corpus --corpus out/corpus --mode ollama --model qwen3:8b --output-dir out/validation/ollama
```

Use new/empty output directories. The separately invoked compatibility diagnostic
retains known failures outside default discovery; see the
[current report](../docs/AUTHENTICATION_CORPUS_INTEGRATION.md). Default tests never
require a model. Public EVTX tests run with Git LFS content and otherwise skip
explicitly; private answers and expected classifications are never used.

The corpus validation runner records model version/digest, configuration,
exact-byte artifact/source/corpus hashes, assistant JSON and provider receipts.
It reuses the existing factual checker; the compatibility name
`check_synthetic_result` also accepts real retrieved records. These are development
checks, not independent verification, baseline scoring or detection accuracy.
Saved artifacts omit personal system specifications.

See [orchestrator invocation and result handling](../docs/M3_TO_M5_HANDOFF.md)
and [architecture](../docs/ARCHITECTURE.md). Endpoint investigation, incident
reconstruction and independent verification/evaluation remain separate
responsibilities. No new EVTX parser, normaliser, query API or storage is added.
