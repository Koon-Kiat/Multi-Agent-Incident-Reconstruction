# Authentication corpus integration and validation

Updated 2026-09-23 after safely merging PR #10 (`9dfe89c`) into
`codex/authentication-corpus-integration` with merge commit `d9d9a63`.
The initial working tree was clean. Main was fetched, compared and merged without
rewriting history. The descriptive `event_processing/`, `authentication_agent/`
and `CorpusAuthenticationProvider` interfaces remain authoritative. PR #9 stays
open for review; the Incident Reconstruction Orchestrator is not implemented.

## Fixes inherited from PR #10

The merged provider distinguishes exact lookup from filtered queries:

- `get_event()` preserves any supported Security record, including 4634/4688.
  Missing/malformed IDs and Sysmon records return `None`.
- `query()` offers only Security 4624/4625, as permitted by `QueryRequest`.
- The agent separately validates scenario, window, event type and final exact
  readback. Real 4634/4688 lookup tests fail at that boundary with
  `provider_scope_violation` and no findings.
- `EventStore` deep-copies constructor inputs and detaches returned records.
  The original ownership regression now passes. This fix belongs to PR #10.
  The broader store remains available to other components for cross-source access.

All **12 original reusable provider-contract checks pass** against the actual
integrated adapter. PR #10's default-discovery wrapper and the earlier explicit
diagnostic both exercise the unchanged generic suite. The latter reports
**13 passed** including the original constructor regression. Generic fixtures use
unchecked test-only records for fields outside the EVTX schema; production corpus
validation remains strict. No generic assertion was relaxed, skipped or marked xfail.

The merge also retains protected output paths, manifest/schema validation,
detection-output ownership and staging, scoring input/corpus-revision validation,
error handling, zero-hit rule reporting and R-EXEC-02 version 2. These fixes were
ported to the descriptive packages rather than reimplemented independently.

An isolated replay of unchanged PR #10 reproduced its original pinned corpus and
detection digests. Integrated event JSONL is byte-identical. Detection content is
identical after excluding renamed schema metadata and its dependent corpus hash.
Against the prior feature run, only the recorded R-EXEC-02 version changes from
1 to 2; detection counts remain **S01 9 / S02 15 / S03 14**. Current byte and
canonical hashes were updated only after these comparisons. See
[integration readback](validation/authentication-pr10-2026-09-23/integration-readback.json).
No threshold, trigger, window or expected count was adjusted to obtain a pass.

## New changes in this session

`ModelReply` now pairs each approved tool name with its actual argument model
in both the decoder's JSON schema and host-side parsing. Unknown keys, omitted
required arguments and arguments for a different tool are rejected. The public
`ToolCall` and result wire shapes remain unchanged. Tool scope/budget checks and
exact-reference validation remain in place after parsing. Five additional model
regressions cover mismatched argument shapes and a valid unknown-ID lookup.

The prompt now gives an explicit trusted tool request precedence over the default
finish preference and explains that a requested lookup ID can be absent. It also
encourages finishing empty windows instead of repeating retrieval. Versions are
`authentication-prompt-v4` and `authentication-config-v3`; results remain
`authentication-result-v1`, with `AUTH-` finding IDs. Two real-corpus regressions
verify the provider's broader exact lookup cannot introduce unsupported types
into authentication findings. The original stale 4688 lookup assertion was
updated to the agreed contract, not removed.

## Current automated and local verification

| Check | Result |
| --- | --- |
| Full suite with real EVTX, final prompt | **734 passed, 3 skipped** |
| CI-shaped local suite without EVTX | **694 passed, 43 skipped** |
| Actual adapter: original reusable contract | **12 passed** |
| Original explicit contract + ownership diagnostic | **13 passed** |
| Synthetic fake matrix | **16/16** |
| Real-corpus fake matrix | **11/11** |
| Final real-corpus local-model matrix | **7/11**, exit 1; four directed plans failed |
| Final synthetic local-model matrix | **15/16**, exit 1; success-only query selected a different tool |
| Explicit live smoke | **1 passed, 736 deselected** |
| Final wheel | Fresh staging, descriptive package paths only; isolated wheel import runs real S01 with 6 findings |
| Dependency consistency | `python -m pip check` passed |

Full-suite skips are the opt-in live smoke and two Windows symlink cases.
The live smoke runs separately; Linux CI exercises symlinks. CI-shaped skips add
40 tests requiring real EVTX. Logs: [full suite](validation/authentication-pr10-2026-09-23/full-suite-v4.txt),
[CI shape](validation/authentication-pr10-2026-09-23/ci-shape-v4.txt),
[12-check contract](validation/authentication-pr10-2026-09-23/provider-contract.txt),
[original diagnostic](validation/authentication-pr10-2026-09-23/original-diagnostic.txt),
[wheel](validation/authentication-pr10-2026-09-23/package-verification-v4.json),
[live smoke](validation/authentication-pr10-2026-09-23/live-smoke-v4.txt),
[synthetic model matrix](validation/authentication-pr10-2026-09-23/synthetic-ollama-final-v4/manifest.json).

## Real corpus and evidence safeguards

The digest-verified corpus holds **6,661 records**: S01 2,700, S02 1,930,
S03 2,031. All six original EVTX objects remain unchanged against their Git LFS
hashes. No source export, private evaluation material, answer key or runbook was
modified or supplied to the model. Validation uses public telemetry windows:

| Scenario | UTC window, start inclusive / end exclusive | Findings | Failures / successes |
| --- | --- | ---: | ---: |
| S01 | 2022-08-31 17:46:00-17:49:00 | 6 | 0 / 6 |
| S02 | 2026-09-21 02:04:30-02:06:00 | 7 | 5 / 7 |
| S03 | 2026-09-21 02:24:50-02:26:00 | 7 | 2 / 7 |

Natural investigations passed factual checks for counts, entities, chronological
ordering, original seven-digit timestamps and exact evidence readback. Missing
optional fields retain uncertainty. The one-tick query boundary remains tested.
`S02-SEC-43584` is 4624 at `2026-09-21T02:05:30.0430374Z`;
`S03-SEC-43584` is a distinct 4688 record, returned by exact lookup but excluded
from authentication queries/findings. Fabricated, changed, missing and
cross-scenario citations still fail closed. Empty and truncated results retain
explicit uncertainty; operational failures return no partial findings.

These windows cover 27 authentication records; full exports contain 6, 20 and 17
respectively. They are bounded integration checks, not detection accuracy,
independent Evidence Verification & Evaluation or end-to-end reconstruction.

## Qwen3 tool-selection investigation

All corpus experiments ran against actual local **Ollama 0.34.2 / qwen3:8b**,
digest `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`,
loopback endpoint, context 8192, thinking off, temperature 0, seed 0,
2048 output tokens and a 60-second per-request deadline. Preflight verified
installed local weights and no cloud-backed alias. No model was downloaded.

| Experiment | Checks | Empty-window tool calls, including initial query | Evidence |
| --- | ---: | ---: | --- |
| Fresh integrated baseline, original prompt/schema | 6/11 | 1 | [baseline](validation/authentication-pr10-2026-09-23/ollama-baseline/manifest.json) |
| Prompt v3 only | 8/11 | 8 | [prompt experiment](validation/authentication-pr10-2026-09-23/ollama-prompt/manifest.json) |
| Prompt v3 + typed schema | 8/11 | 8 | [typed experiment](validation/authentication-pr10-2026-09-23/ollama-typed/manifest.json) |
| Repeat of typed v3 | 8/11 | 8 | [repeat](validation/authentication-pr10-2026-09-23/ollama-final/manifest.json) |
| Final prompt v4 + typed schema | **7/11** | **2** | [current run](validation/authentication-pr10-2026-09-23/ollama-final-v4/manifest.json) |

The original 6/11 result was rerun, not assumed current. Removing the conflicting
finish preference improved prescribed-tool selection but introduced redundant
queries. The final prompt limits that regression to one extra empty-window query
in this run, while losing the v3 budget-exercise selection. That tradeoff remains
visible; neither version reliably executes prescribed plans. The typed schema
makes arguments concrete but did not alone improve the measured pass count.
This follows Ollama's documented [schema and validation interface](https://docs.ollama.com/capabilities/structured-outputs);
structured validity does not establish that the requested action was selected.

A [token-count probe](validation/authentication-pr10-2026-09-23/token-probe.json)
of the failing typed-v3 missing-ID request measured 5,222 prompt tokens plus 57
output tokens in an 8,192 context, with stop rather than length termination.
That measured failure is not explained by context exhaustion. Prompt/schema
sensitivity is observed; no general causal claim about Qwen3 internals is made.

The final live failures are explicit:

- Missing-ID request: asked for `S02-SEC-999999999`, looked up observed
  `S02-SEC-43571` instead; no missing-lookup uncertainty was produced.
- Success-only query and account-history requests: finished without executing
  the prescribed tools.
- One-call budget exercise: finished within budget rather than attempting the
  requested extra lookup. This fails the exercise, not the budget limit.

Natural S01-S03, empty/truncated windows, existing lookup and interpretation
checks pass. All completed results pass factual readback even when plan checks
fail. Fake/synthetic host tests still prove all tool paths and budget exhaustion.
The real model is never replaced with a fake, its responses are not rewritten,
and its schema is not pinned to the expected action or identifier. Directed
exercises test developer plans; they are not spontaneous investigative skill.
The final synthetic live run passes 15/16: its success-only query selects
account history instead. Natural synthetic cases and the synthetic budget
exercise pass; that does not remove the real-corpus plan failures.
No native Ollama function-calling claim is made.

## Handoff and unresolved work

The [orchestrator handoff](ORCHESTRATOR_HANDOFF.md) specifies invocation, typed
result handling, the broader exact-lookup contract, failure/empty/truncation
semantics, async worker-thread usage, limits and outstanding orchestration
decisions. Required retrieval must remain deterministic. A completed finding
set does not certify adherence to an external model plan. Do not retry unsupported
model behavior indefinitely.

Remaining issues are model plan-following/redundant queries and the separate
owners' orchestrator dispatch, deadlines/cancellation, bounded retries,
truncation continuation, endpoint findings and cross-source reconstruction.
No orchestrator implementation or end-to-end reconstruction claim is included.
Real baseline scoring remains blocked on agreed definitions and supplied labels;
no precision, recall or F1 was computed.

Per-case JSON, provider receipts, runtime/configuration and exact-byte hashes
are saved under `validation/authentication-pr10-2026-09-23/`. Prior evidence is
preserved, including superseded v3 experiments and the original integration
recordings. [Final readback](validation/authentication-pr10-2026-09-23/final-readback.json)
checks artifact hashes, final source hashes, corpus factual references and all
six original LFS hashes. Source hashes include local line endings; historical
source hashes are not claimed to match the final tree.

## Reproduce

```powershell
python -m pip install -e '.[test]'
python -m event_processing normalise --datasets datasets --out out/corpus
python -m pytest -q --basetemp .test-tmp/reproduce
python -m pytest -q event_processing/tests/test_authentication_provider_contract.py::TestCorpusAuthenticationProviderContract
python -m pytest -q authentication_agent/testing/check_processing_contract.py

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
python -m authentication_agent.validate_corpus --corpus out/corpus --mode fake --output-dir "out/validation/fake-$stamp"
# Exit 1 is the observed model-plan failure, not a successful matrix.
python -m authentication_agent.validate_corpus --corpus out/corpus --mode ollama --model qwen3:8b --output-dir "out/validation/ollama-$stamp"
python -m authentication_agent.validate_synthetic --mode fake --output-dir "out/validation/synthetic-fake-$stamp"
python -m authentication_agent.validate_synthetic --mode ollama --model qwen3:8b --num-ctx 8192 --think off --output-dir "out/validation/synthetic-ollama-$stamp"

$env:MAIR_RUN_OLLAMA_SMOKE = '1'
$env:MAIR_OLLAMA_MODEL = 'qwen3:8b'
$env:MAIR_OLLAMA_NUM_CTX = '8192'
$env:MAIR_OLLAMA_THINK = 'off'
python -m pytest -q -m ollama
Remove-Item Env:MAIR_RUN_OLLAMA_SMOKE
$env:MAIR_DATASETS_DIR = Join-Path (Get-Location) 'out/no-evtx-ci'
python -m pytest -q --basetemp .test-tmp/ci-reproduce
Remove-Item Env:MAIR_DATASETS_DIR
python -m pip check
```

Use new output directories: validation refuses to overwrite recorded evidence.
The original generic suite is unchanged. Runtime/model changes can alter choices
even with fixed seed and temperature; inspect `check_errors`, not status alone.
