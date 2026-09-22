> Historical handoff/report: numbered role labels and recorded results are preserved.
> See [component names and current architecture](ARCHITECTURE.md) and the
> [current authentication integration report](AUTHENTICATION_CORPUS_INTEGRATION.md) for current status.

# M3 local validation and integration report

Validated on 2026-09-21, from PR #6's merged implementation (`b986680`), on
`m3/ollama-validation-and-integration`, preserved locally. Delivery was resumed
on 2026-09-22 on `codex/m3-ollama-validation`, based directly on `origin/main`
so the earlier commit containing personal system specifications is excluded
from the delivery history. **Qwen3 completed all nine natural
synthetic scenario runs with evidence-correct findings. The full development
runner passed 15 of 16 checks; one directed tool-selection check failed.**
At the 2026-09-22 refresh, M2's development branch `origin/m2/normaliser`
(`31add71`) contains normalisation and corpus writing, but its query and lookup
commands are still unimplemented. Neither M2 nor M5 is merged into `origin/main`,
and neither has an open delivery PR. Real-data integration remains waiting for
M2's read-only query provider and joint contract agreement; M5 integration awaits
its orchestrator.

## Runtime and model

Ollama was already running on port 11434, version **0.34.2**, initially with no
models. After the user's explicit selection, `qwen3:8b` was downloaded and used
locally. This is a **provisional M3 configuration**, not a team model agreement.

| Item | Observed configuration |
| --- | --- |
| Windows executable | `%LOCALAPPDATA%\Programs\Ollama\ollama.exe` (not on this shell's PATH) |
| Model | `qwen3:8b`, 8.2B parameters, Q4_K_M, 5,225,388,164 bytes on disk |
| Model digest | `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` |
| Validation server | `http://127.0.0.1:11435`, started from the normal Windows installation with `OLLAMA_NO_CLOUD=1` |
| Local-only confirmation | Server startup reported cloud disabled; model metadata identified local weights |
| Tested generation settings | `num_ctx=8192`, `think=false`, temperature 0, seed 0; 2048 output tokens; 60-second request deadline |
| Versions | Python 3.14.6; `m3-config-v2`; `m3-authentication-v2`; result contract remains `m3-provisional-v1` |

See [runtime evidence](validation/m3-qwen3-2026-09-21/runtime.json), with host
hardware identifiers and memory usage omitted for privacy. After testing,
the temporary server's model was unloaded and only that server was stopped.
The original port-11434 service was preserved and the downloaded model remains
installed; see [cleanup readback](validation/m3-qwen3-2026-09-21/cleanup.json).
No persistent server settings were changed. For configuration semantics, see
[Ollama local-only mode](https://docs.ollama.com/faq#how-do-i-disable-ollama-cloud-features)
and [thinking controls](https://docs.ollama.com/capabilities/thinking).

## Actual inference and evidence checks

The [final manifest](validation/m3-qwen3-2026-09-21/final-run/manifest.json)
links all 16 actual results, assistant JSON replies, provider-call receipts,
timings, configuration and source hashes. Each investigation used the packaged
synthetic corpus and the window `[2026-01-10T00:00:00Z, 2026-01-10T00:01:00Z)`.

| Case | Findings | Failed / successful logons | Observed result |
| --- | ---: | ---: | --- |
| A: failures then success | 1 | 3 / 1 | Correct sequence and full evidence IDs |
| B: benign lookalike | 1 | 0 / 2 | Successful activity described without an attack claim |
| C: failures only | 1 | 3 / 0 | No success invented |
| D: multiple entities | 6 | 2 / 4 | Separate account, host and source combinations preserved |
| E: empty window | 0 | 0 / 0 | Explicit uncertainty, no invented findings |
| F: incomplete fields | 3 | 1 / 2 | Missing, conflicting and malformed optional fields qualified |
| H1: shared record 42 | 1 | 1 / 0 | `SYN-H1-SEC-42` resolved to its own scenario |
| H2: shared record 42 | 1 | 0 / 1 | `SYN-H2-SEC-42` remained distinct |
| I: close timestamps | 1 | 2 / 1 | Record order 3, 2, 1; original seventh fractional digits retained |

Case G was exercised through an actual model-requested lookup of
`SYN-A-SEC-999`: the provider returned `None`, uncertainty reported not found,
and the ID was never cited. Other directed exercises passed for exact existing
lookup, account history, a two-event truncated query, and an optional qualified
interpretation. With a one-call budget, a requested additional lookup produced
`tool_budget_exhausted` and no findings, as expected.

The remaining **failed check** is
[query_tool.json](validation/m3-qwen3-2026-09-21/final-run/query_tool.json):
the developer exercise requested a success-only `query_authentication_events`
call, but Qwen3 chose `get_authentication_event` for `SYN-A-SEC-1`. Its final
observations were still supported by the mandatory initial query. The runner
correctly returned exit code 1; this is not an all-passing model validation.
All three approved tool names were emitted and executed across the recorded
runs, including a query in [an earlier attempt](validation/m3-qwen3-2026-09-21/run-1/get_missing.json),
but that earlier query also differed from the requested lookup. Exact tool-plan
compliance is therefore unreliable. Required retrieval must stay in deterministic
code. These are M3's structured JSON actions; native Ollama `tools` function
calling was not used or tested.

For all nine natural runs the model selected finish with no annotations, giving
`interpretation: null`. The separate
[interpretation exercise](validation/m3-qwen3-2026-09-21/final-run/interpretation.json)
returned `may_warrant_review` with the complete supporting ID array. Counts,
entities, timestamps and relationships are computed by Python, not authored by
the model. These results establish local execution and synthetic correctness,
not model detection accuracy or independent M6 verification.

`m3/testing/factual_checks.py` independently checks the returned schema, counts,
entity associations, scenario/window membership, original timestamps, ordering,
failure/success relationships, reference coverage, uncertainty and qualified
interpretations against retrieved original fixture records. M3 also performs
exact provider readback before returning findings. The tests never use the
model's explanation as factual proof or read private evaluation materials.

## Defects, fixes and retained failures

| Finding | Resolution and evidence |
| --- | --- |
| Initial 32768-context/default-thinking SYN-A run timed out | Retained [baseline result](validation/m3-qwen3-2026-09-21/baseline-syn-a.json). Added explicit CLI/environment context and thinking controls. The combined 8192/think-off profile completed; the effects of those settings were not isolated experimentally. |
| Qwen3 then mixed a tool action with final annotations | Retained [invalid reply](validation/m3-qwen3-2026-09-21/configured-syn-a-model-reply.json) and [failed result](validation/m3-qwen3-2026-09-21/configured-syn-a.json). Python already rejected it, but the JSON schema did not express the cross-field rule. Separate typed tool/finish alternatives now expose that rule to structured decoding. Prompt v2 clarifies complete observation IDs and optional annotations. [Fixed SYN-A](validation/m3-qwen3-2026-09-21/fixed-syn-a.json) completed. |
| Directed-tool checker rejected explicit default arguments | Compare validated argument models, preserving exact query semantics. Regression checks accept equivalent defaults and reject changed hosts/tools. |
| Windows newline translation invalidated artifact hashes | Write and hash identical UTF-8 bytes; add regression coverage and `docs/validation/** -text` Git attributes. All 16 final artifact hashes and 8 source hashes matched disk readback. |
| Qwen3 selected a different allowed tool in the query exercise | Preserved as a model limitation, with no relaxation of evidence checks or automatic model substitution. |

Earlier `run-1`, `run-2` and `run-3` directories are retained as historical
attempts. Their case-file hashes were generated before the newline fix and
**do not match their Windows-written files**; those hashes are not authoritative.
Use `final-run/manifest.json` for the corrected recorded run. Source hashes
identify exact working-tree bytes, including line endings; a later checkout
with different source line endings can legitimately differ. Result artifacts
are preserved byte-for-byte by the new Git attributes.

## Automated validation and delivery status

Recovery checks on 2026-09-22 repeated the normal suite (**156 passed, 1 skipped**,
`python -m pytest -q --basetemp .test-tmp/privacy-resume-pytest`), fake runner
(**16/16**), live Ollama smoke test (**1 passed, 156 deselected**) and live
programmatic M5 example. The 16 saved final results passed hash and factual
readback, and all eight source hashes matched after restoring the original mixed
line endings from hash-matched local build copies; source text is unchanged.
The complete real-model matrix below remains the recorded 2026-09-21 run.
The recovery's dedicated local-only server was stopped after testing, with the
original port-11434 service and installed model confirmed intact.

| Check | Actual result |
| --- | --- |
| `python -m pytest -q --basetemp .test-tmp/pytest` | **156 passed, 1 skipped**; includes contribution-policy tests; skip is the opt-in Ollama test |
| `python -m pytest -q -m ollama` with the configuration below | **1 passed, 156 deselected** |
| Fake development runner | **16/16 checks passed**, exit 0 |
| Real Qwen3 development runner | **15/16 checks passed**, exit 1 for the directed query selection |
| M2 provider contract | All 12 reusable checks passed against the existing in-memory provider |
| M5 example | Success, empty and timeout envelopes tested; live programmatic SYN-A invocation completed |
| Wheel | Built with `pip wheel --no-deps --no-build-isolation`; isolated import from the wheel ran the M5 example, fixture loading and SYN-I validation |
| GitHub Actions | Consult the delivery PR for hosted checks and merge status |

Completed and tested: local inference, schema correction, configurable runtime
profile, synthetic evidence assertions, reusable provider contract, M5 example,
and these handoffs. Implemented but not tested against external components:
the provider/call boundaries have only been exercised with the synthetic
provider; no real M2 adapter or M5 orchestrator is claimed. Waiting for M2/M5:
M2's query provider, M5's orchestrator and shared contract decisions. Failed/limited: exact
Qwen3 tool selection above, the retained initial failures, and real-data testing
which cannot proceed without M2. No original dataset or other member's code was
modified; no EVTX ingestion or reconstruction functionality was added.

The separate [M2 handoff and message](M3_TO_M2_HANDOFF.md) specifies normalized
records/query delivery, collision-safe identity, precise timestamps, exact
lookup, bounded queries and adapter conformance. The
[M5 handoff and message](M3_TO_M5_HANDOFF.md) specifies invocation, provider/LLM
injection, output envelopes, errors, worker-thread use and open contract choices.
The messages are prepared for the user and have not been sent. To finish
integration, connect M2's agreed provider, run its contract tests and public-data
readback, then test M5 dispatch and consumption using the agreed result envelope.

## Reproduce on Windows

From the repository root with Python 3.11 or later, install dependencies once:

```powershell
python -m pip install -e '.[test]'
python -m pytest -q --basetemp .test-tmp/pytest
python -m pytest -q m3/tests/test_provider_contract.py m3/tests/test_m5_example.py
python -m m3.examples.invoke_m3
python -m m3.examples.invoke_m3 --scenario SYN-E
```

In a separate PowerShell terminal, confirm the installed model and start a
dedicated loopback server on an unused port. The validation helper was stopped
after testing, so start it again before the live commands. Do not start a second
listener if something already owns this port. These commands do not download
weights or reconfigure the existing desktop service:

```powershell
$ollamaExe = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'
& $ollamaExe --version
& $ollamaExe list
Invoke-RestMethod 'http://localhost:11434/api/tags'
$env:OLLAMA_HOST = '127.0.0.1:11435'
$env:OLLAMA_NO_CLOUD = '1'
& $ollamaExe serve
```

In the repository terminal, use the tested profile:

```powershell
$env:MAIR_OLLAMA_MODEL = 'qwen3:8b'
$env:MAIR_OLLAMA_ENDPOINT = 'http://127.0.0.1:11435'
$env:MAIR_OLLAMA_NUM_CTX = '8192'
$env:MAIR_OLLAMA_THINK = 'off'
python -m m3 --mode ollama --scenario SYN-A --start 2026-01-10T00:00:00Z --end 2026-01-10T00:01:00Z
python -m m3.examples.invoke_m3 --ollama
$env:MAIR_RUN_OLLAMA_SMOKE = '1'
python -m pytest -q -m ollama
Remove-Item Env:MAIR_RUN_OLLAMA_SMOKE
```

Run the complete development matrix into **new** directories; the runner refuses
to overwrite earlier results. The recorded real run returned 1 for the known
query-selection check; inspect `check_errors` rather than assuming success:

```powershell
$runStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
python -m m3.validate_synthetic --mode fake --output-dir ".test-tmp/fake-$runStamp"
python -m m3.validate_synthetic --mode ollama --model qwen3:8b --endpoint http://127.0.0.1:11435 --num-ctx 8192 --think off --output-dir ".test-tmp/qwen3-$runStamp"
```

Check the saved final result bytes independently:

```powershell
$resultDir = 'docs/validation/m3-qwen3-2026-09-21/final-run'
$manifest = Get-Content -LiteralPath "$resultDir/manifest.json" -Raw | ConvertFrom-Json
foreach ($case in $manifest.cases) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $resultDir $case.file)).Hash
    if ($actual.ToLowerInvariant() -ne $case.sha256) { throw "Hash mismatch: $($case.file)" }
}
```

Use Ctrl+C in the dedicated server terminal after the rerun. Outputs can vary
across model/runtime/hardware versions despite temperature 0 and a fixed seed.
