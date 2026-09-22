# Authentication corpus integration and validation

Validated on 2026-09-23, starting from merged PR #8 (`d9291b9`). The checkout was
clean, latest `origin/main` was fetched, and work was isolated on
`codex/authentication-corpus-integration`. Original datasets, evaluation answer
keys, scenario identifiers, evidence IDs and existing public APIs are unchanged.
No private evaluation directories, answer keys or scenario runbooks were read.

## Implementation and boundaries

`m3/investigate_corpus.py` loads the existing digest-verified `EventStore`, creates
`M2AuthenticationProvider`, and calls the unchanged `investigate()` function.
It accepts corpus, scenario, bounded UTC window and installed local model settings.
It checks model metadata before supplying evidence and returns structured JSON.
The new installed command is `mair-investigate-authentication`. Synthetic commands
remain compatible. No extra parser, normaliser, detection engine, query API,
event store, endpoint investigator or orchestrator was implemented.

Exit 0 means completed (possibly empty), 1 an investigation failure with no
findings, 2 setup failure, and 3 completed with truncation. Exit 2 has a compact
setup diagnostic, not the typed investigation envelope. Existing result schema
and `status` values are preserved; uncertainty carries incomplete coverage.

Names in current manuals, architecture, integration handoffs, processing CLI
messages and the Python Actions check now identify responsibilities. Numeric
packages/classes, schemas, version strings, evidence/finding IDs, filenames and
historical recorded reports remain compatible. See [architecture](ARCHITECTURE.md).
The processing implementation changed only display text; its query/adapter/store
behavior was not silently modified.

## Corpus and real-event findings

`git lfs pull` confirmed all six real EVTX exports. The existing processing CLI
verified source digests and wrote **6,661 records**: S01 2,700; S02 1,930; S03 2,031.
`EventStore.load()` verified the output digests. Corpus/source digests are embedded
in the [final manifest](validation/authentication-corpus-2026-09-23/final-ollama/manifest.json).
The same original LFS objects remained intact after testing.

The windows below are public telemetry selections, not labels or expected attack
stages. All timestamps are UTC, and the end is exclusive.

| Scenario | Window | Findings | Failed / successful logons |
| --- | --- | ---: | ---: |
| S01 | 2022-08-31 17:46:00–17:49:00 | 6 | 0 / 6 |
| S02 | 2026-09-21 02:04:30–02:06:00 | 7 | 5 / 7 |
| S03 | 2026-09-21 02:24:50–02:26:00 | 7 | 2 / 7 |

Every natural investigation completed with schema-valid, evidence-supported
findings. Counts, entity associations, seven-digit timestamp strings, chronological
ordering, scope and exact readback passed checks against actual retrieved records.
Missing optional fields retained uncertainty rather than invented values.
`S02-SEC-43584` remained Security 4624 at `2026-09-21T02:05:30.0430374Z`;
`S03-SEC-43584` remained a different, non-authentication 4688 record and was excluded.
A real one-tick window tested inclusive/exclusive boundaries.

The selected windows do not cover every authentication event in the exports.
Full-export authentication counts are 6, 20 and 17 respectively. Findings count
only the retrieved subset; they are not accuracy measurements or independent
Evidence Verification & Evaluation results.

## Actual automated checks

| Check | Actual result |
| --- | --- |
| Unmodified baseline suite | 636 passed, 1 skipped |
| Final default suite, original EVTX available | **659 passed, 1 skipped**, 109.02 s |
| CI-shaped suite with absent EVTX root | **621 passed, 39 skipped**; explicit real-data skips and optional model skip |
| Existing live synthetic Ollama smoke | **1 passed, 659 deselected** |
| Existing synthetic fake validation runner | **16/16 passed** |
| New real-corpus fake runner | **11/11 passed** |
| Generic provider contract against actual adapter | **11 passed, 1 failed**; compatibility scope difference below |
| Additional constructor isolation regression | **1 failed**; component issue below |
| Combined explicit diagnostic | **11 passed, 2 failed**, exit 1; assertions unchanged, no expected-failure marks |
| New module CLI and installed console CLI | Real S02 fake/local-model runs completed, 7 findings |
| Packaging | Wheel built; isolated `python -I` import from the wheel ran S01 against the real corpus, 6 findings |
| Dependency consistency | `python -m pip check` passed |

Logs: [default suite](validation/authentication-corpus-2026-09-23/full-suite.txt),
[CI shape](validation/authentication-corpus-2026-09-23/ci-shape.txt),
[live smoke](validation/authentication-corpus-2026-09-23/live-smoke.txt),
[compatibility diagnostics](validation/authentication-corpus-2026-09-23/provider-contract.txt).
The new default integration file adds 23 cases, covering actual retrieval/counts,
IDs, precision, entities, missing values, empty/truncated results, corrupted corpus,
scope rejection, fabricated citations, simulated timeout/connection errors, local
model preflight, CLI exits and configuration. Existing synthetic tests still pass.

Default discovery deliberately excludes the separately invoked diagnostic module
under `m3/testing/`; these pre-existing shared-boundary differences are not hidden
by changing assertions or counted as conformance passes. Default-suite success
must always be reported alongside the diagnostic failures.

## Actual local Ollama results

Ollama **0.34.2**, installed **qwen3:8b**, digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`.
Requests used loopback `127.0.0.1:11434`, context **8192**, thinking **false**,
temperature **0**, seed **0**, 2048 output tokens and 60-second per-request deadline.
Preflight confirmed installed weights and no remote model/host alias. The existing
service and installed models were preserved; no service was restarted or downloaded.
This remains a provisional local model selection, not a team-wide decision.

The [final local-model matrix](validation/authentication-corpus-2026-09-23/final-ollama/manifest.json)
passed **6/11 checks** and correctly returned **exit 1**. The earlier
[initial matrix](validation/authentication-corpus-2026-09-23/ollama/manifest.json)
also passed 6/11; it precedes final naming/preflight changes. Both are retained.

| Exercise | Final observation |
| --- | --- |
| Natural S01, S02, S03 | Completed; factual checks passed; optional interpretations null |
| Empty known-scenario window | Completed empty with uncertainty; passed |
| Two-event bounded query | Explicit truncation, 2 supported successes; passed |
| Directed interpretation | Qualified interpretation with exact citations; passed |
| Directed existing lookup | Model finished instead of requesting lookup; failed requested plan |
| Directed missing lookup | Model requested existing `S02-SEC-43503` instead of absent `S02-SEC-999999999`; failed plan and missing-lookup reporting check |
| Directed success-only query | Model finished instead of requesting the query; failed requested plan |
| Directed account history | Model finished instead of requesting history; failed requested plan |
| One-call budget exercise | Model finished within budget instead of requesting a second tool; intended exhaustion path was not exercised; failed exercise |

The historical synthetic 15/16 result is not claimed to be resolved. Directed
selection is still unreliable and failed more exercises on this matrix. The
missing-ID substitution did not fabricate an event: it retrieved a real existing
record, but did not answer the requested lookup. All three approved tool paths
were exercised by deterministic real-provider tests/fake runner. This live matrix
only observed an additional exact-event lookup beyond mandatory initial queries;
local-model selection of all three tools is **not** claimed.

The budget exercise's failed expectation is not an observed budget bypass: only
one tool was used. Deterministic tests/fake runner actually trigger exhaustion
and return `tool_budget_exhausted` with no findings. Simulated timeout/error paths
are tested; no real timeout occurred in this final matrix. All completed matrix
results still passed independent factual readback against EventStore, including
the five cases whose requested tool plans failed. No validation was weakened.

Assistant JSON, result envelopes and provider receipts are saved per case. No
thinking text, private evaluation content or personal system specifications are
recorded. Byte hashes for all 11 fake and 11 final-model artifacts, all 42 source
files listed per manifest, and the corpus manifest matched disk readback at
validation. The initial matrix retains its earlier source hashes; do not treat
them as hashes of the final working tree. Source hashes include exact line endings;
a different checkout can legitimately differ. Validation artifacts are preserved
by existing `docs/validation/** -text` attributes.

## Remaining processing and orchestration dependencies

1. **Lookup scope agreement:** the unchanged generic contract expects the
   non-logon fixture `SYN-A-SEC-99` (4634) from exact lookup. The actual provider
   deliberately offers only 4624/4625. Its documented authentication queries work.
   Generic fixtures also exceed the EVTX string-field schema; the diagnostic
   explicitly uses unchecked test-only records to probe the actual adapter without
   altering fixtures. This is not a production ingestion path. Agree whether the
   generic contract should specify authentication-only lookup before changing it.
2. **Constructor ownership:** `EventStore([event])` retains caller-owned mutable
   `event_data`. A caller mutation changes lookup results. The focused regression
   reproduces this using a valid normalised event. Proposed smallest fix: copy the
   record's dictionary at construction before indexing. The new entry point uses
   `EventStore.load()`, which does not expose those constructor inputs. The engine
   owner must review the fix; no implementation change was made.
3. **Actual orchestrator integration:** the call boundary and envelopes are tested,
   but no orchestrator dispatch, Endpoint Investigation Agent combination,
   cross-source reconstruction, cancellation/retry policy, or final envelope
   agreement has been connected. See the [handoff](M3_TO_M5_HANDOFF.md).

Exact reproductions and proposed ownership are in the
[processing handoff](M3_TO_M2_HANDOFF.md). Baseline scoring and project-wide
accuracy evaluation are separate and were not performed.

## Changed files

- New entry point: `m3/investigate_corpus.py`; console command in `pyproject.toml`.
- New runner: `m3/validate_corpus.py`; existing recording helpers in
  `m3/validate_synthetic.py` accept provider injection and a trace scope.
- Verification: `tests/test_authentication_corpus.py`,
  `m3/testing/check_processing_contract.py`; existing factual checker reused with
  descriptive diagnostic text. Runtime agent logic and public schemas unchanged.
- Display-only processing changes: `m2/__main__.py`. Actions display name:
  `.github/workflows/python-tests.yml` now shows `Python and contribution tests`.
- Current documentation: root README, both package READMEs, CONTRIBUTING,
  ARCHITECTURE, this report, both authentication handoffs, and processing schema,
  query, detection and metric-proposal docs. Historical handoffs/reports receive
  only a current-status notice; their recorded findings are not rewritten.
- Evidence: `docs/validation/authentication-corpus-2026-09-23/` contains preserved
  fake/model matrices, command outputs, logs and hash readback receipts.

The Python check's job id remains `tests`. The current main ruleset has no named
required check contexts. No repository settings were changed. CONTRIBUTING notes
that any future rule using the old display name must be updated by a maintainer.
The feature branch is intended for a reviewable PR, with no automatic merge.

## Reproduce

Run from the repository root (PowerShell). These commands use only the public
exports and a local installed model:

```powershell
python -m pip install -e '.[test]'
git lfs pull --include='datasets/S01/raw/*.evtx,datasets/S02/raw/*.evtx,datasets/S03/raw/*.evtx'
git lfs ls-files
python -m m2 normalise --datasets datasets --out out/corpus
python -m pytest -q --basetemp .test-tmp/reproduce
python -m pytest -q tests/test_authentication_corpus.py --basetemp .test-tmp/integration-reproduce
# Expected nonzero until shared issues are resolved: 11 pass, 2 fail.
python -m pytest -q m3/testing/check_processing_contract.py --tb=short --basetemp .test-tmp/contract-reproduce

python -m m3.investigate_corpus --corpus out/corpus --scenario S01 --start 2022-08-31T17:46:00Z --end 2022-08-31T17:49:00Z --model qwen3:8b
python -m m3.investigate_corpus --corpus out/corpus --scenario S02 --start 2026-09-21T02:04:30Z --end 2026-09-21T02:06:00Z --model qwen3:8b
python -m m3.investigate_corpus --corpus out/corpus --scenario S03 --start 2026-09-21T02:24:50Z --end 2026-09-21T02:26:00Z --model qwen3:8b

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
python -m m3.validate_synthetic --mode fake --output-dir "out/validation/synthetic-$stamp"
python -m m3.validate_corpus --corpus out/corpus --mode fake --output-dir "out/validation/fake-$stamp"
# Recorded model run exits 1 for failed directed-tool exercises.
python -m m3.validate_corpus --corpus out/corpus --mode ollama --model qwen3:8b --output-dir "out/validation/ollama-$stamp"

$env:MAIR_RUN_OLLAMA_SMOKE = '1'
$env:MAIR_OLLAMA_MODEL = 'qwen3:8b'
$env:MAIR_OLLAMA_ENDPOINT = 'http://127.0.0.1:11434'
$env:MAIR_OLLAMA_NUM_CTX = '8192'
$env:MAIR_OLLAMA_THINK = 'off'
python -m pytest -q -m ollama
Remove-Item Env:MAIR_RUN_OLLAMA_SMOKE

$env:M2_DATASETS_DIR = Join-Path (Get-Location) 'out/no-evtx-ci'
python -m pytest -q --basetemp .test-tmp/ci-reproduce
Remove-Item Env:M2_DATASETS_DIR
python -m pip wheel --no-deps --no-build-isolation --wheel-dir out/wheels .
python -m pip check
```

Use new output directories; runners refuse overwriting prior evidence. A seed and
temperature zero do not guarantee identical model actions across runtime/hardware
changes. Inspect actual `check_errors`, not just completed investigation status.
