# Authentication corpus integration and validation

Validated on 2026-09-23 from the merged processing delivery in PR #8 (`d9291b9`).
The checkout was clean and latest main was fetched before work began on
`codex/authentication-corpus-integration`. The project owner subsequently requested
fully descriptive names, including internal interfaces. That request supersedes
the original package-compatibility constraint. Original evidence/scenario IDs,
raw datasets, investigation logic and evidence validation remain intact.

## Implemented functionality

`authentication_agent.investigate_corpus` loads the existing digest-verified
`event_processing.query.EventStore`, injects `CorpusAuthenticationProvider`, and
calls the existing `investigate()` logic. It accepts a corpus, scenario, bounded
UTC window and configured local model. Preflight confirms installed local weights
before supplying evidence. JSON results distinguish failure and incomplete coverage.
No parser, normaliser, detection engine, query API or storage system was duplicated.

The project distribution is `mair-incident-reconstruction` 0.2.0. Packages, imports,
class names, commands, schema identifiers, finding-ID prefixes, examples, documents
and current validation artifacts use descriptive names. A regression check finds
no retired role identifiers in tracked filenames or text. Original evidence IDs
such as `S02-SEC-43584` and scenario IDs such as `S01` are unchanged. See the
[migration guide](COMPONENT_NAMING.md) and [architecture](ARCHITECTURE.md).

This is an intentional breaking name migration: downstream consumers must update
imports/configuration and regenerate derived artifacts. There are no retired
package/command aliases. Earlier reports and exact model recordings are preserved
in Git history at `38ccd57` and `84f0cbe`; the current artifacts were executed
again under the new interfaces rather than editing historical model replies.

The installed real-data command is `mair-investigate-authentication`. Exit 0
means completed (possibly empty), 1 failed with no findings, 2 setup failure,
and 3 completed with truncation. Setup errors use a compact diagnostic, not the
typed investigation envelope. The result field structure and status choices
remain intact; its identifier is now `authentication-result-v1` and finding IDs
use `AUTH-`. The synthetic commands retain their behavior under descriptive names.

## Corpus and findings

Git LFS supplied all six public EVTX files. The existing normalisation CLI
verified their SHA-256 digests and produced **6,661 records**: S01 2,700; S02 1,930;
S03 2,031. Loading verified the written corpus digests. Source hashes and corpus
metadata are in the [model-run manifest](validation/authentication-corpus-2026-09-23/ollama/manifest.json).
No original exports, private evaluation material, answer keys or scenario runbooks
were modified or placed in model context. Private evaluation material was not read.

Windows are public telemetry selections, not attack-stage or expected labels.
Start is inclusive and end exclusive, with all seven timestamp digits retained.

| Scenario | UTC window | Findings | Failed / successful logons |
| --- | --- | ---: | ---: |
| S01 | 2022-08-31 17:46:00–17:49:00 | 6 | 0 / 6 |
| S02 | 2026-09-21 02:04:30–02:06:00 | 7 | 5 / 7 |
| S03 | 2026-09-21 02:24:50–02:26:00 | 7 | 2 / 7 |

All natural investigations returned schema-valid findings with supported counts,
entity associations, original timestamps, chronological order and exact evidence
readback. Missing optional fields retained uncertainty. A one-tick real query
verified half-open boundaries. `S02-SEC-43584` remains 4624 at
`2026-09-21T02:05:30.0430374Z`; `S03-SEC-43584` is a distinct 4688 event excluded
by the authentication provider. No cross-scenario or fabricated references passed.

These windows cover 27 authentication records; the complete exports contain
6, 20 and 17 respectively. Counts cover only retrieved evidence. They do not
measure detection accuracy or independent Evidence Verification & Evaluation.

## Actual automated verification

| Check | Actual result |
| --- | --- |
| Initial unmodified baseline | 636 passed, 1 skipped |
| Final suite with real EVTX | **660 passed, 1 skipped**, 92.27 s |
| CI-shaped suite without EVTX | **622 passed, 39 skipped** |
| Existing live synthetic Ollama smoke | **1 passed, 660 deselected** |
| Synthetic fake validation matrix | **16/16 passed** |
| Real-corpus fake validation matrix | **11/11 passed** |
| Unchanged generic contract against actual corpus adapter | **11 passed, 1 failed** |
| Additional constructor ownership regression | **1 failed** |
| Combined explicitly invoked diagnostic | **11 passed, 2 failed**, exit 1 |
| Module and installed real-data CLI | Fake and local-model S02 runs completed with 7 findings |
| Wheel | Built from fresh staging; no retired package paths; isolated wheel import ran real S01 with 6 findings |
| Dependency consistency | `python -m pip check` passed |

Logs: [full suite](validation/authentication-corpus-2026-09-23/full-suite.txt),
[CI shape](validation/authentication-corpus-2026-09-23/ci-shape.txt),
[live smoke](validation/authentication-corpus-2026-09-23/live-smoke.txt),
[diagnostics](validation/authentication-corpus-2026-09-23/provider-contract.txt).
Integration adds 23 cases plus the project naming regression. Tests cover real
counts/IDs/precision/entities, optional fields, empty/truncated results, corrupted
corpora, scope rejection, fabricated citations, simulated timeout/connection errors,
local-model preflight, CLI statuses and configuration. Synthetic tests still pass.

The diagnostic module is explicitly invoked outside default discovery. Its
shared-boundary failures remain actual failures, without relaxed assertions or
expected-failure marks. Always report them alongside the green default suite.

The name migration initially failed a pinned byte-hash test. Comparison against
the saved pre-migration corpus/detection outputs proved that event JSONL bytes,
all detection content, counts, trigger IDs, windows and relationships are identical.
Only `schema_version` and the dependent `corpus_manifest_sha256` changed. Updated
byte fixtures reflect those requested identifiers; added canonical behavior
hashes pin unchanged detection content separately. See
[migration readback](validation/authentication-corpus-2026-09-23/naming-migration-readback.json).
Detection thresholds and expected counts were not altered to obtain a pass.

## Actual local Ollama inference

Runtime: **Ollama 0.34.2**, installed **qwen3:8b**, digest
`500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`.
Loopback endpoint `127.0.0.1:11434`; context **8192**; thinking **false**;
temperature **0**; seed **0**; output limit 2048 tokens and 60 seconds per request.
Preflight confirmed installed weights with no remote model/host alias. The existing
service was preserved; no model was downloaded. This remains a provisional local
selection, not a final team model decision.

The [regenerated matrix](validation/authentication-corpus-2026-09-23/ollama/manifest.json)
passed **6/11 checks**, correctly returning **exit 1**:

| Exercise | Observed result |
| --- | --- |
| Natural S01, S02, S03 | Completed; factual checks passed; interpretations null |
| Empty window | Empty with uncertainty; passed |
| Two-event truncated query | Explicit incomplete coverage; 2 supported successes; passed |
| Directed interpretation | Qualified interpretation with exact citations; passed |
| Directed existing lookup | Finished instead of requesting lookup; failed plan |
| Directed missing lookup | Requested existing `S02-SEC-43503` instead of absent `S02-SEC-999999999`; failed plan and missing-lookup reporting |
| Directed success-only query | Finished instead of querying; failed plan |
| Directed account history | Finished instead of requesting history; failed plan |
| One-call budget exercise | Finished within budget; requested exhaustion path was not exercised; failed exercise |

The historical synthetic 15/16 limitation remains unresolved. The model still
fails externally prescribed tool plans. The missing-ID substitution retrieved an
actual existing record rather than fabricating one, but did not answer the
requested lookup. Mandatory retrieval remains deterministic. All three approved
tool paths ran through deterministic real-provider tests/fake validation; this
live matrix only observed an extra exact lookup beyond initial queries. Model
selection of all three tools is not claimed.

The budget exercise is not a budget bypass: only one tool call occurred. Tests
and the fake runner trigger exhaustion and correctly return `tool_budget_exhausted`
with no findings. Simulated errors/timeouts are tested; no real timeout occurred
in the current matrix. All completed matrix results, including failed tool-plan
exercises, passed factual readback against EventStore. Evidence checks were not
weakened. Structured JSON actions are used; native Ollama function calling is
not claimed.

Per-case assistant JSON, provider receipts and result envelopes are retained.
[Readback](validation/authentication-corpus-2026-09-23/readback.json) verified all
11 fake and 11 local-model artifact hashes, all 42 listed source hashes per run,
the corpus manifest, 16 synthetic artifacts/eight source hashes, and all six
unchanged original LFS objects. Source hashes include exact line endings; a
checkout with different line endings may differ. Artifacts retain exact bytes
under the existing Git attributes. No thinking text or personal system
specifications are recorded. Diagnostic console whitespace alone was trimmed.

## Unresolved component dependencies

- **Provider lookup agreement:** the generic contract expects non-logon fixture
  `SYN-A-SEC-99` (4634); the corpus adapter deliberately exposes only 4624/4625.
  Its authentication queries work. Generic fixtures exceed the EVTX string-field
  schema, so the diagnostic explicitly uses unchecked test-only records to probe
  the actual adapter without changing assertions. It is not an ingestion path.
- **Constructor ownership:** `EventStore([event])` retains the caller's mutable
  `event_data`; modifying that dictionary changes lookup results. Proposed smallest
  fix: detach it at construction before indexing. This entry point uses verified
  `EventStore.load()`, which does not expose those input objects. A focused failing
  regression is supplied; engine behavior is left for its owner to review.
- **Orchestrator delivery:** invocation and result consumption are demonstrated,
  but no actual Incident Reconstruction Orchestrator dispatch, Endpoint Investigation
  Agent combination, cross-source reconstruction or final shared contract has been
  connected. Owners must adopt the descriptive interfaces. Overall deadlines,
  cancellation, bounded retries and truncation continuation remain decisions.

See [provider issues and reproducers](AUTHENTICATION_PROVIDER_HANDOFF.md) and the
[orchestrator handoff](ORCHESTRATOR_HANDOFF.md). Baseline scoring and project-wide
accuracy evaluation are separate and were not performed.

## Files and delivery

Code lives under `event_processing/` and `authentication_agent/`. New functionality
is in `authentication_agent/investigate_corpus.py` and `validate_corpus.py`;
recording/factual helpers are reused. Tests are in
`tests/test_authentication_corpus.py`, `tests/test_component_naming.py` and the
explicit `authentication_agent/testing/check_processing_contract.py` diagnostic.
`pyproject.toml` defines the new distribution and commands. Current documentation
uses descriptive filenames throughout; `COMPONENT_NAMING.md` lists interfaces.
The dataset-verification scripts receive naming changes only and were not run
against private evaluation material.

The Python Actions check is named `Python and contribution tests`; its job id
remains `tests`. The current main ruleset has no named required check contexts;
repository settings are unchanged. A draft PR is prepared without merging main.
The original raw evidence and public metadata files remain unchanged.

## Reproduce from the repository root

```powershell
python -m pip install -e '.[test]'
git lfs pull --include='datasets/S01/raw/*.evtx,datasets/S02/raw/*.evtx,datasets/S03/raw/*.evtx'
python -m event_processing normalise --datasets datasets --out out/corpus
python -m pytest -q --basetemp .test-tmp/reproduce
# Expected nonzero until the shared issues are resolved: 11 pass, 2 fail.
python -m pytest -q authentication_agent/testing/check_processing_contract.py --tb=short --basetemp .test-tmp/contract-reproduce

python -m authentication_agent.investigate_corpus --corpus out/corpus --scenario S01 --start 2022-08-31T17:46:00Z --end 2022-08-31T17:49:00Z --model qwen3:8b
python -m authentication_agent.investigate_corpus --corpus out/corpus --scenario S02 --start 2026-09-21T02:04:30Z --end 2026-09-21T02:06:00Z --model qwen3:8b
python -m authentication_agent.investigate_corpus --corpus out/corpus --scenario S03 --start 2026-09-21T02:24:50Z --end 2026-09-21T02:26:00Z --model qwen3:8b

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
python -m authentication_agent.validate_synthetic --mode fake --output-dir "out/validation/synthetic-$stamp"
python -m authentication_agent.validate_corpus --corpus out/corpus --mode fake --output-dir "out/validation/fake-$stamp"
# The recorded model matrix exits 1 for directed-tool failures.
python -m authentication_agent.validate_corpus --corpus out/corpus --mode ollama --model qwen3:8b --output-dir "out/validation/ollama-$stamp"

$env:MAIR_RUN_OLLAMA_SMOKE = '1'
$env:MAIR_OLLAMA_MODEL = 'qwen3:8b'
$env:MAIR_OLLAMA_ENDPOINT = 'http://127.0.0.1:11434'
$env:MAIR_OLLAMA_NUM_CTX = '8192'
$env:MAIR_OLLAMA_THINK = 'off'
python -m pytest -q -m ollama
Remove-Item Env:MAIR_RUN_OLLAMA_SMOKE
$env:MAIR_DATASETS_DIR = Join-Path (Get-Location) 'out/no-evtx-ci'
python -m pytest -q --basetemp .test-tmp/ci-reproduce
Remove-Item Env:MAIR_DATASETS_DIR
python -m pip check
```

Use new output directories; runners refuse overwriting evidence. For a wheel,
use `python -m pip wheel --no-deps --no-build-isolation --wheel-dir out/wheels .`
in a fresh checkout so stale generated build caches cannot be packaged. A fixed
seed/temperature does not guarantee identical actions across runtime/hardware
changes. Inspect `check_errors`, not just completed investigation status.
