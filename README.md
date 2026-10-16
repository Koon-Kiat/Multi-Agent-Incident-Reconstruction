# Multi-Agent Incident Reconstruction (MAIR)

ICT3214 Security Analytics project. The Authentication Investigation Agent now
uses the Event Processing & Detection Engine's verified S01–S03 normalised
corpus through the existing read-only provider. Synthetic development remains
available. The Incident Reconstruction Orchestrator and Reconstruction Agent now
connect detection, both investigation agents and an ordered claim timeline end to
end, in three evaluation run modes; see [Run the full pipeline](#run-the-full-pipeline).

The Endpoint Investigation Agent now consumes the same verified corpus through
a separate Sysmon provider and returns typed process/evidence findings. Its fake
mode and corpus tests run without a model. Local Qwen3:8b integration smoke tests
also passed on small S01-S03 windows; see the
[validation scope and limitations](docs/ENDPOINT_IMPLEMENTATION.md#validation-scope).

## Components

| Component | Location / boundary |
| --- | --- |
| Dataset & Ground Truth Management | `datasets/`, dataset scripts; evaluation answers remain separate |
| Event Processing & Detection Engine | `event_processing/`: corpus, query API and conventional detection baseline |
| Authentication Investigation Agent | `authentication_agent/`: bounded authentication observations and local model interpretation |
| Endpoint Investigation Agent | `endpoint_agent/`: bounded Sysmon observations, process relationships and local model interpretation |
| Incident Reconstruction Orchestrator and Reconstruction Agent | `incident_reconstruction/`: dispatch, claim timeline, ATT&CK mapping, run modes and HTML report |
| Evidence Verification & Evaluation | Separate responsibility; connects through the verifier interface. Integration checks do not establish accuracy |

Packages, imports, commands and machine identifiers now use descriptive names.
Original evidence and scenario IDs are unchanged. See [architecture](docs/ARCHITECTURE.md)
and [migration details](docs/COMPONENT_NAMING.md).

## Run against real events

From the repository root, with Python 3.11 or later and an installed local model:

```powershell
python -m pip install -e '.[test]'
git lfs pull --include='datasets/S01/raw/*.evtx,datasets/S02/raw/*.evtx,datasets/S03/raw/*.evtx'
python -m event_processing normalise --datasets datasets --out out/corpus
python -m authentication_agent.investigate_corpus --corpus out/corpus --scenario S02 --start 2026-09-21T02:04:30Z --end 2026-09-21T02:06:00Z --model qwen3:8b
python -m pytest -q --basetemp .test-tmp/full
```

The entry point defaults to local `qwen3:8b`, context 8192, thinking disabled,
temperature 0 and seed 0. `--model` or `MAIR_OLLAMA_MODEL` selects another installed
local model. Nothing downloads weights. Add `--mode fake` to exercise the same
integration without inference. JSON goes to stdout; exit 3 signals truncation.

See the [integration report and reproduction commands](docs/AUTHENTICATION_CORPUS_INTEGRATION.md),
[agent manual](authentication_agent/README.md), [processing manual](event_processing/README.md), and
[orchestrator handoff](docs/ORCHESTRATOR_HANDOFF.md). Local model tool-selection
limitations remain explicit; PR #10 resolved the provider lookup and constructor
ownership failures, and the actual adapter now passes all 12 reusable checks.

## Run the full pipeline

After installing dependencies and normalising the corpus above, run any evaluation
configuration. `--llm fake` checks the plumbing without a model; `--llm ollama` uses the
installed local model (Ollama on the same machine, `ollama pull qwen3:8b` first).

```powershell
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode single-agent --out out/runs
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode multi-agent --out out/runs
python -m incident_reconstruction --corpus out/corpus --llm ollama --model qwen3:8b --mode full --out out/runs
start out/runs/index.html
```

| `--mode` | Configuration | Output in `out/runs/<mode>/` |
| --- | --- | --- |
| `single-agent` | One generalist model with the same evidence access | claims, timing |
| `multi-agent` | Specialist agents + Reconstruction Agent, no verifier | + agent dispatch record |
| `full` | `multi-agent` + independent verification (`--verifier package.module:factory`) | + verification decisions |

Each run ends by writing an HTML report per scenario and `out/runs/index.html`. Useful options:
`--scenario S02` (repeatable), `--plan-only` (print the investigation windows), and
`--reconstruct-only` (re-narrate and re-verify saved runs without re-running the agents).
Exit `1` means the files were written but something stayed incomplete, such as an investigation
window that exceeded the agent's context; it is listed in the report. Until the independent
verifier is connected, `full` marks every claim unverified.

To check a release from a clean checkout (fresh virtual environment, corpus, all modes, reports
and tests):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\release-smoke-test.ps1 -WorkingTree
```

See the [package manual](incident_reconstruction/README.md) and the
[verification and evaluation handoff](docs/RECONSTRUCTION_HANDOFF.md).

## Synthetic development

```powershell
python -m authentication_agent --mode fake --scenario SYN-A --start 2026-01-10T00:00:00Z --end 2026-01-10T00:01:00Z
```

See [contribution guidance](CONTRIBUTING.md). Default CI requires no model;
real EVTX tests skip explicitly when LFS content is absent. Generated corpora
belong under ignored `out/`. Original datasets and private evaluation material
are not modified by this integration.

## Endpoint investigation

After installing dependencies and normalising the corpus above:

```powershell
python -m endpoint_agent --corpus out/corpus --scenario S02 --start 2026-09-21T02:04:30Z --end 2026-09-21T02:06:30Z --mode fake
python -m pytest -q endpoint_agent/tests tests/test_endpoint_corpus.py --basetemp .test-tmp-endpoint
```

Use `--mode ollama --model qwen3:8b` for the shared installed local model.
Exit 3 signals truncated evidence; it is not a complete inventory. The endpoint
result shares the finding envelope but has endpoint-specific payload types.
See the [endpoint manual](endpoint_agent/README.md),
[provider/orchestrator handoff](docs/ENDPOINT_PROVIDER_HANDOFF.md), and
[role alignment and implementation review](docs/ENDPOINT_IMPLEMENTATION.md).
