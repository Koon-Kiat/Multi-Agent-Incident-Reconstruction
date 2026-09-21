# Multi-Agent Incident Reconstruction (MAIR)

ICT3214 Security Analytics project.

## Project Structure

- datasets/      Dataset metadata and scenario files
- runbooks/      Reproducible scenario documentation
- scripts/       Dataset acquisition and validation scripts
- ground_truth/  Ground-truth templates only; actual evaluation answer keys are kept separate
- m3/            Standalone Authentication Investigation Agent and synthetic fixtures

## M3 local development

M3 works independently with synthetic normalised events and a deterministic fake
LLM, with an optional local Ollama adapter. Its M2/M5 interfaces are provisional.
See [M3 setup and integration](m3/README.md) for commands, limits, schemas and tests.

```powershell
python -m pip install -e '.[test]'
python -m m3 --mode fake --scenario SYN-A --start 2026-01-10T00:00:00Z --end 2026-01-10T00:01:00Z
python -m pytest -q --basetemp .test-tmp
```

See [contribution guidance](CONTRIBUTING.md) for the lightweight PR-description
and commit-message checks. No model download or private evaluation material is
needed for the default tests.
