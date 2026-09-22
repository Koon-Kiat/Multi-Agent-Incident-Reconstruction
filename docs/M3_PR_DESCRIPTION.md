> Historical handoff/report: numbered role labels and recorded results are preserved.
> See [component names and current architecture](ARCHITECTURE.md) and the
> [current authentication integration report](AUTHENTICATION_CORPUS_INTEGRATION.md) for current status.

This is the historical description for merged PR #6. For subsequent real Qwen3
testing and integration readiness, see [the current validation report](M3_VALIDATION_AND_INTEGRATION.md).

## Summary

Add an independent, locally hosted M3 Authentication Investigation Agent that
investigates synthetic normalised Windows authentication evidence before M2 and
M5 are ready. Observations and references are calculated and validated in Python.

## Changes

- Add provisional typed event/query/finding contracts, a temporary mock M2
  in-memory adapter, approved bounded tools, and the M5 Python entry point.
- Preserve precise timestamps and exact scenario-scoped evidence IDs; separate
  observations from constrained tentative model interpretations.
- Add fake and loopback Ollama adapters, synthetic fixtures, CLI, tests and
  integration documentation.
- Add lightweight PR-description and commit-subject checks plus Python test CI.

## Testing

- `python -m pip install -e '.[test]'` completed successfully.
- `python -m pytest -q --basetemp .test-tmp`: 131 passed, 1 skipped on Python 3.14.6.
- Fake CLI completed for SYN-A and generated `m3/examples/synthetic-result.json`.
- Live local Ollama `/api/tags` responded with no installed models. A missing-model
  request returned a structured failure with no findings. Real model inference
  was not run; the optional smoke test was skipped and no model was downloaded.
- Wheel build and isolated wheel import/CLI execution passed, including the
  packaged fixture. Workflow YAML parsed; `git diff --check` passed.
- Commit enumeration was checked read-only against existing PR #5: one commit
  matched `totalCount`. Unit tests cover 305 commits, final-page validation, and
  incomplete/error pagination. No existing PR was modified.
- Commit subject validation uses the complete GitHub message, not its shortened
  display headline, with a regression test for overlong subjects.
- GitHub-hosted checks must pass on the current PR commit before merge; local
  validation does not substitute for those workflow results.

## Notes

M2 must confirm/implement the provisional read-only schema and query adapter.
M5 must agree the final findings envelope and integrate orchestration. M6 owns
independent verification. This does not claim full pipeline integration or
evaluation. Maintainers must enable required status checks separately.
