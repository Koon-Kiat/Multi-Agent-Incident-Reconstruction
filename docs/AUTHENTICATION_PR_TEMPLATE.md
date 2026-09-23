# Authentication Investigation Agent PR guidance

Use the repository PR template with Summary, Changes and Testing sections.
Explain the concrete behavior, actual validation and unresolved dependencies.
State the model/runtime, provider/corpus and exact commands used. Distinguish
completed execution from factual correctness and detection accuracy.

Retain genuine model-selection and provider-contract failures. Attribute the
resolved provider conversion and constructor ownership issues to PR #10.
Report which tests skipped because original EVTX files or a local model were
unavailable. Do not claim Incident Reconstruction Orchestrator integration
until its implementation is connected and exercised.

Use [the current report](AUTHENTICATION_CORPUS_INTEGRATION.md) for evidence,
and [contribution conventions](../CONTRIBUTING.md) for commit/PR checks.
Historical PR text remains in Git history; do not copy stale delivery claims.
