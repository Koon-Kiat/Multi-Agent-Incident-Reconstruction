# Authentication Investigation Agent synthetic validation history

PR #7 validated the local agent before real-corpus integration. The recorded
Qwen3 run completed nine natural synthetic scenarios and passed 15 of 16
checks. One directed success-only query selected a different approved tool.
This was a model-selection limitation, not an accuracy measurement.

Original reports and exact recordings remain immutable in Git history at
`38ccd57`. The initial real-corpus implementation and its 6/11 local-model
matrix remain in history at `84f0cbe`. These historical recordings are not
rewritten to imitate results from renamed interfaces.

The current checkout uses descriptive package, command and schema names.
Current validation is regenerated under those interfaces and documented in
[the corpus integration report](AUTHENTICATION_CORPUS_INTEGRATION.md).
For reproduction, use the [agent manual](../authentication_agent/README.md).
No prior artifact hashes are claimed to describe the current source tree.

The earlier PR #10 integration rerun with prompt v4/configuration v3 passed
15/16, with the directed success-only query still selecting account history.
This is a new measurement, saved in the
[historical synthetic manifest](validation/authentication-pr10-2026-09-23/synthetic-ollama-final-v4/manifest.json).

The subsequent required-operation/optional-investigation work reran the original
synthetic checks before edits (**15/16**) and with prompt v8 (**15/16**). The final
success-only directed query still selects another approved tool. See the
[new directed synthetic recordings](validation/authentication-agent-2026-09-23/directed-synthetic-v8/manifest.json).
The separate ordinary/required matrix passes 23 checks, including 16 ordinary
runs across two repetitions and seven required-operation checks. Qwen selected
no optional tools in those ordinary runs; this is not evidence of autonomous
retrieval. The current report separates factual completion, trusted execution
and model-following limitations. All earlier recordings remain unchanged.
