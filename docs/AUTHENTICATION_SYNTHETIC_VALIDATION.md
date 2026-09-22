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
