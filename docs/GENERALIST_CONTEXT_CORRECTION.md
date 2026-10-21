# Generalist context correction experiment

**Evaluation status: diagnostic only; not officially scored.** Completed
independent human annotations and signed owner approvals have not been supplied
for validation. Code publication does not establish evaluation completion or
semantic correctness. Private run artifacts, review forms, ground truth and
runbooks remain outside Git.

Authorized on 21 October 2026 after the preserved `out/final-01` experiment.
This is a separately labelled implementation correction, not a replacement of
the original results or a change to scoring definitions.

The original generalist reserved 4,096 output tokens on every turn, including
tool-selection turns whose claim list must be empty. Initial input plus that
reserve exceeded 8,192 tokens for S02 and S03. S01 failed after conversation
growth. These were context-admission failures, not observed memory exhaustion.

The correction uses compact JSON, presents each retrieved event's fields once
and references its exact evidence ID on repeated retrieval. Tool-selection
responses reserve at most 1,024 tokens. Final responses retain up to 4,096
tokens, with a minimum reservation of 2,048 (or the caller's smaller explicit
output limit). The installed adapter's token counter and shared byte/schema
guard determine admission. No additional event-field clipping, summarization,
ground-truth selection, automatic query selection or specialist reasoning is
introduced.

Every proposed tool result is checked with space reserved for the final turn.
If the complete result does not fit, only the consecutive prefix that fits is
presented, the omitted count is explicit, omitted records cannot be cited, and
the investigation ends with a recorded context-capacity gap and a final response
from the evidence actually shown. Previously shown evidence is never evicted.
Oversized initial input or an output-limit failure remains an explicit failure.
This policy does not promise that every incident fits a fixed context window.
The CLI reports a context-capacity stop as incomplete even when a partial
timeline was returned. Reconstruction metadata records each admitted call's
phase, input bound, output allowance and available transport response metrics.
The generalist model-call count now counts actual adapter invocations; host
admission checks that reject before invocation are not model calls.

The experiment keeps the authorized Ollama 0.40.6 / qwen3:8b digest, context
8,192, temperature zero, seed zero, thinking disabled, 16-tool generalist budget,
provider limits, scenario boundaries and existing timeouts. A fresh corpus and
all nine B/C/D investigations must use the frozen corrected implementation.
Record the base commit, source patch and implementation fingerprint.
Regenerate hash-bound review forms afterwards.
Human annotations and owner approvals remain prerequisites for official scoring.
