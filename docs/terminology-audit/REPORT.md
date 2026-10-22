# Repository terminology audit - 2026-10-22

PR: [#20](https://github.com/Koon-Kiat/Multi-Agent-Incident-Reconstruction/pull/20).
Branch: `docs/descriptive-component-evaluation-names-20261022`.
Starting PR head: `852168c29584e7d839cc2202d5f7eab13d31f95e`.
Latest main inspected: `1da89ee64d7e799b37c9ede5e4bd46eea72d077f`.
The checkout was clean before switching from main to the PR branch.

## Outcome

Active documentation, CLI summaries, readiness labels, Markdown/HTML reports and
new evaluation outputs use descriptive names. No outdated human-facing labels
remain in the audited active tree. Compatibility identifiers, original records,
audit quotations and unrelated technical values are intentionally distinguished
below. This is a terminology and interface migration, not a new model evaluation.
The PR is updated without merging.

## Original-to-replacement mapping

| Old component designation | Canonical responsibility |
| --- | --- |
| M1 / Member 1 | Dataset & Ground Truth Management |
| M2 / Member 2 | Event Processing & Detection Engine |
| M3 / Member 3 | Authentication Investigation Agent |
| M4 / Member 4 | Endpoint Investigation Agent |
| M5 / Member 5 | Incident Reconstruction Orchestrator and Reconstruction Agent |
| M6 / Member 6 | Evidence Verification & Evaluation |

The project name is **Multi-Agent Incident Reconstruction (MAIR)**: a local-first,
multi-agent security incident reconstruction and evidence verification framework.
Course branding is absent from active product text. No role-token occurrences
were found in the starting active tree; that part of the earlier migration was
already effective. The mappings here deliberately quote the retired names.

| Old evaluation label / serialized ID | Canonical name | New result ID |
| --- | --- | --- |
| A / `configuration_A_rules_only` | Rules-only Detection Baseline | `rules_only_detection_baseline` |
| B / `B_single_agent` | Single-Agent Generalist Baseline | `single_agent_generalist_baseline` |
| C / `C_multi_agent_no_verifier` | Specialist-Agent Incident Reconstruction | `specialist_agent_incident_reconstruction` |
| D / `D_full_mair` | Specialist-Agent Incident Reconstruction with Independent Evidence Verification | `specialist_agent_incident_reconstruction_with_independent_evidence_verification` |

## PR history inspection

The original PR contained three commits. `278019f` edited documentation and eight
Python files; `5699145` restored those eight Python files to preserve fingerprints;
`852168c` made further documentation edits. The eight omitted Python files are:

- `evidence_verification/evaluation/__main__.py`
- `evidence_verification/evaluation/detection.py`
- `evidence_verification/evaluation/report.py`
- `incident_reconstruction/__main__.py`
- `incident_reconstruction/claims.py`
- `incident_reconstruction/pipeline.py`
- `incident_reconstruction/single_agent.py`
- `incident_reconstruction/verification.py`

All eight have now been inspected and updated, along with readiness, runner,
validation, HTML reporting, dependent tests and the evaluation script.
The original twelve changed files relative to main were:

- `README.md`
- `docs/AUTHENTICATION_CLOSEOUT_AUDIT.md`
- `docs/COMPONENT_NAMING.md`
- `docs/CORRECTNESS_REMEDIATION.md`
- `docs/EVALUATION_PROTOCOL.md`
- `docs/EVIDENCE_ACCEPTANCE.md`
- `docs/FINAL_EVALUATION_HANDOFF.md`
- `docs/GENERALIST_CONTEXT_CORRECTION.md`
- `docs/SEMANTIC_CLAIM_REVIEW.md`
- `evidence_verification/README.md`
- `incident_reconstruction/README.md`
- `scripts/run-evaluation.ps1`

## Complete search scope and reproducibility

[before.json](before.json) inventories the original 1,103 tracked files with
SHA-256 hashes and every match's path, line, column, exact text and classification.
It records 87 matches: 55 outdated active labels, 18 machine identifiers needing
coordinated migration, eight original historical-record matches and six unrelated
synthetic-scenario matches. Multiple matching patterns on the same line are
counted separately; counts are occurrences, not changed files.

[after.json](after.json) repeats the search over the final tracked tree and adds
stable CLI/interface and compatibility-alias searches. It contains the complete
remaining occurrence list with justifications, all scanned file paths and hashes,
and the exact regexes. The before/after totals are not directly comparable because
the final audit additionally inventories stable interfaces and the audit machinery.

Procedure:

1. `git ls-files -z` enumerates the entire current tracked tree, with no extension
   whitelist. Python, PowerShell, Markdown, YAML, TOML, JSON, fixtures, workflow
   definitions, schemas, templates and recorded validation artifacts are included.
2. `git grep -n -I -i -E` independently searches bounded role tokens, branding,
   evaluation letters and serialized IDs. `rg -n -i -e` repeats those searches in
   batches of explicit tracked paths, excluding binary EVTX and this audit folder.
3. Supplemental contextual searches inspect standalone evaluation letters,
   parenthesized labels, school/course/academic terminology, `MODES`, command
   examples, report strings and stage selectors. Unrelated lettered authentication
   audit categories, Mermaid node IDs, account examples, Windows drive letters,
   synthetic scenario IDs and metric IDs remain unchanged.
4. `python scripts/audit-terminology.py --out out/terminology-audit/check.json`
   regenerates the final classified inventory and exits nonzero for an unclassified
   active occurrence. The naming regression test uses the same reviewed exceptions.

Exclusions are explicit: immutable binary EVTX is hashed instead of text-decoded;
private ignored inputs are never read; `.git` history and untracked generated
outputs are outside the current tracked-tree request. Files under this audit
folder are listed but not recursively searched because they quote their own
search terms, mappings and historical snapshots. No other tracked text is skipped.
There are no undecodable tracked text files needing manual follow-up.

## Remaining-reference assessment

**Outdated human-facing terminology: zero.** The final inventory contains no
`outdated_terminology` rows. This conclusion combines the complete searches and
contextual review; passing tests alone is not used as proof of terminology coverage.

**Legacy machine identifiers:** the four old result IDs exist only in
`evidence_verification/evaluation/legacy.py` and explicit migration documentation.
The adapter accepts v1/v2 saved results for display, copies their dictionaries,
and never writes or rescores them, or changes provenance. New producers emit v3 IDs
through every `configuration` field, nested metric, totals key and CSV row.
`report.render()` consumes both schemas. Existing external JSON/CSV consumers
must migrate to v3; the schema version explicitly signals that interface change.

The PowerShell aliases `B`, `C` and `D` normalize to `generalist`, `specialist` and
`verified-specialist`. They remain for existing automation, with regression tests
for dispatch and overwrite protection. Defaults and new logs use descriptive
names. `single-agent`, `multi-agent`, `full` and `MODES` remain stable pipeline
interfaces used in command parsing, schemas, artifact directories, review bindings,
validation and scoring. They do not appear as the sole displayed result label.
`full` means the independently verified specialist approach; it is documented.
Readiness JSON gate names change alongside text labels, with dependent tests
updated. Status values, gates and exit codes remain unchanged.

**Historical evidence:** the original filename `Coursework 1 AY2026.pdf` in
`docs/validation/authentication-closeout-2026-10-18/audit-metadata.json:5` identifies
a hashed source reference. Renaming it would misdescribe the original provenance.
Seven other historical matches are lettered authentication audit categories in
`completion-audit.md` for the 2026-09-23 and 2026-09-24 snapshots, not labels for
the four-approach comparison. They remain original records, with each occurrence
listed in `after.json`.

**False positives:** six matches are the suffixes of `SYN-B:` / `SYN-C:` in
Event Processing documentation/tests; these are legitimate scenario identities.
Windows `System32`, PowerShell `psm1`, drive prefixes, record IDs, and timestamps
are not component roles and are not subject to substring replacement. For example,
`docs/PROCESSING_VERIFICATION_HANDOFF.md` retains the original Windows process
paths and record IDs, and `docs/VERIFIER_FALSE_ALARM_REVIEW.md` retains the quoted
account placeholders. Audit regexes necessarily contain the search terms and are
classified separately as `audit_methodology`.

## Fingerprints, behavior and evaluation compatibility

- Previous implementation: `7f68e2289bb848eaf857885d9413f0d1d7107872369204106a5f5918d34bfa71`
- New implementation: `5d0dcc60fbd8615365914fd1f1bef85ea1717a79cde46c42690e7318d1b9c377`
- Previous public protocol: `8dae3d5b652d6be9e1a402aadb03f6a7101912a018a47b3e714bfe555451ce68`
- New public protocol: `d9aa549d26e0e6ce7f74b331e952da002e5d6ef4ae3ebb8796b84fa37e6bcd19`

[fingerprints.json](fingerprints.json) lists all 14 fingerprint-affecting source
files with before/after content hashes. The existing fingerprint algorithm is
unchanged: it hashes normalized Python source across the five implementation
packages, excluding tests. Comment/docstring and label changes therefore count.

The changes include cosmetic prose plus deliberate interface behavior changes:
new result-schema IDs, legacy display adaptation, descriptive readiness/CLI output,
and descriptive PowerShell stages/log names. Detector logic, query semantics,
model prompts, evidence identity, scoring arithmetic, verifier decisions and
review/approval gates are unchanged. No claim of bit-identical runtime behavior
is made for the renamed presentation and serialization interfaces.

Original evaluation artifacts retain their original source/protocol hashes.
`validate_run` still rejects a stale implementation fingerprint; the display
adapter cannot bypass that check. A current-code final comparison requires fresh
runs of all three model approaches for each scenario (nine runs for the current
three-scenario corpus), the matching rules-only detection baseline, independent
reviews bound to the new claims and an approved scoring contract. Historical
scores remain attributable only to their recorded revision. No live Ollama run
was executed for this cleanup. CI and synthetic fixtures do not establish private
lab ground-truth accuracy or replace human review.

[preservation.json](preservation.json) confirms that all 873 tracked dataset,
fixture and original validation-artifact files are byte-for-byte unchanged.
Existing scenario/evidence-ID token multisets in every edited pre-existing file
also match the starting PR head. Private answer keys, runbooks and historical
local run outputs were neither read nor modified.

## Verification

Final verification results are recorded in [verification.json](verification.json).
The first full suite passed with 1,299 tests and seven skips (five opt-in live-model tests and two unavailable symlink tests). A subsequent
focused contract/CLI/PowerShell run passed all 45 tests. The final full suite passed with **1,301 tests and seven skips**, including the
new CLI-label and repository terminology regression tests.

The wheel builds and installs into an isolated target; imports from that installed
copy cover all five packages, the canonical naming module and the legacy adapter.
Its implementation digest matches the source tree. The PowerShell script parses,
accepts both descriptive and legacy stage selections, rejects unknown stages and
preserves overwrite refusal without invoking Ollama.

The [synthetic report](synthetic-report.md) was generated from synthetic events,
claims, reviews and contracts; no model ran and no private key was used. Its
headings and table labels include all four canonical names. HTML report tests
check every mode's index and page labels. CLI help and result-summary tests check
descriptive names. A readiness invocation against missing synthetic paths exits
1 and displays descriptive gates; this verifies failure behavior, not real-run
readiness. The existing stale-run, private-review and scoring-contract tests remain
in force.

## Complete changed-file list relative to main

See [changed-files.json](changed-files.json). It includes the earlier PR changes,
all restored Python edits, coordinated consumers/tests, documentation and these
audit artifacts. The original changes were extended rather than replaced.
