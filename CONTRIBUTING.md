# Contributing

Use a feature branch and preserve contributor authorship. The pull-request
template at `.github/pull_request_template.md` asks for three short sections:
Summary (what/why), Changes (meaningful changes) and Testing (what actually ran).
Notes is optional. Headings are case-insensitive and tolerate Markdown spacing.
Comments and untouched placeholders do not count as completed sections.
`Not run (reason)` is acceptable; the check does not assert that tests passed.

Commit subjects should be descriptive and about 8-100 characters. Sentence-style
subjects, Conventional Commits in either case, and issue references such as `(#5)`
are accepted. Generated Merge/Revert subjects are accepted, including longer
ones. Bare `fix`, `update`, `wip`, `changes` and `test` are rejected. No prefix,
capitalization, ticket, sign-off or commit body is required.

Examples:

```text
Add bounded authentication queries
fix: reject unknown evidence references
Document local authentication setup (#5)
```

`.github/workflows/contribution-checks.yml` runs on normal `pull_request` events:
opened, edited, synchronize, reopened and ready_for_review. Its independent
status checks are **PR description** and **Commit messages**. The workflow has
read-only token permissions, disables persisted checkout credentials, and uses
no secrets, external services or LLM. PR text is read from the event JSON file;
it is never interpolated into executable shell code. The checks execute in the
ordinary unprivileged PR workflow, never `pull_request_target`.

The commit validator queries only that pull request's `commits` GraphQL connection,
100 per page. It follows `pageInfo.endCursor` until `hasNextPage` is false, checks
unique SHAs, and requires the collected count to match `totalCount`. API errors,
changing counts and incomplete pagination fail instead of producing a partial
pass. This avoids the REST pull-request commits endpoint's 250-commit ceiling.
Subjects are taken from the first line of each full commit message; GitHub's
shortened display headline is not used for length validation.
The log states the total inspected count. The local pagination test supplies 305
commits and puts a rejected subject on the last page; it must be detected.

Run the small policy suite or the complete suite:

```powershell
python -m pip install -e '.[test]'
python -m pytest -q tests/test_contribution_checks.py
python -m pytest -q --basetemp .test-tmp
```

To fix **PR description**, edit the indicated empty/missing section in GitHub;
the edited event reruns the check. To fix **Commit messages**, inspect the SHA
named in the failed log and coordinate the subject correction with the contributor
under the team's normal branch policy. The validator never changes any commit,
author/committer identity or Git history. Do not change old repository commits
unrelated to the PR. A transient API failure can be rerun.

For authentication changes, state which corpus/provider, fake and local Ollama
checks actually ran. Keep provider compatibility diagnostics and model-selection
failures visible, and distinguish the tested call boundary from pending Incident
Reconstruction Orchestrator integration. Use the current validation report rather
than copying historical PR descriptions.

`.github/workflows/python-tests.yml` runs **Python and contribution tests** on
pull requests and pushes to main using Python 3.11. CI uses `lfs: false`; tests
requiring original EVTX files skip explicitly. Run those tests locally after
fetching Git LFS evidence. This application test check does not replace the
metadata checks. The intentionally failing, explicitly invoked compatibility
diagnostic is documented in `docs/AUTHENTICATION_CORPUS_INTEGRATION.md` and is
not included in default test discovery; it is not a conformance pass.

Maintainers must separately enable branch protection or a ruleset requiring
**PR description**, **Commit messages**, and (recommended) **Python and contribution
tests** before merge. Confirm the exact displayed check contexts after their
first GitHub run. No repository settings are changed by these files. Like other
repository-owned CI, validators/workflow changes themselves require review.

The former Python check display name was `M3 and contribution tests`. If a
branch ruleset requires that exact context, a maintainer must update it to
`Python and contribution tests`; the workflow job id `tests` is unchanged.
