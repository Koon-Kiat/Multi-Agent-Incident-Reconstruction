import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("contribution_policy", Path(__file__).resolve().parents[1] / ".github/scripts/check_contributions.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

VALID = "## Summary\nAdd authentication investigation.\n## Changes\n- Add bounded tools.\n## Testing\nNot run (documentation-only)."


@pytest.mark.parametrize("body", [VALID, VALID.replace("## Summary", "  ## SUMMARY  ").replace("## Testing", "## testing ##"), VALID + "\n## Notes\nNone", VALID.replace("Not run (documentation-only).", "`python -m pytest -q` passed."), VALID.replace("- Add bounded tools.", "### Tools\nAdded read-only query tools.")])
def test_valid_pr_bodies(body):
    assert not policy.validate_pr_body(body)


@pytest.mark.parametrize("replacement", ["", "<!-- add details -->", "TODO", "- [ ] TBD", "...", "[Your text here]", "<!-- multiline\ncomment -->"])
def test_placeholder_or_empty_sections(replacement):
    errors = policy.validate_pr_body(VALID.replace("Add authentication investigation.", replacement))
    assert len(errors) == 1 and "Summary" in errors[0]


def test_missing_sections_and_template():
    assert len(policy.validate_pr_body("No headings")) == 3
    template = Path(__file__).resolve().parents[1] / ".github/pull_request_template.md"
    assert len(policy.validate_pr_body(template.read_text())) == 3


@pytest.mark.parametrize("subject", ["Add authentication query limits", "fix: handle missing evidence", "Fix: handle missing evidence", "Document Authentication Investigation Agent setup (#5)", "Merge branch 'main' into authentication_agent/authentication-investigation-agent", 'Revert "Add authentication query limits"', "Merge " + "x" * 120])
def test_valid_commit_subjects(subject):
    assert policy.validate_subject(subject) is None


@pytest.mark.parametrize("subject", ["", "fix", "update", "WIP", "changes", "test", "tiny", "x" * 101])
def test_invalid_commit_subjects(subject):
    assert policy.validate_subject(subject)


def test_full_commit_message_preserves_subject_length():
    assert "messageHeadline" not in policy.COMMITS_QUERY
    assert policy.validate_commit({"oid": "abc123", "message": "Add authentication query limits\n\nA separate body."}) is None
    error = policy.validate_commit({"oid": "abc123", "message": "A" * 101 + "\n\nA separate body."})
    assert "abc123" in error and "8-100" in error
    assert "too generic" in policy.validate_commit({"oid": "abc123", "message": "wip\n\nA descriptive body does not fix the subject."})


def test_pagination_checks_every_commit():
    commits = [{"oid": f"{i:040x}", "message": "Add authentication query limits"} for i in range(305)]
    commits[-1]["message"] = "wip"
    cursors = []
    def query(payload):
        cursor = payload["variables"]["cursor"]
        cursors.append(cursor)
        start = int(cursor or 0)
        end = min(start + 100, len(commits))
        return {"data": {"repository": {"pullRequest": {"commits": {"totalCount": len(commits),
            "nodes": [{"commit": c} for c in commits[start:end]],
            "pageInfo": {"hasNextPage": end < len(commits), "endCursor": str(end)}}}}}}
    fetched = policy.fetch_all_commits(query, "owner", "repo", 5)
    assert fetched == commits and cursors == [None, "100", "200", "300"]
    assert policy.validate_commit(fetched[-1])


@pytest.mark.parametrize("mode", ["error", "short", "duplicate", "bad_cursor"])
def test_incomplete_pagination_never_passes(mode):
    def query(_):
        if mode == "error": return {"errors": [{"message": "API failure"}]}
        return {"data": {"repository": {"pullRequest": {"commits": {"totalCount": 2,
            "nodes": [{"commit": {"oid": "one", "message": "Valid subject"}}] * (2 if mode == "duplicate" else 1),
            "pageInfo": {"hasNextPage": mode == "bad_cursor", "endCursor": None}}}}}}
    with pytest.raises(ValueError):
        policy.fetch_all_commits(query, "owner", "repo", 5)
