"""Read-only PR metadata checks. No dependencies, shell execution or log contents."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from collections.abc import Callable

REQUIRED_SECTIONS = ("summary", "changes", "testing")
PLACEHOLDERS = {"todo", "tbd", "...", "fill in", "fill this in", "your text here", "n/a", "none", "summary", "changes", "testing"}
GENERIC_SUBJECTS = {"fix", "update", "wip", "changes", "test"}


def validate_pr_body(body: str) -> list[str]:
    body = re.sub(r"<!--.*?-->", "", body or "", flags=re.DOTALL)
    sections: dict[str, list[str]] = {}
    current = None
    in_fence = False
    for line in body.splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
        heading = None if in_fence else re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if heading:
            title = heading.group(1).strip().casefold()
            title = re.sub(r"[*_`:]", "", title).strip()
            if title in REQUIRED_SECTIONS or title == "notes":
                current = title
                sections.setdefault(current, [])
            elif len(line.lstrip()) - len(line.lstrip().lstrip("#")) <= 2:
                current = None
        elif current:
            sections[current].append(line)
    errors = []
    for name in REQUIRED_SECTIONS:
        meaningful = []
        for line in sections.get(name, []):
            cleaned = re.sub(r"^[\s>*_`#\-+\d.\[\]xX]+", "", line).strip().strip("*_` .:[]<>-").casefold()
            if cleaned and cleaned not in PLACEHOLDERS and not cleaned.startswith(("replace this", "describe here", "add your")):
                meaningful.append(cleaned)
        if not meaningful:
            errors.append(f"Missing or empty {name.title()} section: add a short explanation under '## {name.title()}'. Comments/placeholders alone do not count.")
    return errors


def validate_subject(subject: str) -> str | None:
    subject = subject.strip()
    if not subject:
        return "Commit subject is empty."
    if subject.casefold().strip(".! ") in GENERIC_SUBJECTS:
        return "Commit subject is too generic."
    # Git-generated merge/revert titles can legitimately exceed the normal range.
    if re.match(r'^(Merge\s+\S|Revert\s+".+")', subject):
        return None
    if not 8 <= len(subject) <= 100:
        return "Commit subject should be 8-100 characters."
    return None


def validate_commit(commit: dict) -> str | None:
    # GitHub's messageHeadline is a shortened display value, not the original
    # subject. Validate the first line of the full message without truncation.
    reason = validate_subject(commit["message"].split("\n", 1)[0])
    if reason:
        return f"Commit {commit['oid']}: {reason} Example: 'Describe authentication query limits'."
    return None


COMMITS_QUERY = """query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      commits(first: 100, after: $cursor) {
        totalCount
        nodes { commit { oid message } }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}"""


def fetch_all_commits(query: Callable[[dict], dict], owner: str, name: str, number: int) -> list[dict]:
    """Cursor pagination, with total-count and duplicate checks to fail closed."""
    commits: list[dict] = []
    cursor = None
    cursors: set[str] = set()
    total = None
    while True:
        reply = query({"query": COMMITS_QUERY, "variables": {"owner": owner, "name": name, "number": number, "cursor": cursor}})
        if reply.get("errors"):
            raise ValueError("GitHub returned an API error; could not validate all PR commits.")
        page = reply["data"]["repository"]["pullRequest"]["commits"]
        if total is None:
            total = page["totalCount"]
        if page["totalCount"] != total:
            raise ValueError("PR changed during pagination; rerun the check.")
        commits.extend(node["commit"] for node in page["nodes"])
        if not page["pageInfo"]["hasNextPage"]:
            break
        cursor = page["pageInfo"]["endCursor"]
        if not cursor or cursor in cursors or not page["nodes"] or len(commits) >= total:
            raise ValueError("Incomplete PR commit pagination; rerun the check.")
        cursors.add(cursor)
    if not commits or len(commits) != total or len({c["oid"] for c in commits}) != total:
        raise ValueError("PR commit count mismatch; could not validate all commits.")
    return commits


def github_query(payload: dict) -> dict:
    request = urllib.request.Request(os.environ.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"),
        data=json.dumps(payload).encode(), headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
        "Content-Type": "application/json", "User-Agent": "mair-contribution-check"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main() -> int:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    mode = sys.argv[1]
    if mode == "body":
        errors = validate_pr_body(event["pull_request"].get("body") or "")
    elif mode == "commits":
        repository = event["repository"]
        try:
            commits = fetch_all_commits(github_query, repository["owner"]["login"], repository["name"], event["number"])
            errors = [error for commit in commits if (error := validate_commit(commit))]
            print(f"Inspected all {len(commits)} PR commits (paginated GraphQL totalCount matched).")
        except Exception:
            errors = ["Unable to retrieve every PR commit. Check API availability/read permissions and rerun; no partial pass was recorded."]
    else:
        raise ValueError("expected body or commits mode")
    for error in errors:
        print(error)
    if not errors:
        print("Contribution metadata check passed. This does not indicate that application tests passed.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
