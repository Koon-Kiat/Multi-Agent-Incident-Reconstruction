"""Keep responsibility names throughout the tracked project."""

from pathlib import Path
import re
import subprocess
import importlib.util


def test_tracked_names_and_text_have_no_retired_role_identifiers():
    root = Path(__file__).resolve().parents[1]
    retired = re.compile(r"(?i)(?<![a-z0-9])m[1-6](?![a-z0-9])|M[1-6](?=[A-Z])")
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    problems = []
    for relative in filter(None, paths):
        path = root / relative
        if not path.is_file():
            continue
        if retired.search(relative):
            problems.append(f"path: {relative}")
        # The explicit migration inventory quotes retired names, with a per-match
        # classification. It is an audit record, not active component terminology.
        if relative.startswith("docs/terminology-audit/"):
            continue
        # Raw evidence is immutable binary data; private material is never read.
        if "/raw/" in relative or relative.startswith("ground_truth/private/"):
            continue
        if path.suffix not in (".py", ".md", ".json", ".toml", ".yml", ".ps1", ".txt") and path.name not in (".gitignore", ".gitattributes"):
            continue
        if retired.search(path.read_text(encoding="utf-8-sig")):
            problems.append(f"text: {relative}")
    assert not problems, "Retired component identifiers remain: " + ", ".join(problems)


def test_tracked_active_terminology_has_no_unclassified_occurrences():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("terminology_audit", root / "scripts/audit-terminology.py")
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    problems = []
    for relative in filter(None, paths):
        if relative.startswith(audit.AUDIT_PREFIX) or "/raw/" in relative:
            continue
        path = root / relative
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(content.splitlines(), 1):
            for kind, pattern in audit.PATTERNS.items():
                if re.search(pattern, line) and audit.classify(relative, kind, line)[0] == "outdated_terminology":
                    problems.append(f"{relative}:{number}: {line}")
    assert not problems, "\n".join(problems)
