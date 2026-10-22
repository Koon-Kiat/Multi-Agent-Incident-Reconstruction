"""Inventory terminology in every tracked file without reading private inputs.

Run from the repository root. The generated audit directory is recorded but not
searched recursively: it quotes the exact terms being audited. Binary evidence
is hashed, never decoded or rewritten. Every other UTF-8 file is searched,
regardless of extension. An unmatched classification remains actionable.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

PATTERNS = {
    "role": r"(?i)(?<![a-z0-9])(?:m[1-6]|member\s+[1-6])(?![a-z0-9])|M[1-6](?=[A-Z])",
    "branding": r"(?i)ICT3214|Security Analytics|school(?:\s+\w+)?\s+(?:project|assignment)|coursework|\bassignment\b",
    "evaluation": r"(?i)\bA/B/C/D\b|\bB/C/D\b|\b[AB][–-]D\b|\bconfiguration[ _]+[ABCD]\b|B_single_agent|C_multi_agent_no_verifier|D_full_mair|configuration_A_rules_only|\bprep,B,C,D\b",
    "letter_labels": r"\b[ABCD]: (?!\\)|\([BCD]\)|\b[BCD](?:'s)? (?:the |verification|single-agent|multi-agent|complete MAIR)|\bfor B\b|\bFor D\b|detection \(A\)",
    "stable_interface": r"\bMODES\b|--mode (?:single-agent|multi-agent|full)\b|\b[BCD] = |\"[BCD]\"",
}
AUDIT_PREFIX = "docs/terminology-audit/"


def classify(path, kind, text):
    if path == "scripts/audit-terminology.py":
        return "audit_methodology", "Search expression or explicit classification rule, not a product label."
    if path.startswith("docs/validation/"):
        return "historical_evidence", "Original dated experimental record or hashed reference filename; preserve bytes."
    if path == "evidence_verification/evaluation/legacy.py":
        return "legacy_machine_identifier", "Read-only display adapter for original result schemas; never emitted by new scores."
    if path == "docs/COMPONENT_NAMING.md" and kind == "evaluation":
        return "legacy_machine_identifier", "Explicit compatibility documentation, not an active evaluation label."
    if path == "tests/test_evaluation_script.py" and kind in ("evaluation", "stable_interface"):
        return "legacy_machine_identifier", "Tests that existing stage aliases still dispatch to the correct pipeline mode."
    if path == "scripts/run-evaluation.ps1" and kind == "stable_interface" and "$aliases =" in text:
        return "legacy_machine_identifier", "Compatibility stage aliases normalized before dispatch."
    if kind == "stable_interface":
        return "stable_descriptive_interface", "Stable pipeline mode/schema/path contract or ordinary Python collection name."
    if path.startswith("event_processing/") and kind == "letter_labels" and re.search(r"SYN-[BC]:", text):
        return "false_positive", "Synthetic scenario identifier, unrelated to comparison configurations."
    return "outdated_terminology", "Requires contextual review and correction."


def scan():
    paths = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
    files, occurrences = [], []
    for name in filter(None, paths):
        path = Path(name)
        if name.startswith(("ground_truth/private/", "runbooks/private/")):
            raise ValueError("Private material must not be tracked or read by this audit")
        if name.startswith(AUDIT_PREFIX):
            files.append({"path": name, "kind": "audit record; self-reference excluded"})
            continue
        data = path.read_bytes()
        entry = {"path": name, "sha256": hashlib.sha256(data).hexdigest()}
        if path.suffix == ".evtx" or b"\0" in data:
            entry["kind"] = "binary evidence; hash only"
        else:
            try:
                content = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                entry["kind"] = "non-UTF8; manual inspection required"
            else:
                entry["kind"] = "text"
                for number, line in enumerate(content.splitlines(), 1):
                    for kind, pattern in PATTERNS.items():
                        for match in re.finditer(pattern, line):
                            category, reason = classify(name, kind, line)
                            occurrences.append({"path": name, "line": number, "column": match.start() + 1,
                                                "match": match.group(), "search": kind, "text": line,
                                                "classification": category, "reason": reason})
        files.append(entry)
    return {"revision": subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip(),
            "scope": "Tracked working tree; audit records listed but excluded from recursive matching",
            "patterns": PATTERNS, "files": files, "occurrences": occurrences,
            "counts": dict(Counter(item["classification"] for item in occurrences))}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = scan()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
    print(json.dumps({"files": len(report["files"]), **report["counts"]}))
    raise SystemExit(1 if report["counts"].get("outdated_terminology")
                     or any(item["kind"].startswith("non-UTF8") for item in report["files"]) else 0)
