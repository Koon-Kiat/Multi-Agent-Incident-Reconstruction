"""Stable content fingerprints for comparable pipeline artifacts."""

import hashlib
import json
from pathlib import Path

PACKAGES = ("event_processing", "authentication_agent", "endpoint_agent",
            "incident_reconstruction", "evidence_verification")


def json_digest(value) -> str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",", ":"),
                                    ensure_ascii=False).encode()).hexdigest()


def implementation_digest() -> str:
    root = Path(__file__).resolve().parents[1]
    sources = {}
    for package in PACKAGES:
        for path in sorted((root/package).rglob("*.py")):
            if "tests" not in path.parts and "__pycache__" not in path.parts:
                sources[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return json_digest(sources)
