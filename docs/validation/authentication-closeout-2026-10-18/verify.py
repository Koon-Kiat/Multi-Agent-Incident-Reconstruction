"""Verify retained audit bytes, current production sources and directed facts.

Run from the repository root. No model invocation or output mutation.
"""
import hashlib
import json
from pathlib import Path

from authentication_agent.__main__ import synthetic_provider
from authentication_agent.models import InvestigationResult
from authentication_agent.testing.factual_checks import check_synthetic_result
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.query import EventStore

root = Path(__file__).resolve().parent
hashes = json.loads((root / "artifact-hashes.json").read_text())
actual = {path.relative_to(root).as_posix() for path in root.rglob("*")
          if path.is_file() and path.name != "artifact-hashes.json"
          and "__pycache__" not in path.parts}
assert actual == set(hashes), "Artifact inventory changed"
for name, expected in hashes.items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
providers = {
    "corpus": CorpusAuthenticationProvider(EventStore.load("out/corpus")),
    "synthetic": synthetic_provider(),
}
count = 0
for group in ("autonomy", "corpus", "synthetic", "investigations"):
    manifest = json.loads((root / group / "manifest.json").read_text())
    for name, expected in manifest["source_sha256"].items():
        source = Path(name)
        if not source.exists():
            source = Path("authentication_agent") / name
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected, name
    for item in manifest["cases"]:
        path = root / group / item["file"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], path
        case = json.loads(path.read_text())
        result = InvestigationResult.model_validate_json(json.dumps(case["result"]))
        if group in providers:
            ids = {eid for operation in result.metadata.operations for eid in operation.evidence_ids}
            errors = check_synthetic_result(result, [providers[group].get_event(eid) for eid in ids])
            assert not errors, (path, errors)
        if any(op.truncated for op in result.metadata.operations):
            assert any("truncated" in value for value in result.uncertainty), path
        if result.status == "failed":
            assert not result.findings, path
        count += 1
print(f"Verified {len(hashes)} artifact hashes, production source hashes, {count} cases, "
      "27 directed factual readbacks, truncation warnings and fail-closed results.")
