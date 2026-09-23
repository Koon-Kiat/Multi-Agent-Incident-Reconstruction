"""Read back this delivery's recordings against the unchanged evidence snapshot.

Run from the repository root after regenerating out/corpus. Earlier experiments
keep their original errors; only *-v8 recordings claim current source hashes.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from authentication_agent.__main__ import synthetic_provider
from authentication_agent.models import InvestigationResult
from authentication_agent.testing.factual_checks import check_synthetic_result
from authentication_agent.validate_synthetic import write_json_artifact
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.query import EventStore


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    base = Path(__file__).resolve().parent
    store = EventStore.load(ROOT / "out/corpus")
    real = CorpusAuthenticationProvider(store)
    synthetic = synthetic_provider()
    report = {"runs": {}, "corpus_records": len(store.evidence_ids), "original_evtx": {}}
    for manifest_path in sorted(base.glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_bytes())
        name = manifest_path.parent.name
        completed = failed = 0
        for summary in manifest["cases"]:
            path = manifest_path.parent / summary["file"]
            assert sha(path) == summary["sha256"], str(path)
            case = json.loads(path.read_bytes())
            assert case["check_errors"] == summary["check_errors"]
            result = InvestigationResult.model_validate_json(json.dumps(case["result"]))
            if result.status == "failed":
                assert result.findings == ()
                failed += 1
                continue
            provider = synthetic if result.request.scenario_id.startswith("SYN-") else real
            # Recover the retrieved union independently of findings, from provider
            # receipts (including real exact reads). No answer labels are used.
            ids = set()
            for call in case["provider_calls"]:
                ids.update(call.get("evidence_ids", ()))
                if call.get("found"):
                    ids.add(call["evidence_id"])
            events = [provider.get_event(eid) for eid in sorted(ids)]
            assert all(events), str(path)
            assert not check_synthetic_result(result, events), str(path)
            completed += 1
        source_count = None
        if name.endswith("-v8"):
            for relative, digest in manifest["source_sha256"].items():
                source = ROOT / ("authentication_agent" if manifest.get("synthetic_only") else "") / relative
                assert sha(source) == digest, (name, relative)
            source_count = len(manifest["source_sha256"])
        if "corpus_manifest_sha256" in manifest:
            assert sha(ROOT / "out/corpus/corpus_manifest.json") == manifest["corpus_manifest_sha256"]
        report["runs"][name] = {
            "artifact_hashes_verified": len(manifest["cases"]), "current_source_hashes_verified": source_count,
            "completed_factual_readbacks_verified": completed, "failed_empty_envelopes_verified": failed,
            "checks_passed": sum(not case["check_errors"] for case in manifest["cases"]),
            "checks_total": len(manifest["cases"])}
    paths = subprocess.check_output(["git", "ls-files", "datasets/*/raw/*.evtx"], cwd=ROOT, text=True).splitlines()
    assert len(paths) == 6
    for relative in paths:
        pointer = subprocess.check_output(["git", "show", "HEAD:" + relative], cwd=ROOT, text=True)
        expected = next(line.split(":", 1)[1] for line in pointer.splitlines() if line.startswith("oid sha256:"))
        assert sha(ROOT / relative) == expected
        report["original_evtx"][relative] = expected
    baseline = "4f249ed03ab716752853ea8fd728d63b4a3f4e5b"
    for unchanged in ("event_processing", "datasets", "authentication_agent/testing/provider_contract.py"):
        assert not subprocess.check_output(["git", "diff", baseline, "--", unchanged], cwd=ROOT)
    report["processing_code_datasets_and_original_provider_contract_unchanged"] = True
    write_json_artifact(base / "final-readback.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
