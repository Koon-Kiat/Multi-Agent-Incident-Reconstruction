"""Read back M3 development recordings; no private answers or model verdicts.

Run from the repository root. Old failed experiments remain failed. Source byte
hashes describe the recorded checkout; final source comparisons normalize EOLs
using the accompanying source-readback.json, for Windows/Linux portability.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from authentication_agent.__main__ import synthetic_provider
from authentication_agent.agent import _event_context
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
    providers = {"corpus": CorpusAuthenticationProvider(store), "synthetic": synthetic_provider()}
    report = {"runs": {}, "original_evtx": {}}
    for manifest_path in sorted(base.glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_bytes())
        completed = failed = 0
        for summary in manifest["cases"]:
            path = manifest_path.parent / summary["file"]
            assert sha(path) == summary["sha256"], str(path)
            case = json.loads(path.read_bytes())
            assert case["check_errors"] == summary["check_errors"], str(path)
            result = InvestigationResult.model_validate_json(json.dumps(case["result"]))
            provider = providers["synthetic" if result.request.scenario_id.startswith("SYN-") else "corpus"]
            ids = set()
            for call in case["provider_calls"]:
                ids.update(call.get("evidence_ids", ()))
                if call.get("found"):
                    ids.add(call["evidence_id"])
            events = [provider.get_event(eid) for eid in sorted(ids)]
            assert all(events), str(path)
            actual = {event.evidence_id: event for event in events}
            for event in case.get("retrieved_events", case.get("initial_events", [])):
                assert actual[event["evidence_id"]].model_dump(mode="json") == event, str(path)
            for call in case["model_calls"]:
                if "messages" not in call:
                    continue
                context = json.loads(call["messages"][-1]["content"])
                for observation in context["observations"]:
                    for event in observation.get("events", []):
                        assert _event_context(actual[event["evidence_id"]]) == event, str(path)
            if result.status == "failed":
                assert result.findings == (), str(path)
                failed += 1
            else:
                assert not check_synthetic_result(result, events), str(path)
                completed += 1
            if "optional_actions" in case:
                assert sum(op.provider_invoked for op in result.metadata.operations) + result.metadata.evidence_readbacks == len(case["provider_calls"])
                assert len(case["optional_actions"]) == sum(op.origin == "model" for op in result.metadata.operations)
            evaluation = case.get("evaluation_only")
            if evaluation:
                for event in evaluation["availability_witness"]["events"]:
                    assert provider.get_event(event["evidence_id"]).model_dump(mode="json") == event
                assert evaluation["assessment"]["behavior_errors"] == summary["behavior_errors"]
        if "corpus_manifest_sha256" in manifest:
            assert sha(ROOT / "out/corpus/corpus_manifest.json") == manifest["corpus_manifest_sha256"]
        if "source_unchanged_during_run" in manifest:
            assert manifest["source_unchanged_during_run"], str(manifest_path)
        report["runs"][manifest_path.parent.name] = {
            "artifact_hashes_verified": len(manifest["cases"]), "completed_factual_readbacks": completed,
            "failed_empty_envelopes": failed, "recorded_checks_passed": sum(not c["check_errors"] for c in manifest["cases"]),
            "behavior_checks_total": sum("behavior_errors" in c for c in manifest["cases"]),
            "behavior_checks_passed": (sum(not c["behavior_errors"] for c in manifest["cases"])
                if all("behavior_errors" in c for c in manifest["cases"]) else None)}
    paths = subprocess.check_output(["git", "ls-files", "datasets/*/raw/*.evtx"], cwd=ROOT, text=True).splitlines()
    assert len(paths) == 6
    for relative in paths:
        pointer = subprocess.check_output(["git", "show", "HEAD:" + relative], cwd=ROOT, text=True)
        expected = next(line.split(":", 1)[1] for line in pointer.splitlines() if line.startswith("oid sha256:"))
        assert sha(ROOT / relative) == expected, relative
        report["original_evtx"][relative] = expected
    baseline = "4ad96da752c8752d89994b06d6db31662aa64574"
    for unchanged in ("event_processing", "datasets", "authentication_agent/testing/provider_contract.py"):
        assert not subprocess.check_output(["git", "diff", baseline, "--", unchanged], cwd=ROOT)
    source_record = base / "source-readback.json"
    if source_record.exists():
        for relative, digest in json.loads(source_record.read_bytes())["normalized_source_sha256"].items():
            data = (ROOT / relative).read_bytes().replace(b"\r\n", b"\n")
            assert hashlib.sha256(data).hexdigest() == digest, relative
        report["final_source_readback"] = True
    report["provider_processing_and_datasets_unchanged"] = True
    write_json_artifact(base / "final-readback.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
