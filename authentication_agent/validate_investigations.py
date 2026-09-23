"""Separate ordinary model choices from trusted required-operation validation.

No prescribed tools or annotations are injected into ordinary model requests.
The historical directed evaluations remain in validate_corpus/validate_synthetic.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

from authentication_agent import InvestigationRequest, RequiredOperations, ToolCall, investigate
from authentication_agent.__main__ import synthetic_provider
from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.investigate_corpus import local_model_runtime
from authentication_agent.llm.fake import FakeLLM
from authentication_agent.llm.ollama_client import OllamaClient
from authentication_agent.models import QueryRequest
from authentication_agent.testing.factual_checks import check_synthetic_result
from authentication_agent.validate_corpus import WINDOWS, public_request
from authentication_agent.validate_synthetic import RecordedLLM, RecordedProvider, write_json_artifact
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.corpus import CORPUS_MANIFEST_FILENAME
from event_processing.query import EventStore


def source_hashes():
    root = Path(__file__).resolve().parents[1]
    sources = [*sorted((root / "authentication_agent").rglob("*.py")),
               *sorted((root / "event_processing").rglob("*.py"))]
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources if "tests" not in path.parts}


def run_case(name, category, request, provider, llm, limits, required=None, expected_error=None):
    recorded_provider = RecordedProvider(limits, provider)
    recorded_llm = RecordedLLM(llm, validation_scope=category)
    started = time.monotonic()
    result = investigate(request, recorded_provider, recorded_llm, limits, required_operations=required)
    errors = check_synthetic_result(result, recorded_provider.retrieved.values(), expected_error)
    receipts = result.metadata.operations
    required_receipts = [op for op in receipts if op.origin == "required"]
    calls = required.calls() if required else ()
    if tuple(op.call for op in required_receipts) != calls:
        errors.append("required operations were not recorded with their exact original arguments")
    if expected_error is None and any(op.status not in ("completed", "no_evidence") for op in required_receipts):
        errors.append("a required operation was not completed")
    if any(op.status == "no_evidence" and op.call.name == "get_authentication_event" for op in receipts):
        if not any("not found" in text for text in result.uncertainty):
            errors.append("missing exact lookup was not represented in uncertainty")
    if any(op.truncated for op in receipts) and not any("truncated" in text for text in result.uncertainty):
        errors.append("incomplete query coverage was not represented in uncertainty")
    readbacks = result.metadata.evidence_readbacks
    for index, call in enumerate(recorded_provider.calls):
        call["phase"] = "final_readback" if index >= len(recorded_provider.calls) - readbacks else "retrieval"
    if sum(op.provider_invoked for op in receipts) + readbacks != len(recorded_provider.calls):
        errors.append("provider calls do not reconcile with operation receipts and final readbacks")
    optional = []
    for op in receipts:
        if op.origin != "model":
            continue
        contribution = ("rejected_or_failed" if op.status in ("failed", "rejected") else
                        "duplicate_reused" if op.reused_from is not None else
                        "added_evidence" if op.new_evidence_ids else "no_new_evidence")
        optional.append({"receipt_index": op.index, "call": op.call.model_dump(mode="json"),
                         "contribution": contribution, "new_evidence_ids": list(op.new_evidence_ids),
                         "note": "New evidence is a retrieval contribution, not proof of investigative correctness or malicious activity."})
    initial_ids = receipts[0].evidence_ids if receipts else ()
    initial_events = [recorded_provider.retrieved[eid].model_dump(mode="json") for eid in initial_ids]
    return {"case": name, "category": category, "request": request.model_dump(mode="json"),
            "required_operations": required.model_dump(mode="json", exclude_unset=True) if required else None,
            "prescribed_model_tools": False, "expected_error": expected_error,
            "initial_events": initial_events, "optional_actions": optional,
            "elapsed_seconds": round(time.monotonic() - started, 3), "check_errors": errors,
            "result": result.model_dump(mode="json"), "model_calls": recorded_llm.calls,
            "provider_calls": recorded_provider.calls}


def cases(store):
    limits = Limits()
    ordinary = [(name, public_request(name), limits, "corpus") for name in WINDOWS]
    ordinary.extend([
        ("empty", InvestigationRequest(scenario_id="S02", start_utc="2026-09-21T00:00:00Z", end_utc="2026-09-21T00:01:00Z"), limits, "corpus"),
        # Retain the existing small-budget coverage exercise. No records are hidden
        # by the harness; both host and model receive the same explicit query cap.
        ("bounded", public_request("S02"), Limits(max_events_per_query=2), "corpus"),
    ])
    for name, scenario, cap in [("synthetic_sufficient", "SYN-A", 100),
                                ("synthetic_missing_context", "SYN-F", 100), ("synthetic_bounded", "SYN-A", 2)]:
        ordinary.append((name, InvestigationRequest(scenario_id=scenario,
            start_utc="2026-01-10T00:00:00Z", end_utc="2026-01-10T00:01:00Z"), Limits(max_events_per_query=cap), "synthetic"))
    request = public_request("S02")
    provider = CorpusAuthenticationProvider(store, limits)
    events = provider.query(QueryRequest(**request.model_dump())).events
    anchor = next(event for event in events if event.user is not None)
    absent = "S02-SEC-999999999"
    if store.lookup(absent).status != "not_found":
        raise ValueError("missing-ID exercise requires an absent ID")
    existing = ToolCall(name="get_authentication_event", arguments={"evidence_id": anchor.evidence_id})
    missing = ToolCall(name="get_authentication_event", arguments={"evidence_id": absent})
    filtered = ToolCall(name="query_authentication_events", arguments={**request.model_dump(), "event_ids": [4624], "limit": 100})
    history = ToolCall(name="get_account_authentication_history", arguments={**request.model_dump(), "account": anchor.user, "limit": 100})
    required = [
        ("exact_existing", limits, (existing,), None), ("exact_missing", limits, (missing,), None),
        ("filtered", limits, (filtered,), None), ("history", limits, (history,), None),
        ("combined", limits, (missing, filtered, history), None),
        ("duplicates", limits, (missing, missing, filtered, filtered), None),
        ("budget", Limits(max_tool_calls=1), (existing, missing), "tool_budget_exhausted"),
    ]
    return ordinary, [(name, request, cap, RequiredOperations.from_calls(*ops), error)
                       for name, cap, ops, error in required]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--mode", choices=("fake", "ollama"), default="fake")
    parser.add_argument("--model", default="qwen3:8b")
    parser.add_argument("--repetitions", type=int, choices=(1, 2, 3), default=2)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        parser.error("output directory must be new or empty; preserve earlier recordings")
    store = EventStore.load(args.corpus)
    ordinary, required = cases(store)
    llm, runtime = FakeLLM(), {"runtime": "fake"}
    if args.mode == "ollama":
        config = OllamaConfig(model=args.model, num_ctx=8192, think=False, temperature=0.0, seed=0)
        runtime = local_model_runtime(config)
        llm = OllamaClient(config)
    before = source_hashes()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = []

    def save(case):
        name = case["category"] + "-" + case["case"] + ".json"
        digest = write_json_artifact(args.output_dir / name, case)
        item = {"case": case["case"], "category": case["category"], "file": name, "sha256": digest,
                "status": case["result"]["status"], "error_code": case["result"]["error_code"],
                "check_errors": case["check_errors"], "optional_actions": case["optional_actions"],
                "elapsed_seconds": case["elapsed_seconds"]}
        summary.append(item)
        print(json.dumps(item), flush=True)

    for repeat in range(1, args.repetitions + 1):
        for name, request, limits, kind in ordinary:
            provider = CorpusAuthenticationProvider(store, limits) if kind == "corpus" else synthetic_provider(limits)
            save(run_case(f"{name}-{repeat}", "ordinary", request, provider, llm, limits))
    for name, request, limits, plan, error in required:
        save(run_case(name, "required", request, CorpusAuthenticationProvider(store, limits), llm, limits, plan, error))
    stable = before == source_hashes()
    manifest_bytes = (args.corpus / CORPUS_MANIFEST_FILENAME).read_bytes()
    write_json_artifact(args.output_dir / "manifest.json", {
        "completed_at_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
        "runtime": runtime, "source_sha256": before, "source_unchanged_during_run": stable,
        "corpus_manifest": json.loads(manifest_bytes), "corpus_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "repetitions": args.repetitions, "cases": summary,
        "scope": "Authentication retrieval and factual checks; not attack accuracy, independent verification or orchestrator integration"})
    return 1 if not stable or any(case["check_errors"] for case in summary) else 0


if __name__ == "__main__":
    raise SystemExit(main())
