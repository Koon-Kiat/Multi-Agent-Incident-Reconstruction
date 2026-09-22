"""Reproducible local corpus integration checks, never detection-accuracy scoring."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import time

from m2.adapters.m3_provider import M2AuthenticationProvider
from m2.corpus import CORPUS_MANIFEST_FILENAME
from m2.query import EventStore
from m3 import InvestigationRequest, investigate
from m3.config import Limits, OllamaConfig
from m3.investigate_corpus import local_model_runtime
from m3.llm.fake import FakeLLM
from m3.llm.ollama_client import OllamaClient
from m3.models import ModelReply, QueryRequest, ToolCall
from m3.testing.factual_checks import check_synthetic_result
from m3.validate_synthetic import RecordedLLM, RecordedProvider, equivalent_tool_call, write_json_artifact

# Public telemetry windows; no classifications, runbooks or answer keys.
WINDOWS = {
    "S01": ("2022-08-31T17:46:00Z", "2022-08-31T17:49:00Z"),
    "S02": ("2026-09-21T02:04:30Z", "2026-09-21T02:06:00Z"),
    "S03": ("2026-09-21T02:24:50Z", "2026-09-21T02:26:00Z"),
}


def public_request(scenario: str) -> InvestigationRequest:
    start, end = WINDOWS[scenario]
    return InvestigationRequest(scenario_id=scenario, start_utc=start, end_utc=end)


def run_case(store, name, request, llm, limits, first_tool=None, annotate=False, expected_error=None):
    provider = RecordedProvider(limits, M2AuthenticationProvider(store, limits))
    recorded = RecordedLLM(llm, first_tool, annotate, validation_scope="corpus")
    started = time.monotonic()
    result = investigate(request, provider, recorded, limits)
    # The existing checker is telemetry-generic despite its compatibility name.
    errors = check_synthetic_result(result, provider.retrieved.values(), expected_error)
    for event in provider.retrieved.values():
        found = store.lookup(event.evidence_id)
        if found.event is None or any(getattr(found.event, key) != value
                                      for key, value in event.model_dump().items()):
            errors.append("retrieved event does not resolve unchanged in EventStore")
    if first_tool:
        try:
            actual = ModelReply.model_validate_json(recorded.calls[0]["reply"])
            if actual.action != "tool" or not equivalent_tool_call(actual.tool, first_tool):
                errors.append("model did not emit the directed approved tool call")
        except (ValueError, KeyError, IndexError):
            errors.append("directed tool response was missing or invalid")
    if annotate and (not result.findings or not all(f.interpretation for f in result.findings)):
        errors.append("directed interpretation was not supplied")
    if name == "get_missing" and not any("not found" in item for item in result.uncertainty):
        errors.append("unknown lookup was not explicitly reported")
    if name == "bounded_query" and not any("truncated" in item for item in result.uncertainty):
        errors.append("query truncation was not explicitly reported")
    return {"case": name, "elapsed_seconds": round(time.monotonic() - started, 3),
            "check_errors": errors, "expected_error": expected_error,
            "result": result.model_dump(mode="json"), "model_calls": recorded.calls,
            "provider_calls": provider.calls}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--mode", choices=("fake", "ollama"), default="fake")
    parser.add_argument("--model", default=os.getenv("MAIR_OLLAMA_MODEL", "qwen3:8b"))
    parser.add_argument("--endpoint", default=os.getenv("MAIR_OLLAMA_ENDPOINT", "http://127.0.0.1:11434"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        parser.error("output directory must be new or empty; preserve earlier run evidence")
    store = EventStore.load(args.corpus)
    if not set(WINDOWS).issubset(store.scenario_ids):
        parser.error("validation requires the public S01, S02 and S03 corpus")
    runtime = {"runtime": "fake"}
    llm = FakeLLM()
    if args.mode == "ollama":
        config = OllamaConfig(model=args.model, endpoint=args.endpoint, num_ctx=8192,
                              think=False, temperature=0.0, seed=0)
        runtime = local_model_runtime(config)
        llm = OllamaClient(config)
    limits = Limits()
    request = public_request("S02")
    events = M2AuthenticationProvider(store, limits).query(QueryRequest(**request.model_dump())).events
    if not events:
        parser.error("the public S02 validation window has no authentication records")
    anchor = next(event for event in events if event.user is not None)
    absent = "S02-SEC-999999999"
    if store.lookup(absent).status != "not_found":
        parser.error("missing-evidence exercise ID unexpectedly exists")
    get = ToolCall(name="get_authentication_event", arguments={"evidence_id": anchor.evidence_id})
    window = {**request.model_dump(), "limit": 100}
    cases = [(s, public_request(s), limits, None, False, None) for s in WINDOWS]
    cases.extend([
        ("empty", InvestigationRequest(scenario_id="S02", start_utc="2026-09-21T00:00:00Z",
                                       end_utc="2026-09-21T00:01:00Z"), limits, None, False, None),
        ("get_existing", request, limits, get, False, None),
        ("get_missing", request, limits, ToolCall(name="get_authentication_event",
                                                 arguments={"evidence_id": absent}), False, None),
        ("query_tool", request, limits, ToolCall(name="query_authentication_events",
                                                arguments={**window, "event_ids": [4624]}), False, None),
        ("account_history", request, limits, ToolCall(name="get_account_authentication_history",
                                                     arguments={**window, "account": anchor.user}), False, None),
        ("tool_budget", request, Limits(max_tool_calls=1), get, False, "tool_budget_exhausted"),
        ("bounded_query", request, Limits(max_events_per_query=2), None, False, None),
        ("interpretation", public_request("S01"), limits, None, True, None),
    ])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for name, case_request, case_limits, first_tool, annotate, expected_error in cases:
        case = run_case(store, name, case_request, llm, case_limits, first_tool, annotate, expected_error)
        filename = name + ".json"
        digest = write_json_artifact(args.output_dir / filename, case)
        summary.append({"case": name, "status": case["result"]["status"],
                        "error_code": case["result"]["error_code"], "check_errors": case["check_errors"],
                        "elapsed_seconds": case["elapsed_seconds"], "file": filename, "sha256": digest})
        print(json.dumps(summary[-1]), flush=True)
    root = Path(__file__).resolve().parents[1]
    sources = [*sorted((root / "m3").rglob("*.py")), *sorted((root / "m2").rglob("*.py"))]
    source_hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sources if "tests" not in p.parts}
    manifest = {"completed_at_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
                "runtime": runtime, "cases": summary, "source_sha256": source_hashes,
                "corpus_manifest": json.loads((args.corpus / CORPUS_MANIFEST_FILENAME).read_bytes()),
                "corpus_manifest_sha256": hashlib.sha256((args.corpus / CORPUS_MANIFEST_FILENAME).read_bytes()).hexdigest(),
                "scope": "Authentication Investigation Agent corpus integration; not detection accuracy, independent verification or orchestrator integration"}
    write_json_artifact(args.output_dir / "manifest.json", manifest)
    return 1 if any(case["check_errors"] for case in summary) else 0


if __name__ == "__main__":
    raise SystemExit(main())
