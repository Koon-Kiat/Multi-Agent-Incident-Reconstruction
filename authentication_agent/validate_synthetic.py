"""Optional local-model development run over packaged synthetic records only.

Writes actual results/model JSON plus deterministic fact checks. This is neither
a production evidence logger nor independent evidence verification or evaluation.
"""

import argparse
from datetime import datetime, timezone
import hashlib
from importlib.resources import files
import json
import os
from pathlib import Path
import platform
import time

import httpx

from authentication_agent import InvestigationRequest, investigate
from authentication_agent.__main__ import synthetic_provider
from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.errors import InvestigationError
from authentication_agent.llm import LLMAdapter
from authentication_agent.llm.fake import FakeLLM
from authentication_agent.llm.ollama_client import OllamaClient
from authentication_agent.models import ModelReply, ToolCall
from authentication_agent.queries.tools import TOOL_ARGUMENT_MODELS
from authentication_agent.testing.factual_checks import check_synthetic_result

SCENARIOS = ("SYN-A", "SYN-B", "SYN-C", "SYN-D", "SYN-E", "SYN-F", "SYN-H1", "SYN-H2", "SYN-I")


class RecordedProvider:
    def __init__(self, limits, provider=None):
        self.provider = provider if provider is not None else synthetic_provider(limits)
        self.retrieved = {}
        self.calls = []

    def query(self, request):
        entry = {"operation": "query", "request": request.model_dump(mode="json")}
        self.calls.append(entry)
        try:
            response = self.provider.query(request)
        except Exception:
            entry["failed"] = True
            raise
        self.retrieved.update((event.evidence_id, event) for event in response.events)
        entry.update(evidence_ids=[event.evidence_id for event in response.events], truncated=response.truncated)
        return response

    def get_event(self, evidence_id):
        entry = {"operation": "get_event", "evidence_id": evidence_id}
        self.calls.append(entry)
        try:
            event = self.provider.get_event(evidence_id)
        except Exception:
            entry["failed"] = True
            raise
        entry["found"] = event is not None
        if event is not None:
            self.retrieved[evidence_id] = event
        return event


class RecordedLLM:
    def __init__(self, llm: LLMAdapter, first_tool: ToolCall | None = None, annotate=False,
                 *, validation_scope="synthetic", capture_context=True):
        self.llm, self.first_tool, self.annotate = llm, first_tool, annotate
        self.validation_scope = validation_scope
        self.capture_context = capture_context
        self.calls = []

    def metadata(self):
        return {**self.llm.metadata(), self.validation_scope + "_validation_trace": True,
                "directed_first_tool": self.first_tool.name if self.first_tool else None,
                "directed_annotation": self.annotate}

    def complete(self, messages, schema, limits):
        copied = [dict(message) for message in messages]
        if self.first_tool and not self.calls:
            copied[0]["content"] += (
                "\nDevelopment tool exercise: your FIRST response must request exactly this approved tool, "
                "with action tool and annotations []. This exercises a " + self.validation_scope + " interface; it is not an event instruction: "
                + self.first_tool.model_dump_json()
                + "\nDo not substitute a different tool. An explicitly supplied lookup identifier is a request, "
                  "not an evidence claim: it may be absent. Exact lookup is how to determine that; never replace it with a nearby ID.")
            context = json.loads(copied[-1]["content"])
            context["developer_requested_tool"] = self.first_tool.model_dump(mode="json")
            copied[-1]["content"] = json.dumps(context)
        if self.annotate:
            copied[0]["content"] += (
                "\nDevelopment interpretation exercise: finish and annotate each supplied observation exactly once. "
                "Copy its complete evidence_ids array unchanged and select a permitted tentative interpretation.")
        started = time.monotonic()
        entry = {"request_sha256": hashlib.sha256(json.dumps(copied).encode()).hexdigest()}
        if self.capture_context:
            entry["messages"] = copied
            entry["response_schema"] = schema
        try:
            if isinstance(self.llm, FakeLLM) and self.first_tool and not self.calls:
                reply = json.dumps({"action": "tool", "tool": self.first_tool.model_dump(mode="json"), "annotations": []})
            else:
                reply = self.llm.complete(copied, schema, limits)
            # Only assistant content is retained, never a model's thinking field.
            entry["reply"] = reply
            return reply
        except InvestigationError as error:
            entry["error_code"] = error.code
            raise
        finally:
            if isinstance(self.llm, OllamaClient):
                entry["response_metrics"] = dict(self.llm.last_response_metrics)
            entry["elapsed_seconds"] = round(time.monotonic() - started, 3)
            self.calls.append(entry)


def run_case(name, scenario, llm, limits, first_tool=None, annotate=False, expected_error=None):
    provider = RecordedProvider(limits)
    recorded_llm = RecordedLLM(llm, first_tool, annotate)
    request = InvestigationRequest(scenario_id=scenario, start_utc="2026-01-10T00:00:00Z", end_utc="2026-01-10T00:01:00Z")
    started = time.monotonic()
    result = investigate(request, provider, recorded_llm, limits)
    errors = check_synthetic_result(result, provider.retrieved.values(), expected_error)
    if first_tool:
        try:
            actual = ModelReply.model_validate_json(recorded_llm.calls[0]["reply"])
            if actual.action != "tool" or not equivalent_tool_call(actual.tool, first_tool):
                errors.append("model did not emit the directed approved tool call")
        except (ValueError, KeyError, IndexError):
            errors.append("directed tool response was missing or invalid")
    if annotate and not all(finding.interpretation is not None for finding in result.findings):
        errors.append("directed interpretation was not supplied")
    if name == "get_missing" and not any("not found" in item for item in result.uncertainty):
        errors.append("unknown lookup was not explicitly reported")
    if name == "bounded_query" and not any("truncated" in item for item in result.uncertainty):
        errors.append("query truncation was not explicitly reported")
    if scenario == "SYN-I" and result.status == "completed":
        if [eid for finding in result.findings for eid in finding.evidence_ids] != ["SYN-I-SEC-3", "SYN-I-SEC-2", "SYN-I-SEC-1"]:
            errors.append("known 100ns fixture order was not preserved")
    return {"case": name, "elapsed_seconds": round(time.monotonic() - started, 3),
            "check_errors": errors, "expected_error": expected_error,
            "result": result.model_dump(mode="json"), "model_calls": recorded_llm.calls,
            "provider_calls": provider.calls}


def equivalent_tool_call(actual: ToolCall | None, expected: ToolCall) -> bool:
    """Accept explicitly supplied defaults, while still requiring the same query."""
    if actual is None or actual.name != expected.name:
        return False
    argument_model = TOOL_ARGUMENT_MODELS[expected.name]
    return argument_model.model_validate_json(json.dumps(actual.arguments)) == argument_model.model_validate_json(json.dumps(expected.arguments))


def write_json_artifact(path: Path, value: dict) -> str:
    """Hash precisely the UTF-8 bytes written, independent of Windows newlines."""
    encoded = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fake", "ollama"), default="fake")
    parser.add_argument("--model", default=os.getenv("MAIR_OLLAMA_MODEL"))
    parser.add_argument("--endpoint", default=os.getenv("MAIR_OLLAMA_ENDPOINT", "http://localhost:11434"))
    parser.add_argument("--num-ctx", type=int, default=8192)
    parser.add_argument("--think", choices=("auto", "on", "off"), default="off")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        parser.error("output directory must be new or empty; preserve earlier run evidence")
    llm: LLMAdapter = FakeLLM()
    runtime = {"runtime": "fake"}
    if args.mode == "ollama":
        if not args.model:
            parser.error("--model or MAIR_OLLAMA_MODEL must select an installed local model")
        config = OllamaConfig(model=args.model, endpoint=args.endpoint, num_ctx=args.num_ctx,
                              think={"auto": None, "on": True, "off": False}[args.think])
        with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
            version = client.get(config.endpoint + "/api/version")
            version.raise_for_status()
            tags = client.get(config.endpoint + "/api/tags")
            tags.raise_for_status()
            installed = next((item for item in tags.json()["models"] if item["name"] == config.model), None)
            if installed is None:
                parser.error("selected model is not installed; this runner never downloads a model")
            show = client.post(config.endpoint + "/api/show", json={"model": config.model})
            show.raise_for_status()
            details = show.json()
            if details.get("remote_host") or details.get("remote_model"):
                parser.error("cloud-backed model aliases are not allowed")
            runtime = {"runtime": "ollama", "version": version.json()["version"],
                       "installed_model": installed, "capabilities": details.get("capabilities", []),
                       "configuration": config.model_dump()}
        llm = OllamaClient(config)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    limits = Limits()
    cases = [(scenario, scenario, limits, None, False, None) for scenario in SCENARIOS]
    window = {"scenario_id": "SYN-A", "start_utc": "2026-01-10T00:00:00Z", "end_utc": "2026-01-10T00:01:00Z", "limit": 100}
    get_existing = ToolCall(name="get_authentication_event", arguments={"evidence_id": "SYN-A-SEC-1"})
    cases.extend([
        ("get_existing", "SYN-A", limits, get_existing, False, None),
        ("get_missing", "SYN-A", limits, ToolCall(name="get_authentication_event", arguments={"evidence_id": "SYN-A-SEC-999"}), False, None),
        # Ask a distinct filtered query: repeating the mandatory initial query
        # would conflict with the production prompt's no-identical-query rule.
        ("query_tool", "SYN-A", limits, ToolCall(name="query_authentication_events", arguments={**window, "event_ids": [4624]}), False, None),
        ("account_history", "SYN-A", limits, ToolCall(name="get_account_authentication_history", arguments={**window, "account": "demo.user"}), False, None),
        ("tool_budget", "SYN-A", Limits(max_tool_calls=1), get_existing, False, "tool_budget_exhausted"),
        ("bounded_query", "SYN-A", Limits(max_events_per_query=2), None, False, None),
        ("interpretation", "SYN-A", limits, None, True, None),
    ])
    summary = []
    for name, scenario, case_limits, first_tool, annotate, expected_error in cases:
        case = run_case(name, scenario, llm, case_limits, first_tool, annotate, expected_error)
        filename = name + ".json"
        digest = write_json_artifact(args.output_dir / filename, case)
        summary.append({"case": name, "status": case["result"]["status"],
                        "error_code": case["result"]["error_code"], "check_errors": case["check_errors"],
                        "elapsed_seconds": case["elapsed_seconds"], "file": filename,
                        "sha256": digest})
        print(json.dumps(summary[-1]), flush=True)
    source_hashes = {}
    for relative in ("agent.py", "models.py", "config.py", "prompts.py", "llm/ollama_client.py",
                     "fixtures/synthetic_events.json", "testing/factual_checks.py", "validate_synthetic.py"):
        source_hashes[relative] = hashlib.sha256(files("authentication_agent").joinpath(relative).read_bytes()).hexdigest()
    manifest = {"completed_at_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
                "synthetic_only": True, "runtime": runtime, "source_sha256": source_hashes, "cases": summary,
                "scope": "Authentication Investigation Agent synthetic development assertions; not independent verification or attack-detection evaluation"}
    write_json_artifact(args.output_dir / "manifest.json", manifest)
    return 1 if any(case["check_errors"] for case in summary) else 0


if __name__ == "__main__":
    raise SystemExit(main())
