"""Authentication Investigation Agent development evaluation of optional retrieval, separate from factual completion.

Expectations and availability probes never enter the model request. This is not
incident classification, private ground-truth scoring, or independent verification.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from authentication_agent import InvestigationRequest, RequiredOperations, ToolCall
from authentication_agent.__main__ import synthetic_provider
from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.investigate_corpus import local_model_runtime
from authentication_agent.llm.fake import FakeLLM
from authentication_agent.llm.ollama_client import OllamaClient
from authentication_agent.models import ModelReply
from authentication_agent.queries.tools import AuthenticationTools
from authentication_agent.validate_corpus import public_request
from authentication_agent.validate_investigations import run_case, source_hashes
from authentication_agent.validate_synthetic import write_json_artifact
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.corpus import CORPUS_MANIFEST_FILENAME
from event_processing.query import EventStore


def evaluation_cases(store):
    """Reuse public windows and existing bounded fixtures, without hiding records."""
    synthetic = InvestigationRequest(scenario_id="SYN-A", start_utc="2026-01-10T00:00:00Z",
                                     end_utc="2026-01-10T00:01:00Z")
    real = public_request("S02")
    missing = ToolCall(name="get_authentication_event", arguments={"evidence_id": "S02-SEC-999999999"})
    if store.lookup(missing.arguments["evidence_id"]).status != "not_found":
        raise ValueError("missing-evidence fixture must be absent")
    return [
        ("sufficient", "synthetic", synthetic, Limits(), None, None,
         "The complete initial authentication inventory is sufficient; no new evidence is available."),
        ("useful_synthetic", "synthetic", synthetic, Limits(max_events_per_query=2), None, 4624,
         "Do the observed failed logons have a subsequent successful logon in the requested window?"),
        ("useful_corpus", "corpus", real, Limits(max_events_per_query=2), None, 4625,
         "Does the incomplete window also contain failed logons, beyond the initial service successes?"),
        ("empty", "corpus", real.model_copy(update={"start_utc": "2026-09-21T00:00:00Z",
                                                    "end_utc": "2026-09-21T00:01:00Z"}), Limits(), None, None,
         "No records are available in this window; repeating it cannot supply context."),
        ("missing_context", "synthetic", synthetic.model_copy(update={"scenario_id": "SYN-F"}),
         Limits(), None, None, "Missing or conflicting identity fields cannot be repaired by re-fetching these records."),
        ("missing_exact", "corpus", real, Limits(), RequiredOperations.from_calls(missing), None,
         "A trusted caller requested an absent exact record; retain the missing result without substitution."),
    ]


def availability_probe(request, provider, limits, event_id):
    """Independent approved-boundary witness; never sent to the investigation.

    A witness is one possible retrieval, not a required model tool/argument plan.
    The small cap is the pre-existing coverage test and applies to every query.
    """
    tools = AuthenticationTools(request, provider, limits)
    initial = tools.execute(ToolCall(name="query_authentication_events",
                                    arguments={**request.model_dump(), "limit": limits.max_events_per_query}), origin="initial")
    if event_id is not None:
        tools.execute(ToolCall(name="query_authentication_events", arguments={
            **request.model_dump(), "limit": limits.max_events_per_query, "event_ids": [event_id]}))
        if not initial["truncated"] or not tools.operations[-1].new_evidence_ids:
            raise ValueError("follow-up fixture has no demonstrated retrieval opportunity")
    return {"operations": [op.model_dump(mode="json") for op in tools.operations],
            "events": [event.model_dump(mode="json") for event in tools.retrieved.values()]}


def assess(case, event_id=None):
    """Score observable behavior without prescribing the model's chosen query."""
    operations = case["result"]["metadata"]["operations"]
    optional = [op for op in operations if op["origin"] == "model"]
    initial_ids = set(operations[0]["evidence_ids"])
    optional_new={eid for op in optional for eid in op["new_evidence_ids"]}
    # Record contents must actually occur in a post-retrieval model context.
    reviewed = {}
    annotations = set()
    finished = False
    for call in case["model_calls"]:
        context = json.loads(call["messages"][-1]["content"])
        for observation in context["observations"]:
            for event in observation["events"]:
                if event["evidence_id"] in optional_new:
                    reviewed[event["evidence_id"]] = event
        if "reply" in call:
            try:
                from authentication_agent.planning import parse_reply
                reply = parse_reply(call["reply"],context["observations"],context.get("available_queries",{}))
            except ValueError:
                continue
            if reply.action == "finish":
                finished = True
                annotations.update(eid for annotation in reply.annotations if annotation.interpretation is not None
                                   for eid in annotation.evidence_ids)
    new_ids = {eid for op in optional if op["status"] == "completed" and op["provider_invoked"]
               for eid in op["new_evidence_ids"]} - initial_ids
    relevant = {eid for eid in new_ids if eid in reviewed and reviewed[eid]["event_id"] == event_id}
    qualified = case["result"]["status"] == "completed" and not case["check_errors"] and finished
    used = relevant & annotations
    errors = []
    if not qualified:
        errors.append("factual completion or final model response failed")
    if any(op["reused_from"] is not None for op in optional):
        errors.append("model repeated an identical operation")
    if event_id is not None and not used:
        errors.append("useful new outcome was not retrieved, reviewed and explicitly annotated by the model")
    return {"opportunity_requires_new_outcome": event_id, "optional_operation_count": len(optional),
            "new_evidence_ids": sorted(new_ids), "reviewed_new_evidence_ids": sorted(new_ids & reviewed.keys()),
            "relevant_new_evidence_ids": sorted(relevant), "model_annotated_relevant_ids": sorted(used),
            "qualified_completion": qualified, "useful_autonomous_retrieval_demonstrated": bool(used) and qualified,
            "behavior_errors": errors,
            "interpretation_limit": "An exact qualified annotation demonstrates use; it does not expose the model's reasoning or establish compromise."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--mode", choices=("fake", "ollama"), default="fake")
    parser.add_argument("--model", default="qwen3:8b")
    parser.add_argument("--think", choices=("off", "on"), default="off")
    parser.add_argument("--max-output-tokens", type=int, default=2048)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--repetitions", type=int, choices=(1, 2, 3), default=3)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        parser.error("output directory must be new or empty; preserve earlier recordings")
    store = EventStore.load(args.corpus)
    llm, runtime = FakeLLM(), {"runtime": "fake"}
    if args.mode == "ollama":
        config = OllamaConfig(model=args.model, num_ctx=8192, think=args.think == "on", temperature=0.0, seed=0)
        runtime, llm = local_model_runtime(config), OllamaClient(config)
    before = source_hashes()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for name, kind, request, limits, required, outcome, question in evaluation_cases(store):
        limits = Limits(**{**limits.model_dump(), "max_output_tokens": args.max_output_tokens,
                           "model_timeout_seconds": args.timeout})
        provider = CorpusAuthenticationProvider(store, limits) if kind == "corpus" else synthetic_provider(limits)
        witness = availability_probe(request, provider, limits, outcome)
        for repeat in range(1, args.repetitions + 1):
            # run_case sees only request/provider/limits and trusted requirements.
            # No question, witness, expected outcome, labels or tool plan is injected.
            case = run_case(f"{name}-{repeat}", "autonomy", request, provider, llm, limits, required)
            assessment = assess(case, outcome)
            case["evaluation_only"] = {"unresolved_question": question, "availability_witness": witness,
                                       "assessment": assessment}
            filename = case["case"] + ".json"
            digest = write_json_artifact(args.output_dir / filename, case)
            item = {"case": case["case"], "file": filename, "sha256": digest,
                    "status": case["result"]["status"], "check_errors": case["check_errors"], **assessment}
            summary.append(item)
            print(json.dumps(item), flush=True)
    stable = before == source_hashes()
    write_json_artifact(args.output_dir / "manifest.json", {
        "completed_at_utc": datetime.now(timezone.utc).isoformat(), "runtime": runtime,
        "source_sha256": before, "source_unchanged_during_run": stable,
        "corpus_manifest_sha256": hashlib.sha256((args.corpus / CORPUS_MANIFEST_FILENAME).read_bytes()).hexdigest(),
        "repetitions": args.repetitions, "cases": summary,
        "scope": "Authentication Investigation Agent development behavior checks; fake mode cannot demonstrate local-model autonomy"})
    return int(not stable or any(item["check_errors"] or item["behavior_errors"] for item in summary))


if __name__ == "__main__":
    raise SystemExit(main())
