"""Run the Endpoint Investigation Agent against a verified shared event corpus."""

import argparse
import json
import os
from pathlib import Path

import httpx

from authentication_agent.investigate_corpus import local_model_runtime
from endpoint_agent.agent import investigate
from endpoint_agent.config import Limits, OllamaConfig
from endpoint_agent.llm import OllamaClient
from endpoint_agent.llm.fake import FakeLLM
from endpoint_agent.models import InvestigationRequest, InvestigationResult
from event_processing.adapters.endpoint_provider import CorpusEndpointProvider
from event_processing.query import EventStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--scenario")
    parser.add_argument("--start", help="inclusive UTC timestamp")
    parser.add_argument("--end", help="exclusive UTC timestamp")
    parser.add_argument("--evidence-id", action="append", default=[], help="exact Sysmon trigger ID; repeatable")
    parser.add_argument("--mode", choices=("fake", "ollama"), default="ollama")
    parser.add_argument("--model", default=os.getenv("MAIR_OLLAMA_MODEL", "qwen3:8b"))
    parser.add_argument("--endpoint", default=os.getenv("MAIR_OLLAMA_ENDPOINT", "http://127.0.0.1:11434"))
    parser.add_argument("--num-ctx", type=int, default=8192)
    parser.add_argument("--max-tool-calls", type=int, default=8)
    parser.add_argument("--max-events", type=int, default=100)
    parser.add_argument("--max-window-seconds", type=int, default=3600)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--schema", action="store_true")
    args = parser.parse_args(argv)
    if args.schema:
        print(json.dumps(InvestigationResult.model_json_schema(), indent=2))
        return 0
    if not all((args.corpus, args.scenario, args.start, args.end)):
        parser.error("--corpus, --scenario, --start and --end are required")
    try:
        request = InvestigationRequest(scenario_id=args.scenario, start_utc=args.start, end_utc=args.end,
                                       seed_evidence_ids=tuple(args.evidence_id))
        limits = Limits(max_tool_calls=args.max_tool_calls, max_events_per_query=args.max_events,
                        max_window_seconds=args.max_window_seconds, model_timeout_seconds=args.timeout)
        config = OllamaConfig(model=args.model, endpoint=args.endpoint, num_ctx=args.num_ctx,
                              think=False, temperature=0.0, seed=0)
    except ValueError:
        return _setup_error("invalid_configuration")
    try:
        store = EventStore.load(args.corpus)
    except (OSError, ValueError):
        return _setup_error("corpus_load_failed")
    if request.scenario_id not in store.scenario_ids:
        return _setup_error("scenario_not_in_corpus")
    runtime = None
    if args.mode == "ollama":
        try:
            runtime = local_model_runtime(config)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return _setup_error("local_model_preflight_failed")
    llm = FakeLLM() if args.mode == "fake" else OllamaClient(config)
    result = investigate(request, CorpusEndpointProvider(store, limits), llm, limits)
    if runtime is not None:
        result = result.model_copy(update={"metadata": result.metadata.model_copy(update={"llm": runtime})})
    print(result.model_dump_json(indent=2))
    if result.status == "failed":
        return 1
    return 3 if result.metadata.truncated else 0


def _setup_error(code: str) -> int:
    print(json.dumps({"component": "Endpoint Investigation Agent", "status": "failed",
                      "error_code": code, "findings": []}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
