"""Local-only CLI; the fixture path is fixed and never model-controlled."""

import argparse
import json
import os
from importlib.resources import files

from pydantic import TypeAdapter, ValidationError

from authentication_agent.agent import investigate
from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.llm.fake import FakeLLM
from authentication_agent.llm.ollama_client import OllamaClient
from authentication_agent.models import AuthenticationEvent, InvestigationRequest, InvestigationResult
from authentication_agent.queries.in_memory import InMemoryAuthenticationEventProvider


def synthetic_provider(limits: Limits | None = None) -> InMemoryAuthenticationEventProvider:
    contents = files("authentication_agent").joinpath("fixtures/synthetic_events.json").read_text(encoding="utf-8")
    events = TypeAdapter(list[AuthenticationEvent]).validate_json(contents)
    return InMemoryAuthenticationEventProvider(events, limits)


def main() -> int:
    parser = argparse.ArgumentParser(description="Investigate synthetic Windows authentication evidence locally")
    parser.add_argument("--mode", choices=("fake", "ollama"), default="fake")
    parser.add_argument("--scenario")
    parser.add_argument("--start", help="inclusive UTC ISO 8601 timestamp")
    parser.add_argument("--end", help="exclusive UTC ISO 8601 timestamp")
    parser.add_argument("--model", default=os.getenv("MAIR_OLLAMA_MODEL"))
    parser.add_argument("--endpoint", default=os.getenv("MAIR_OLLAMA_ENDPOINT", "http://localhost:11434"))
    parser.add_argument("--num-ctx", type=int, default=os.getenv("MAIR_OLLAMA_NUM_CTX", "32768"))
    parser.add_argument("--think", choices=("auto", "on", "off"), default=os.getenv("MAIR_OLLAMA_THINK", "auto"))
    parser.add_argument("--schema", action="store_true", help="print the provisional result JSON schema")
    parser.add_argument("--max-tool-calls", type=int, default=8)
    parser.add_argument("--max-events", type=int, default=100)
    parser.add_argument("--max-window-seconds", type=int, default=3600)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    if args.schema:
        print(json.dumps(InvestigationResult.model_json_schema(), indent=2))
        return 0
    if not all((args.scenario, args.start, args.end)):
        parser.error("--scenario, --start and --end are required")
    if args.mode == "ollama" and not args.model:
        parser.error("set --model or MAIR_OLLAMA_MODEL to an installed local model")
    try:
        request = InvestigationRequest(scenario_id=args.scenario, start_utc=args.start, end_utc=args.end)
        limits = Limits(max_tool_calls=args.max_tool_calls, max_events_per_query=args.max_events,
                        max_window_seconds=args.max_window_seconds, model_timeout_seconds=args.timeout)
        thinking = {"auto": None, "on": True, "off": False}.get(args.think)
        if args.think not in ("auto", "on", "off"):
            raise ValueError("invalid MAIR_OLLAMA_THINK")
        llm = FakeLLM() if args.mode == "fake" else OllamaClient(OllamaConfig(
            model=args.model, endpoint=args.endpoint, num_ctx=args.num_ctx, think=thinking))
        result = investigate(request, synthetic_provider(limits), llm, limits)
    except (ValidationError, ValueError):
        print(json.dumps({"status": "failed", "error_code": "invalid_configuration_or_fixture", "findings": []}))
        return 2
    print(result.model_dump_json(indent=2))
    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
