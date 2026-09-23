"""Runnable call boundary with optional trusted requirements; no orchestration.

python -m authentication_agent.examples.investigate_required_corpus --corpus out/corpus
Add --ollama for installed local qwen3:8b, and --required-id for a caller-required
exact lookup. Omit --required-id for ordinary model-selected investigation.
"""

import argparse

from authentication_agent import InvestigationRequest, RequiredOperations, ToolCall, investigate
from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.investigate_corpus import local_model_runtime
from authentication_agent.llm.fake import FakeLLM
from authentication_agent.llm.ollama_client import OllamaClient
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.query import EventStore


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--scenario", default="S02")
    parser.add_argument("--start", default="2026-09-21T02:04:30Z")
    parser.add_argument("--end", default="2026-09-21T02:06:00Z")
    parser.add_argument("--ollama", action="store_true")
    parser.add_argument("--required-id", action="append", default=[])
    args = parser.parse_args()
    limits = Limits()
    provider = CorpusAuthenticationProvider(EventStore.load(args.corpus), limits)
    llm = FakeLLM()
    if args.ollama:
        config = OllamaConfig(model="qwen3:8b", num_ctx=8192, think=False, temperature=0.0, seed=0)
        local_model_runtime(config)
        llm = OllamaClient(config)
    request = InvestigationRequest(scenario_id=args.scenario, start_utc=args.start, end_utc=args.end)
    required = RequiredOperations.from_calls(*(ToolCall(name="get_authentication_event",
        arguments={"evidence_id": eid}) for eid in args.required_id))
    result = investigate(request, provider, llm, limits, required_operations=required)
    print(result.model_dump_json(indent=2))
    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
