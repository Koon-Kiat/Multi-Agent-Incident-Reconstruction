"""Run the Authentication Investigation Agent over an existing verified corpus."""

import argparse
import json
import os
from pathlib import Path

import httpx
from pydantic import ValidationError

from m2.adapters.m3_provider import M2AuthenticationProvider
from m2.query import EventStore, QueryError
from m3.agent import investigate
from m3.config import Limits, OllamaConfig
from m3.llm.fake import FakeLLM
from m3.llm.ollama_client import OllamaClient
from m3.models import InvestigationRequest, InvestigationResult


def local_model_runtime(config: OllamaConfig) -> dict:
    """Confirm installed local weights before supplying evidence; never pull a model."""
    with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
        version = client.get(config.endpoint + "/api/version")
        version.raise_for_status()
        tags = client.get(config.endpoint + "/api/tags")
        tags.raise_for_status()
        version_data, tags_data = version.json(), tags.json()
        if (not isinstance(version_data, dict) or not isinstance(version_data.get("version"), str)
                or not isinstance(tags_data, dict) or not isinstance(tags_data.get("models"), list)):
            raise ValueError("invalid local runtime metadata")
        installed = next((item for item in tags_data["models"]
                          if isinstance(item, dict) and item.get("name") == config.model), None)
        if installed is None:
            raise ValueError("selected local model is not installed")
        show = client.post(config.endpoint + "/api/show", json={"model": config.model})
        show.raise_for_status()
        details = show.json()
        if not isinstance(details, dict) or not isinstance(installed.get("digest"), str):
            raise ValueError("invalid local model metadata")
        if details.get("remote_host") or details.get("remote_model"):
            raise ValueError("cloud-backed model aliases are not allowed")
        return {"runtime": "ollama", "version": version_data["version"],
                "model": config.model, "digest": installed["digest"],
                "configuration": config.model_dump()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--scenario")
    parser.add_argument("--start", help="inclusive UTC ISO 8601 timestamp")
    parser.add_argument("--end", help="exclusive UTC ISO 8601 timestamp")
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
        request = InvestigationRequest(scenario_id=args.scenario, start_utc=args.start, end_utc=args.end)
        limits = Limits(max_tool_calls=args.max_tool_calls, max_events_per_query=args.max_events,
                        max_window_seconds=args.max_window_seconds, model_timeout_seconds=args.timeout)
        config = OllamaConfig(model=args.model, endpoint=args.endpoint, num_ctx=args.num_ctx,
                              think=False, temperature=0.0, seed=0)
    except (ValueError, ValidationError):
        return _setup_error("invalid_configuration")
    try:
        store = EventStore.load(args.corpus)
    except (OSError, ValueError, QueryError):
        return _setup_error("corpus_load_failed")
    if request.scenario_id not in store.scenario_ids:
        return _setup_error("scenario_not_in_corpus")
    if args.mode == "ollama":
        try:
            local_model_runtime(config)
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return _setup_error("local_model_preflight_failed")
    llm = FakeLLM() if args.mode == "fake" else OllamaClient(config)
    result = investigate(request, M2AuthenticationProvider(store, limits), llm, limits)
    print(result.model_dump_json(indent=2))
    # A completed but truncated inventory must not be mistaken for full coverage.
    if result.status != "completed":
        return 1
    return 3 if any("truncated" in item for item in result.uncertainty) else 0


def _setup_error(code: str) -> int:
    print(json.dumps({"component": "Authentication Investigation Agent", "status": "failed",
                      "error_code": code, "findings": []}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
