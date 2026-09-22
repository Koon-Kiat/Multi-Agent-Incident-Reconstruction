"""Example M5 call boundary, without implementing orchestration.

Run ``python -m m3.examples.invoke_m3`` for fake mode, or add ``--ollama``
with MAIR_OLLAMA_MODEL and optionally MAIR_OLLAMA_ENDPOINT configured.
"""

import argparse
import os

from m3 import InvestigationRequest, InvestigationResult, investigate
from m3.__main__ import synthetic_provider
from m3.config import Limits, OllamaConfig
from m3.llm import LLMAdapter
from m3.llm.fake import FakeLLM
from m3.llm.ollama_client import OllamaClient
from m3.queries.interface import AuthenticationEventProvider


def invoke_authentication_agent(
    provider: AuthenticationEventProvider,
    llm: LLMAdapter,
    scenario_id: str = "SYN-A",
) -> InvestigationResult:
    request = InvestigationRequest(
        scenario_id=scenario_id,
        start_utc="2026-01-10T00:00:00Z",
        end_utc="2026-01-10T00:01:00Z",
    )
    return investigate(request, provider, llm, Limits())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ollama", action="store_true")
    parser.add_argument("--scenario", default="SYN-A")
    args = parser.parse_args()
    llm: LLMAdapter = FakeLLM()
    if args.ollama:
        model = os.getenv("MAIR_OLLAMA_MODEL")
        if not model:
            parser.error("set MAIR_OLLAMA_MODEL to an installed local model")
        llm = OllamaClient(OllamaConfig(
            model=model, endpoint=os.getenv("MAIR_OLLAMA_ENDPOINT", "http://localhost:11434"),
            num_ctx=int(os.getenv("MAIR_OLLAMA_NUM_CTX", "32768")),
            think={"auto": None, "on": True, "off": False}[os.getenv("MAIR_OLLAMA_THINK", "auto")]))
    result = invoke_authentication_agent(synthetic_provider(), llm, args.scenario)
    print(result.model_dump_json(indent=2))
    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
