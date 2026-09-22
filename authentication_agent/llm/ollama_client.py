"""Bounded loopback-only Ollama transport; never pulls models or follows redirects."""

import asyncio
import json

import httpx

from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.errors import InvestigationError


class OllamaClient:
    def __init__(self, config: OllamaConfig, transport: httpx.AsyncBaseTransport | None = None):
        self.config, self._transport = config, transport

    def metadata(self) -> dict:
        return {"runtime": "ollama", **self.config.model_dump()}

    def complete(self, messages: list[dict[str, str]], schema: dict, limits: Limits) -> str:
        # The public Incident Reconstruction Orchestrator entry point is synchronous. Async orchestrators should run
        # investigate via asyncio.to_thread, keeping local model I/O off their loop.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._complete(messages, schema, limits))
        raise InvestigationError("sync_adapter_requires_worker_thread")

    async def _complete(self, messages: list[dict[str, str]], schema: dict, limits: Limits) -> str:
        payload = {"model": self.config.model, "messages": messages, "format": schema,
                   "stream": False, "options": {"temperature": self.config.temperature,
                   "seed": self.config.seed, "num_ctx": self.config.num_ctx,
                   "num_predict": limits.max_output_tokens}}
        if self.config.think is not None:
            payload["think"] = self.config.think
        try:
            async with asyncio.timeout(limits.model_timeout_seconds):
                async with httpx.AsyncClient(transport=self._transport, timeout=limits.model_timeout_seconds,
                                            follow_redirects=False, trust_env=False) as client:
                    async with client.stream("POST", self.config.endpoint + "/api/chat", json=payload) as response:
                        if response.status_code == 404:
                            raise InvestigationError("model_not_installed_or_endpoint_missing")
                        if response.status_code != 200:
                            raise InvestigationError("ollama_http_error")
                        chunks = bytearray()
                        async for chunk in response.aiter_bytes():
                            chunks.extend(chunk)
                            if len(chunks) > limits.max_model_output_bytes + 16384:
                                raise InvestigationError("model_output_limit")
            envelope = json.loads(chunks)
            if not isinstance(envelope, dict) or envelope.get("done") is not True or envelope.get("done_reason") == "length":
                raise InvestigationError("incomplete_model_response")
            content = envelope["message"]["content"]
            if not isinstance(content, str):
                raise InvestigationError("invalid_model_response")
            if len(content.encode()) > limits.max_model_output_bytes:
                raise InvestigationError("model_output_limit")
            return content
        except (httpx.TimeoutException, TimeoutError):
            raise InvestigationError("model_timeout") from None
        except httpx.RequestError:
            raise InvestigationError("model_connection_failed") from None
        except (ValueError, KeyError, TypeError):
            raise InvestigationError("invalid_model_response") from None
