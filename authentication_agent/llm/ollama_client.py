"""Bounded loopback-only Ollama transport; never pulls models or follows redirects."""

import asyncio
import json

import httpx

from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.errors import InvestigationError


class OllamaClient:
    def __init__(self, config: OllamaConfig, transport: httpx.AsyncBaseTransport | None = None):
        self.config, self._transport = config, transport
        self.last_response_metrics: dict = {}

    def metadata(self) -> dict:
        return {"runtime": "ollama", **self.config.model_dump()}

    def input_token_upper_bound(self,messages) -> int:
        from .token_counting import input_upper_bound
        return input_upper_bound(messages,self.config.endpoint,self.config.model)

    def complete(self, messages: list[dict[str, str]], schema: dict, limits: Limits) -> str:
        self.last_response_metrics = {}
        # The public Incident Reconstruction Orchestrator entry point is synchronous. Async orchestrators should run
        # investigate via asyncio.to_thread, keeping local model I/O off their loop.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            from authentication_agent.context import context_measure
            fits,_,upper=context_measure(messages,schema,self.metadata(),limits,self.input_token_upper_bound)
            if not fits:
                raise InvestigationError("context_size_limit")
            result=asyncio.run(self._complete(messages, schema, limits))
            if self.last_response_metrics.get("prompt_eval_count",0)>upper:
                raise InvestigationError("tokenizer_context_bound_mismatch")
            return result
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
            if isinstance(envelope, dict):
                # Development diagnostics only: no thinking text or machine data.
                self.last_response_metrics = {key: envelope[key] for key in ("prompt_eval_count", "eval_count")
                    if type(envelope.get(key)) is int and envelope[key] >= 0}
                if envelope.get("done_reason") in ("stop", "length"):
                    self.last_response_metrics["done_reason"] = envelope["done_reason"]
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
