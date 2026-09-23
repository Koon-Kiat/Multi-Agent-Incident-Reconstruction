import asyncio
import json
import os

import httpx
import pytest
from pydantic import ValidationError

from authentication_agent.agent import investigate
from authentication_agent.config import Limits, OllamaConfig
from authentication_agent.errors import InvestigationError
from authentication_agent.llm.ollama_client import OllamaClient
from authentication_agent.models import ModelReply


def test_structured_local_request():
    def handler(request):
        payload = json.loads(request.content)
        assert str(request.url) == "http://127.0.0.1:11434/api/chat"
        assert payload["format"] == ModelReply.model_json_schema()
        assert payload["stream"] is False
        assert payload["options"]["num_predict"] == 2048
        assert payload["model"] == "test-local"
        return httpx.Response(200, json={"done": True, "message": {"content": '{"action":"finish","tool":null,"annotations":[]}'}})
    client = OllamaClient(OllamaConfig(model="test-local"), httpx.MockTransport(handler))
    assert ModelReply.model_validate_json(client.complete([], ModelReply.model_json_schema(), Limits())).action == "finish"


def test_absolute_request_deadline():
    async def handler(_):
        await asyncio.sleep(3)
        return httpx.Response(200, json={"done": True, "message": {"content": "{}"}})
    client = OllamaClient(OllamaConfig(model="test-local"), httpx.MockTransport(handler))
    with pytest.raises(InvestigationError, match="model_timeout"):
        client.complete([], {}, Limits(model_timeout_seconds=1))


def test_running_event_loop_requires_worker_thread():
    async def check():
        with pytest.raises(InvestigationError, match="sync_adapter_requires_worker_thread"):
            OllamaClient(OllamaConfig(model="test-local")).complete([], {}, Limits())
    asyncio.run(check())


@pytest.mark.parametrize("think", [None, False, True])
def test_explicit_thinking_and_context_settings_reach_runtime(think):
    def handler(request):
        payload = json.loads(request.content)
        assert payload["options"]["num_ctx"] == 8192
        assert payload["options"]["num_predict"] == 2048
        if think is None:
            assert "think" not in payload
        else:
            assert payload["think"] is think
        return httpx.Response(200, json={"done": True, "message": {"content": '{"action":"finish","tool":null,"annotations":[]}'}})
    client = OllamaClient(OllamaConfig(model="test-local", num_ctx=8192, think=think), httpx.MockTransport(handler))
    client.complete([], ModelReply.model_json_schema(), Limits())
    assert client.metadata()["think"] is think


@pytest.mark.parametrize("status,code", [(404, "model_not_installed_or_endpoint_missing"), (500, "ollama_http_error"), (302, "ollama_http_error")])
def test_http_failures(status, code):
    client = OllamaClient(OllamaConfig(model="test-local"), httpx.MockTransport(lambda _: httpx.Response(status, text="private data", headers={"location": "https://example.invalid"})))
    with pytest.raises(InvestigationError, match=code):
        client.complete([], {}, Limits())


@pytest.mark.parametrize("error,code", [(httpx.ConnectError("refused"), "model_connection_failed"), (httpx.ReadTimeout("timed out"), "model_timeout")])
def test_transport_failures(provider, request_a, error, code):
    def handler(_): raise error
    client = OllamaClient(OllamaConfig(model="test-local"), httpx.MockTransport(handler))
    result = investigate(request_a, provider, client)
    assert result.error_code == code and not result.findings


@pytest.mark.parametrize("body,code", [(b"invalid json", "invalid_model_response"), (b'{}', "incomplete_model_response"), (b'{"done":true,"message":{}}', "invalid_model_response"), (b'{"done":true,"done_reason":"length"}', "incomplete_model_response"), (b"x" * 20000, "model_output_limit")])
def test_invalid_envelopes(body, code):
    client = OllamaClient(OllamaConfig(model="test-local"), httpx.MockTransport(lambda _: httpx.Response(200, content=body)))
    with pytest.raises(InvestigationError, match=code):
        client.complete([], {}, Limits(max_model_output_bytes=256))


@pytest.mark.parametrize("endpoint", ["https://example.com", "http://192.0.2.1:11434", "http://localhost.evil:11434", "http://user@localhost:11434", "http://localhost:11434/private", "http://localhost:11434?x=y", "http://localhost:0"])
def test_remote_endpoints_and_credential_urls_rejected(endpoint):
    with pytest.raises(ValidationError):
        OllamaConfig(model="test-local", endpoint=endpoint)


@pytest.mark.parametrize("model", ["", " ", "model-cloud", "model:cloud", " model "])
def test_model_must_be_explicit_local(model):
    with pytest.raises(ValidationError):
        OllamaConfig(model=model)


@pytest.mark.ollama
@pytest.mark.skipif(os.getenv("MAIR_RUN_OLLAMA_SMOKE") != "1", reason="optional: set MAIR_RUN_OLLAMA_SMOKE=1 and MAIR_OLLAMA_MODEL")
def test_installed_ollama_smoke(provider, request_a):
    model = os.getenv("MAIR_OLLAMA_MODEL")
    assert model, "MAIR_OLLAMA_MODEL must select an installed local model"
    client = OllamaClient(OllamaConfig(model=model,
        endpoint=os.getenv("MAIR_OLLAMA_ENDPOINT", "http://localhost:11434"),
        num_ctx=int(os.getenv("MAIR_OLLAMA_NUM_CTX", "32768")),
        think={"auto": None, "on": True, "off": False}[os.getenv("MAIR_OLLAMA_THINK", "auto")]))
    result = investigate(request_a, provider, client)
    assert result.status == "completed", result.error_code
    assert result.findings[0].observed_events.failed_logons == 3
