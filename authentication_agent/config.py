"""Explicit local runtime settings and investigation budgets."""

from ipaddress import ip_address
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from .models import Model

CONFIGURATION_VERSION = "authentication-config-v3"


class Limits(Model):
    max_tool_calls: int = Field(default=8, ge=1, le=100)
    max_events_per_query: int = Field(default=100, ge=1, le=1000)
    max_window_seconds: int = Field(default=3600, ge=1, le=86400)
    max_model_output_bytes: int = Field(default=32768, ge=256, le=1048576)
    max_event_bytes: int = Field(default=16384, ge=512, le=1048576)
    max_context_bytes: int = Field(default=262144, ge=4096, le=4194304)
    model_timeout_seconds: int = Field(default=60, ge=1, le=300)
    max_output_tokens: int = Field(default=2048, ge=128, le=8192)


class OllamaConfig(Model):
    model: str = Field(min_length=1, max_length=200)
    endpoint: str = "http://localhost:11434"
    temperature: float = Field(default=0.0, ge=0, le=2)
    seed: int = 0
    num_ctx: int = Field(default=32768, ge=1024, le=131072)
    think: bool | None = None

    @field_validator("model")
    @classmethod
    def local_model(cls, value: str) -> str:
        if not value.strip() or value != value.strip() or "cloud" in value.lower():
            raise ValueError("select an explicitly installed local model, not a cloud model")
        return value

    @field_validator("endpoint")
    @classmethod
    def loopback_endpoint(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("Ollama endpoint must be a plain local HTTP origin")
        try:
            local = parsed.hostname == "localhost" or ip_address(parsed.hostname or "").is_loopback
            port = parsed.port
        except ValueError:
            local = False
            port = None
        if not local or port == 0:
            raise ValueError("Ollama endpoint must use localhost or a loopback IP")
        # Pin localhost to loopback rather than delegate its resolution to a proxy/DNS.
        host = "127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname
        host = f"[{host}]" if ":" in host else host
        return f"http://{host}" + (f":{port}" if port else "")
