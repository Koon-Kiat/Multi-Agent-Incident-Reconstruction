from typing import Protocol

from authentication_agent.config import Limits


class LLMAdapter(Protocol):
    def metadata(self) -> dict: ...

    def complete(self, messages: list[dict[str, str]], schema: dict, limits: Limits) -> str: ...
