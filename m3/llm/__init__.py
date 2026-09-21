from typing import Protocol

from m3.config import Limits


class LLMAdapter(Protocol):
    def metadata(self) -> dict: ...

    def complete(self, messages: list[dict[str, str]], schema: dict, limits: Limits) -> str: ...
