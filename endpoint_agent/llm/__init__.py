"""Use the existing local Ollama transport without authentication prompts or facts."""

from authentication_agent.llm import LLMAdapter
from authentication_agent.llm.ollama_client import OllamaClient

__all__ = ["LLMAdapter", "OllamaClient"]
