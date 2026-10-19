"""Reuse the project's local transport configuration and explicit budgets."""

from authentication_agent.config import Limits, OllamaConfig

CONFIGURATION_VERSION = "endpoint-config-v3"

__all__ = ["Limits", "OllamaConfig", "CONFIGURATION_VERSION"]
