"""Provisional M3 integration boundary; no M2 or M5 implementation."""

from .agent import investigate
from .models import InvestigationRequest, InvestigationResult

__all__ = ["investigate", "InvestigationRequest", "InvestigationResult"]
