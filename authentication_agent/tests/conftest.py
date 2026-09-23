import pytest

from authentication_agent.__main__ import synthetic_provider
from authentication_agent.models import InvestigationRequest, QueryRequest


@pytest.fixture
def provider():
    return synthetic_provider()


@pytest.fixture
def request_a():
    return InvestigationRequest(scenario_id="SYN-A", start_utc="2026-01-10T00:00:00Z", end_utc="2026-01-10T00:01:00Z")


@pytest.fixture
def query_a(request_a):
    return QueryRequest(**request_a.model_dump())
