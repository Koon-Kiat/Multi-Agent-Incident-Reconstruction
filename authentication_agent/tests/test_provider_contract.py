import pytest

from authentication_agent.queries.in_memory import InMemoryAuthenticationEventProvider
from authentication_agent.testing.provider_contract import AuthenticationProviderContract


class TestInMemoryProviderContract(AuthenticationProviderContract):
    @pytest.fixture
    def provider_factory(self):
        return lambda events, limits: InMemoryAuthenticationEventProvider(events, limits)
