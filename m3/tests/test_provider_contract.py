import pytest

from m3.queries.in_memory import InMemoryAuthenticationEventProvider
from m3.testing.provider_contract import AuthenticationProviderContract


class TestInMemoryProviderContract(AuthenticationProviderContract):
    @pytest.fixture
    def provider_factory(self):
        return lambda events, limits: InMemoryAuthenticationEventProvider(events, limits)
