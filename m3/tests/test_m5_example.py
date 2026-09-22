from m3.__main__ import synthetic_provider
from m3.examples.invoke_m3 import invoke_authentication_agent
from m3.llm.fake import FakeLLM
from m3.models import InvestigationResult


def test_m5_example_success_and_empty():
    success = invoke_authentication_agent(synthetic_provider(), FakeLLM())
    assert success.status == "completed" and success.findings[0].observed_events.failed_logons == 3
    assert InvestigationResult.model_validate_json(success.model_dump_json()) == success
    empty = invoke_authentication_agent(synthetic_provider(), FakeLLM(), "SYN-E")
    assert empty.status == "completed" and empty.findings == () and empty.uncertainty


def test_m5_example_failure_envelope():
    class UnavailableLLM(FakeLLM):
        def complete(self, messages, schema, limits):
            raise TimeoutError
    failure = invoke_authentication_agent(synthetic_provider(), UnavailableLLM())
    assert failure.status == "failed" and failure.error_code == "model_timeout"
    assert failure.findings == ()
    assert InvestigationResult.model_validate_json(failure.model_dump_json()) == failure
