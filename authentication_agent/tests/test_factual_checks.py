from authentication_agent import investigate
from authentication_agent.llm.fake import FakeLLM
from authentication_agent.testing.factual_checks import check_synthetic_result
from authentication_agent.validate_synthetic import equivalent_tool_call, run_case, write_json_artifact
from authentication_agent.config import Limits
from authentication_agent.models import ToolCall


def test_factual_checker_accepts_real_fixture_facts(provider, request_a, query_a):
    result = investigate(request_a, provider, FakeLLM())
    assert check_synthetic_result(result, provider.query(query_a).events) == []


def test_factual_checker_rejects_wrong_counts_entities_time_and_ids(provider, request_a, query_a):
    result = investigate(request_a, provider, FakeLLM())
    finding = result.findings[0]
    mutations = [
        finding.model_copy(update={"observed_events": finding.observed_events.model_copy(update={"failed_logons": 99})}),
        finding.model_copy(update={"entities": finding.entities.model_copy(update={"host": "WRONG"})}),
        finding.model_copy(update={"timestamps": finding.timestamps.model_copy(update={"first_utc": "2026-01-10T00:00:00Z"})}),
        finding.model_copy(update={"evidence_ids": ("SYN-A-SEC-999",)}),
        finding.model_copy(update={"interpretation": "Confirmed compromise"}),
    ]
    for mutation in mutations:
        assert check_synthetic_result(result.model_copy(update={"findings": (mutation,)}), provider.query(query_a).events)


def test_recording_provider_and_fake_development_case():
    case = run_case("SYN-A", "SYN-A", FakeLLM(), Limits())
    assert case["check_errors"] == []
    assert len(case["model_calls"]) == 1
    assert case["provider_calls"][0]["operation"] == "query"
    assert case["result"]["metadata"]["llm"]["runtime"] == "fake"


def test_directed_tool_check_accepts_equivalent_defaults():
    arguments = {"scenario_id": "SYN-A", "start_utc": "2026-01-10T00:00:00Z", "end_utc": "2026-01-10T00:01:00Z", "account": "demo.user", "limit": 100}
    expected = ToolCall(name="get_account_authentication_history", arguments=arguments)
    expanded = ToolCall(name=expected.name, arguments={**arguments, "host": None, "event_ids": [4624, 4625]})
    assert equivalent_tool_call(expanded, expected)
    wrong_host = ToolCall(name=expected.name, arguments={**arguments, "host": "LAB-B"})
    assert not equivalent_tool_call(wrong_host, expected)
    wrong_tool = ToolCall(name="query_authentication_events", arguments=arguments)
    assert not equivalent_tool_call(wrong_tool, expected)


def test_artifact_hash_matches_bytes_written_on_windows(tmp_path):
    import hashlib
    import json
    path = tmp_path / "result.json"
    payload = {"message": "line one\nline two", "count": 3}
    digest = write_json_artifact(path, payload)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert b"\r\n" not in path.read_bytes()
    assert json.loads(path.read_bytes()) == payload
