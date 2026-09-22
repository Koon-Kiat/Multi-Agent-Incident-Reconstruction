import pytest
from pydantic import ValidationError

from authentication_agent.models import AuthenticationEvent, InvestigationRequest, InvestigationResult, ModelReply, utc_ticks


@pytest.mark.parametrize("timestamp", ["2026-01-10T00:00:00", "2026-01-10T00:00:00+08:00", "2026-02-30T00:00:00Z", "2026-01-10T25:00:00Z", "2026-01-10T00:00:00.12345678Z", "tomorrow"])
def test_invalid_timestamps(timestamp):
    with pytest.raises(ValueError):
        utc_ticks(timestamp)


def test_full_precision(provider):
    early = provider.get_event("SYN-I-SEC-2")
    late = provider.get_event("SYN-I-SEC-1")
    assert utc_ticks(late.timestamp_utc) - utc_ticks(early.timestamp_utc) == 1
    assert AuthenticationEvent.model_validate_json(early.model_dump_json()).timestamp_utc.endswith("1234567Z")
    assert utc_ticks("2026-01-10T00:00:01.1234567+00:00") == utc_ticks(early.timestamp_utc)


@pytest.mark.parametrize("field,value", [("evidence_id", "42"), ("record_id", 0), ("record_id", "1"), ("source_event_id", True), ("channel", "System"), ("raw_reference", ""), ("host", []), ("event_data", [])])
def test_malformed_required_fields(provider, field, value):
    data = provider.get_event("SYN-A-SEC-1").model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        AuthenticationEvent.model_validate(data)


def test_missing_required_field(provider):
    data = provider.get_event("SYN-A-SEC-1").model_dump()
    del data["raw_reference"]
    with pytest.raises(ValidationError):
        AuthenticationEvent.model_validate(data)


def test_empty_and_missing_remain_distinct(provider):
    assert provider.get_event("SYN-F-SEC-1").user is None
    assert provider.get_event("SYN-F-SEC-2").user == ""


def test_non_increasing_window():
    with pytest.raises(ValidationError):
        InvestigationRequest(scenario_id="SYN-A", start_utc="2026-01-10T00:00:00Z", end_utc="2026-01-10T00:00:00Z")


def test_result_schema_is_machine_readable():
    schema = InvestigationResult.model_json_schema()
    assert schema["additionalProperties"] is False
    assert "evidence_ids" in schema["$defs"]["Finding"]["properties"]
    assert "verification_status" not in schema["$defs"]["Finding"]["properties"]


def test_reply_schema_exposes_action_constraints_to_ollama():
    schema = ModelReply.model_json_schema()
    branches = [schema["$defs"][branch["$ref"].split("/")[-1]] for branch in schema["anyOf"]]
    tool = next(branch for branch in branches if branch["properties"]["action"]["const"] == "tool")
    finish = next(branch for branch in branches if branch["properties"]["action"]["const"] == "finish")
    assert tool["properties"]["annotations"]["maxItems"] == 0
    assert "$ref" in tool["properties"]["tool"]
    assert finish["properties"]["tool"] == {"title": "Tool", "type": "null"}


def test_real_qwen_mixed_tool_and_annotation_reply_remains_rejected():
    reply = '{"action":"tool","tool":{"name":"get_authentication_event","arguments":{"evidence_id":"SYN-A-SEC-1"}},"annotations":[{"observation_id":"AUTH-5e53c21298bc2ea6a60ee799","evidence_ids":["SYN-A-SEC-1"],"interpretation":"context_required"}]}'
    with pytest.raises(ValidationError):
        ModelReply.model_validate_json(reply)
