"""Supported-schema and actual public-corpus integration; no evaluation answers."""

import json
from collections import Counter

import httpx
import pytest
from pydantic import ValidationError

from m2.adapters.m3_provider import M2AuthenticationProvider
from m2.corpus import normalise_datasets
from m2.corpus import write_manifest, write_scenario
from m2.manifest import load_scenario
from m2.query import EventStore
from m2.schema import NormalisedEvent
from m2.tests.conftest import real_datasets
from m2.tests.synthetic import build_scenario_dir, make_event
from m2.timeutil import ticks_to_iso
from m3 import InvestigationRequest, investigate
from m3.config import Limits, OllamaConfig
from m3.investigate_corpus import main
from m3.llm.fake import FakeLLM
from m3.models import InvestigationResult, QueryRequest, ToolCall, utc_ticks
from m3.testing.factual_checks import check_synthetic_result
from m3.validate_corpus import public_request, run_case


@pytest.fixture(scope="session")
def authentication_corpus_dir(tmp_path_factory):
    directory = tmp_path_factory.mktemp("authentication-corpus")
    normalise_datasets(real_datasets(), directory)
    return directory


@pytest.fixture(scope="session")
def corpus_store(authentication_corpus_dir):
    return EventStore.load(authentication_corpus_dir)


@pytest.mark.parametrize("scenario,counts", [("S01", {4624: 6}),
                                             ("S02", {4624: 7, 4625: 5}),
                                             ("S03", {4624: 7, 4625: 2})])
def test_real_retrieval_counts_precision_and_findings(corpus_store, scenario, counts):
    request = public_request(scenario)
    provider = M2AuthenticationProvider(corpus_store)
    query = QueryRequest(**request.model_dump())
    response = provider.query(query)
    expected = corpus_store.query(scenario, request.start_utc, request.end_utc,
                                  channels=("Security",), event_ids=(4624, 4625))
    assert not response.truncated and not expected.truncated
    assert [e.evidence_id for e in response.events] == [e.evidence_id for e in expected.events]
    assert Counter(e.source_event_id for e in response.events) == counts
    assert list(response.events) == sorted(response.events, key=lambda e: (utc_ticks(e.timestamp_utc), e.evidence_id))
    for event in response.events:
        original = corpus_store.lookup(event.evidence_id).event
        assert all(getattr(original, key) == value for key, value in event.model_dump().items())
        assert event.evidence_id == f"{scenario}-SEC-{event.record_id}"
        assert len(event.timestamp_utc.rsplit(".", 1)[1]) == 8  # seven digits and Z
        assert provider.get_event(event.evidence_id) == event
    result = investigate(request, provider, FakeLLM())
    assert check_synthetic_result(result, response.events) == []
    assert InvestigationResult.model_validate_json(result.model_dump_json()) == result
    assert sum(f.observed_events.failed_logons for f in result.findings) == counts.get(4625, 0)
    assert sum(f.observed_events.successful_logons for f in result.findings) == counts[4624]


def test_real_half_open_precision_collisions_and_exact_filters(corpus_store):
    provider = M2AuthenticationProvider(corpus_store)
    event = provider.get_event("S02-SEC-43584")
    assert event.timestamp_utc == "2026-09-21T02:05:30.0430374Z"
    assert corpus_store.lookup("S03-SEC-43584").event.source_event_id == 4688
    assert provider.get_event("S03-SEC-43584") is None
    one_tick = QueryRequest(scenario_id="S02", start_utc=event.timestamp_utc,
                           end_utc=ticks_to_iso(utc_ticks(event.timestamp_utc) + 1))
    assert [e.evidence_id for e in provider.query(one_tick).events] == [event.evidence_id]
    before = one_tick.model_copy(update={"start_utc": ticks_to_iso(utc_ticks(event.timestamp_utc) - 1),
                                        "end_utc": event.timestamp_utc})
    assert not provider.query(before).events
    assert provider.query(one_tick.model_copy(update={"account": event.user, "host": event.host})).events
    assert not provider.query(one_tick.model_copy(update={"account": event.user.swapcase()})).events
    assert not provider.query(one_tick.model_copy(update={"host": "absent-host"})).events
    assert provider.get_event("S02-SEC-999999999") is None
    assert provider.get_event("43584") is None


def test_real_empty_and_truncated_results(corpus_store):
    for name, request, limits in [
        ("empty", InvestigationRequest(scenario_id="S02", start_utc="2026-09-21T00:00:00Z",
                                       end_utc="2026-09-21T00:01:00Z"), Limits()),
        ("bounded_query", public_request("S02"), Limits(max_events_per_query=2)),
    ]:
        case = run_case(corpus_store, name, request, FakeLLM(), limits)
        assert not case["check_errors"]
        assert case["result"]["uncertainty"]
        assert case["result"]["status"] == "completed"


@pytest.mark.parametrize("tool,expected_error", [
    (ToolCall(name="get_authentication_event", arguments={"evidence_id": "S01-SEC-31213280"}), "provider_scope_violation"),
    (ToolCall(name="query_authentication_events", arguments={"scenario_id": "S03", "start_utc": "2026-09-21T02:24:50Z", "end_utc": "2026-09-21T02:26:00Z"}), "tool_scope_violation"),
])
def test_real_cross_scenario_requests_fail_closed(corpus_store, tool, expected_error):
    case = run_case(corpus_store, "scope", public_request("S02"), FakeLLM(), Limits(), tool,
                    expected_error=expected_error)
    assert case["result"]["status"] == "failed"
    # The boundary rejects the event before it can be cited, even though the
    # recording provider necessarily saw the response to the rejected lookup.
    assert case["check_errors"] == []


@pytest.mark.parametrize("error,code", [(TimeoutError(), "model_timeout"),
                                        (ConnectionError(), "model_connection_failed")])
def test_real_inference_failure_contains_no_partial_findings(corpus_store, error, code):
    class FailedLLM(FakeLLM):
        def complete(self, *args):
            raise error
    result = investigate(public_request("S02"), M2AuthenticationProvider(corpus_store), FailedLLM())
    assert result.status == "failed" and result.error_code == code and not result.findings


def test_fabricated_model_reference_is_rejected(corpus_store):
    class FabricatingLLM(FakeLLM):
        def complete(self, *args):
            return json.dumps({"action": "finish", "tool": None, "annotations": [
                {"observation_id": "invented", "evidence_ids": ["S02-SEC-999999999"], "interpretation": None}]})
    result = investigate(public_request("S02"), M2AuthenticationProvider(corpus_store), FabricatingLLM())
    assert result.status == "failed" and result.error_code == "invalid_evidence_reference"
    assert not result.findings


def test_supported_schema_missing_fields_and_returned_copy_isolation():
    original = make_event(record_id=1, event_id=4624, user=None, host=None, event_data={})
    provider = M2AuthenticationProvider(EventStore([original]))
    event = provider.get_event(original.evidence_id)
    assert event.user is None and event.host is None and event.event_data == {}
    event.event_data["added"] = "caller change"
    assert provider.get_event(original.evidence_id).event_data == {}
    # The EVTX schema deliberately rejects nested values from generic fixtures.
    with pytest.raises(ValidationError):
        NormalisedEvent(**{**original.model_dump(), "event_data": {"nested": {"value": 1}}})


def test_real_cli_success_and_incomplete(authentication_corpus_dir, capsys):
    args = ["--corpus", str(authentication_corpus_dir), "--mode", "fake", "--scenario", "S02",
            "--start", "2026-09-21T02:04:30Z", "--end", "2026-09-21T02:06:00Z"]
    assert main(args) == 0
    assert InvestigationResult.model_validate_json(capsys.readouterr().out).status == "completed"
    assert main([*args, "--max-events", "2"]) == 3
    assert "truncated" in capsys.readouterr().out


def test_cli_missing_corpus_sanitizes_error(tmp_path, capsys):
    assert main(["--corpus", str(tmp_path / "sensitive-path"), "--mode", "fake", "--scenario", "S02",
                 "--start", "2026-09-21T02:04:30Z", "--end", "2026-09-21T02:06:00Z"]) == 2
    output = capsys.readouterr().out
    assert json.loads(output)["error_code"] == "corpus_load_failed"
    assert "sensitive-path" not in output


def test_local_preflight_rejects_cloud_alias_before_inference(monkeypatch):
    from m3 import investigate_corpus
    calls = []
    def handler(request):
        calls.append(request.url.path)
        payload = {"/api/version": {"version": "test"}, "/api/tags": {"models": [{"name": "local-alias", "digest": "abc"}]},
                   "/api/show": {"remote_host": "https://example.invalid"}}[request.url.path]
        return httpx.Response(200, json=payload)
    real_client = httpx.Client
    monkeypatch.setattr(investigate_corpus.httpx, "Client",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    with pytest.raises(ValueError, match="cloud-backed"):
        investigate_corpus.local_model_runtime(OllamaConfig(model="local-alias"))
    assert calls == ["/api/version", "/api/tags", "/api/show"]


@pytest.fixture
def portable_corpus(tmp_path):
    """Valid written corpus for CLI/error coverage even in CI without Git LFS."""
    info = load_scenario(build_scenario_dir(tmp_path / "datasets"))
    destination = tmp_path / "corpus"
    events = [make_event(record_id=i, event_id=4625 if i < 3 else 4624,
                         event_data={"TargetUserName": "analyst"}) for i in (1, 2, 3)]
    write_manifest(destination, [write_scenario(destination, info, events)])
    return destination


def cli_args(corpus):
    return ["--corpus", str(corpus), "--mode", "fake", "--scenario", "SYN-B",
            "--start", "2026-09-21T02:05:00Z", "--end", "2026-09-21T02:06:00Z"]


@pytest.mark.parametrize("extra,exit_code,error", [
    ([], 0, None), (["--max-events", "1"], 3, None),
    (["--max-window-seconds", "1"], 1, "invalid_contract_or_model_response"),
    (["--max-events", "0"], 2, "invalid_configuration"),
    (["--scenario", "ABSENT"], 2, "scenario_not_in_corpus"),
])
def test_cli_portable_outcomes(portable_corpus, capsys, extra, exit_code, error):
    assert main([*cli_args(portable_corpus), *extra]) == exit_code
    payload = json.loads(capsys.readouterr().out)
    assert payload["error_code"] == error
    if error:
        assert not payload["findings"]
    else:
        InvestigationResult.model_validate_json(json.dumps(payload))


def test_cli_rejects_altered_corpus_before_inference(portable_corpus, capsys):
    path = portable_corpus / "SYN-B.jsonl"
    path.write_bytes(path.read_bytes() + b"\n")
    assert main(cli_args(portable_corpus)) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "corpus_load_failed"


def test_cli_uses_tested_local_profile(portable_corpus, monkeypatch, capsys):
    from m3 import investigate_corpus
    seen = []
    monkeypatch.setattr(investigate_corpus, "local_model_runtime", lambda config: seen.append(config))
    monkeypatch.setattr(investigate_corpus, "OllamaClient", lambda config: FakeLLM())
    assert main([*cli_args(portable_corpus), "--mode", "ollama", "--model", "installed-test"]) == 0
    config = seen[0]
    assert (config.model, config.num_ctx, config.think, config.temperature, config.seed) == ("installed-test", 8192, False, 0, 0)
    assert InvestigationResult.model_validate_json(capsys.readouterr().out).status == "completed"


@pytest.mark.parametrize("failure", [ValueError("untrusted body"), httpx.ConnectError("private detail")])
def test_cli_preflight_failure_is_sanitized(portable_corpus, monkeypatch, capsys, failure):
    from m3 import investigate_corpus
    def fail(config):
        raise failure
    monkeypatch.setattr(investigate_corpus, "local_model_runtime", fail)
    assert main([*cli_args(portable_corpus), "--mode", "ollama"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["error_code"] == "local_model_preflight_failed" and not payload["findings"]
