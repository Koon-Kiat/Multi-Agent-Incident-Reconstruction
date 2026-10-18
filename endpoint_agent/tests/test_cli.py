import json
import os
import subprocess
import sys

import httpx
import pytest

from endpoint_agent import InvestigationRequest
from endpoint_agent.investigate_corpus import main
from endpoint_agent.llm.fake import FakeLLM
from endpoint_agent.models import InvestigationResult
from endpoint_agent.tests.conftest import CHILD, ROOT, endpoint_event
from event_processing.corpus import write_manifest, write_scenario
from event_processing.manifest import load_scenario
from event_processing.tests.synthetic import build_scenario_dir


@pytest.fixture
def portable_corpus(tmp_path):
    info = load_scenario(build_scenario_dir(tmp_path / "datasets"))
    destination = tmp_path / "corpus"
    events = [endpoint_event(1, scenario=info.scenario_id, ProcessGuid=ROOT, Image="explorer.exe"),
              endpoint_event(2, second=1, scenario=info.scenario_id, ProcessGuid=CHILD,
                             ParentProcessGuid=ROOT, ParentImage="explorer.exe", Image="powershell.exe")]
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
    (["--evidence-id", "SYN-B-SEC-1"], 2, "invalid_configuration"),
    (["--evidence-id", "SYN-B-SYS-999"], 0, None),
])
def test_cli_outcomes(portable_corpus, capsys, extra, exit_code, error):
    assert main([*cli_args(portable_corpus), *extra]) == exit_code
    payload = json.loads(capsys.readouterr().out)
    assert payload["error_code"] == error
    if error:
        assert not payload["findings"]
    else:
        InvestigationResult.model_validate_json(json.dumps(payload))


def test_cli_missing_and_altered_corpus_sanitizes_errors(portable_corpus, tmp_path, capsys):
    assert main(cli_args(tmp_path / "private-detail")) == 2
    assert "private-detail" not in capsys.readouterr().out
    path = portable_corpus / "SYN-B.jsonl"
    path.write_bytes(path.read_bytes() + b"\n")
    assert main(cli_args(portable_corpus)) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "corpus_load_failed"


def test_cli_recovered_window_exits_complete_with_original_truncation_audit(tmp_path, capsys):
    info = load_scenario(build_scenario_dir(tmp_path / "datasets"))
    corpus = tmp_path / "corpus"
    records = [endpoint_event(i, second=i, scenario=info.scenario_id, Image="admin.exe") for i in range(1, 6)]
    write_manifest(corpus, [write_scenario(corpus, info, records)])
    assert main([*cli_args(corpus), "--max-events", "2"]) == 0
    result = InvestigationResult.model_validate_json(capsys.readouterr().out)
    assert len(result.findings) == 5
    assert result.metadata.window_coverage_complete and not result.metadata.truncated
    assert result.metadata.operations[0].truncated


def test_cli_local_profile_and_model_digest_are_recorded(portable_corpus, monkeypatch, capsys):
    from endpoint_agent import investigate_corpus
    seen = []
    def preflight(config):
        seen.append(config)
        return {"runtime": "ollama", "model": config.model, "digest": "test-digest", "configuration": config.model_dump()}
    monkeypatch.setattr(investigate_corpus, "local_model_runtime", preflight)
    monkeypatch.setattr(investigate_corpus, "OllamaClient", lambda config: FakeLLM())
    assert main([*cli_args(portable_corpus), "--mode", "ollama", "--model", "installed-test"]) == 0
    assert (seen[0].num_ctx, seen[0].think, seen[0].temperature, seen[0].seed) == (8192, False, 0, 0)
    assert json.loads(capsys.readouterr().out)["metadata"]["llm"]["digest"] == "test-digest"


@pytest.mark.parametrize("failure", [ValueError("private details"), httpx.ConnectError("private details")])
def test_preflight_failure_is_sanitized(portable_corpus, monkeypatch, capsys, failure):
    from endpoint_agent import investigate_corpus
    def fail(config): raise failure
    monkeypatch.setattr(investigate_corpus, "local_model_runtime", fail)
    assert main([*cli_args(portable_corpus), "--mode", "ollama"]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "local_model_preflight_failed"


def test_schema_and_module_entrypoint(portable_corpus, capsys):
    assert main(["--schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert "Finding" in schema["$defs"] and "ProcessFacts" in schema["$defs"]
    completed = subprocess.run([sys.executable, "-m", "endpoint_agent", *cli_args(portable_corpus)],
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    assert InvestigationResult.model_validate_json(completed.stdout).status == "completed"


@pytest.mark.ollama
def test_optional_local_ollama(portable_corpus, capsys):
    if os.getenv("MAIR_TEST_ENDPOINT_OLLAMA") != "1":
        pytest.skip("set MAIR_TEST_ENDPOINT_OLLAMA=1 with the shared model installed locally")
    # Cold model loading counts toward the deadline; retain the production
    # default separately and allow this explicit integration smoke test 180 s.
    code = main([*cli_args(portable_corpus), "--mode", "ollama", "--timeout", "180"])
    payload = capsys.readouterr().out
    assert code == 0, payload
    result = InvestigationResult.model_validate_json(payload)
    assert all(f.agent_type == "endpoint" for f in result.findings)
