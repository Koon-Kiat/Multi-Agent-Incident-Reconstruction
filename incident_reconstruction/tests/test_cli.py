"""End to end through the command line, over a verified on-disk corpus built like ``normalise``'s."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from event_processing.corpus import write_manifest, write_scenario
from event_processing.manifest import load_scenario
from event_processing.tests.synthetic import SECURITY, SYSMON, build_scenario_dir, make_event
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks
from incident_reconstruction.__main__ import main
from incident_reconstruction.claims import Reconstruction
from incident_reconstruction.pipeline import PipelineSummary
from incident_reconstruction.verification import VerificationReport

SCENARIO = "SYN-B"  # The synthetic "lab" dataset shape's scenario.
BASE = iso_to_ticks("2026-09-21T02:05:30.0000000Z")
GUID = "{00000002-aaaa-bbbb-cccc-000000000002}"
USER_DATA = {"TargetUserName": "analyst", "TargetDomainName": "LAB", "LogonType": "3", "IpAddress": "10.0.0.5"}


def at(second):
    return BASE + second * TICKS_PER_SECOND


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """Failed logons then a success, a discovery command and a script dropped in a temp folder."""
    events = [make_event(record_id=r, event_id=4625, timestamp_ticks=at(r), event_data=USER_DATA) for r in (1, 2, 3)]
    events.append(make_event(record_id=4, event_id=4624, timestamp_ticks=at(4), event_data=USER_DATA))
    events.append(make_event(channel=SYSMON, record_id=10, event_id=1, timestamp_ticks=at(20), user="LAB\\analyst",
                             event_data={"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /all",
                                         "ProcessGuid": GUID, "ProcessId": "300", "User": "LAB\\analyst",
                                         "ParentImage": "C:\\Windows\\System32\\cmd.exe"}))
    events.append(make_event(channel=SYSMON, record_id=11, event_id=11, timestamp_ticks=at(25), user="LAB\\analyst",
                             event_data={"Image": "C:\\Windows\\System32\\cmd.exe", "ProcessGuid": GUID,
                                         "TargetFilename": "C:\\Users\\analyst\\AppData\\Local\\Temp\\run.ps1",
                                         "User": "LAB\\analyst"}))
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    out = tmp_path / "corpus"
    write_manifest(out, [write_scenario(out, info, events)])
    return out


def run_cli(corpus, out, *args):
    return main(["--corpus", str(corpus), "--llm", "fake", "--out", str(out), *args])


def test_all_modes_run_end_to_end_and_write_reports(corpus, tmp_path, capsys):
    out = tmp_path / "runs"
    for mode in ("single-agent", "multi-agent", "full"):
        assert run_cli(corpus, out, "--mode", mode) == 0, capsys.readouterr().err
    expected = {
        "single-agent": {"pipeline", "reconstruction", "report"},
        "multi-agent": {"pipeline", "reconstruction", "orchestration", "report"},
        "full": {"pipeline", "reconstruction", "orchestration", "verification", "report"},
    }
    for mode, kinds in expected.items():
        names = {p.name for p in (out / mode).iterdir()}
        assert names == {f"{SCENARIO}.{k}.{'html' if k == 'report' else 'json'}" for k in kinds}
        summary = PipelineSummary.model_validate_json((out / mode / f"{SCENARIO}.pipeline.json").read_text(encoding="utf-8"))
        reconstruction = Reconstruction.model_validate_json(
            (out / mode / f"{SCENARIO}.reconstruction.json").read_text(encoding="utf-8"))
        assert summary.detections >= 3 and summary.claims == len(reconstruction.claims) > 0
    index = (out / "index.html").read_text(encoding="utf-8")
    assert all(f"{mode}/{SCENARIO}.report.html" in index for mode in expected)
    stdout = capsys.readouterr().out
    from incident_reconstruction.terminology import MODE_LABELS
    assert f"{SCENARIO} [{MODE_LABELS['full']}]:" in stdout and "verdicts {'unverified':" in stdout


def test_detections_reach_every_expected_stage(corpus, tmp_path):
    out = tmp_path / "runs"
    assert run_cli(corpus, out, "--mode", "multi-agent") == 0
    claims = Reconstruction.model_validate_json(
        (out / "multi-agent" / f"{SCENARIO}.reconstruction.json").read_text(encoding="utf-8")).claims
    assert [c.claim_type for c in claims] == ["failed_logons_then_success", "discovery_commands", "payload_written"]
    # The discovery command and the dropped script are the same process.
    assert any(link.claim_id == claims[2].claim_id and "same process" in link.reason for link in claims[1].related_claims)


def test_fake_runs_are_reproducible(corpus, tmp_path):
    documents = []
    for name in ("first", "second"):
        assert run_cli(corpus, tmp_path / name, "--mode", "multi-agent") == 0
        data = json.loads((tmp_path / name / "multi-agent" / f"{SCENARIO}.reconstruction.json").read_text(encoding="utf-8"))
        data.pop("latency_seconds"), data.pop("orchestration_started_utc")
        documents.append(data)
    assert documents[0] == documents[1]


def test_plan_only_prints_the_windows(corpus, capsys):
    assert main(["--corpus", str(corpus), "--llm", "fake", "--plan-only"]) == 0
    plans = json.loads(capsys.readouterr().out)
    assert {p["agent_type"] for p in plans} == {"authentication", "endpoint"}
    assert all(p["scenario_id"] == SCENARIO for p in plans)


def test_reconstruct_only_reuses_the_saved_investigation(corpus, tmp_path, capsys):
    out = tmp_path / "runs"
    assert run_cli(corpus, out, "--mode", "full") == 0
    orchestration = (out / "full" / f"{SCENARIO}.orchestration.json").read_bytes()
    capsys.readouterr()
    assert run_cli(corpus, out, "--mode", "full", "--reconstruct-only") == 0
    assert (out / "full" / f"{SCENARIO}.orchestration.json").read_bytes() == orchestration
    assert "claims re-narrated" in capsys.readouterr().out
    assert VerificationReport.model_validate_json((out / "full" / f"{SCENARIO}.verification.json").read_text(encoding="utf-8"))


def test_a_verifier_plugs_in_by_import_path(corpus, tmp_path):
    out = tmp_path / "runs"
    assert run_cli(corpus, out, "--mode", "full",
                   "--verifier", "incident_reconstruction.tests.test_run_modes:make_verifier") == 0
    report = VerificationReport.model_validate_json((out / "full" / f"{SCENARIO}.verification.json").read_text(encoding="utf-8"))
    assert {d.verdict for d in report.decisions} == {"confirmed"} and report.verifier == {"verifier": "fixed"}


@pytest.mark.parametrize("extra, code, message", [
    (["--mode", "full", "--verifier", "no.such.module:factory"], 3, "setup failed"),
    (["--mode", "multi-agent", "--verifier", "x:y"], 2, "full mode only"),
    (["--mode", "single-agent", "--reconstruct-only"], 2, "multi-agent and full"),
    (["--scenario", "S99"], 2, "unknown scenarios"),
])
def test_invalid_requests_fail_cleanly(corpus, tmp_path, capsys, extra, code, message):
    assert run_cli(corpus, tmp_path / "runs", *extra) == code
    assert message in capsys.readouterr().err


def test_protected_and_missing_paths_are_refused(corpus, tmp_path, capsys):
    assert run_cli(corpus, tmp_path / "datasets" / "runs") == 2
    assert "protected evidence tree" in capsys.readouterr().err
    assert run_cli(tmp_path / "missing", tmp_path / "runs") == 2
    assert "cannot load corpus" in capsys.readouterr().err
    assert main(["--corpus", str(corpus), "--llm", "fake"]) == 2
    assert "--out is required" in capsys.readouterr().err


def test_reconstruct_only_without_a_saved_run_is_invalid_input(corpus, tmp_path, capsys):
    assert run_cli(corpus, tmp_path / "runs", "--mode", "multi-agent", "--reconstruct-only") == 2
    assert "cannot read" in capsys.readouterr().err


def test_ollama_preflight_failure_sends_no_evidence(corpus, tmp_path, capsys):
    # Either no local runtime is listening or this model is not installed; both stop before dispatch.
    code = main(["--corpus", str(corpus), "--llm", "ollama", "--model", "mair-test-not-installed:0b",
                 "--out", str(tmp_path / "runs")])
    assert code == 3 and "setup failed" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_module_and_report_entry_points_start(tmp_path):
    for module in ("incident_reconstruction", "incident_reconstruction.report"):
        completed = subprocess.run([sys.executable, "-m", module, "--help"], capture_output=True, text=True, timeout=60)
        assert completed.returncode == 0 and "--corpus" in completed.stdout
