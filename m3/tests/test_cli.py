import json
import subprocess
import sys

from m3.models import InvestigationResult

WINDOW = ["--scenario", "SYN-A", "--start", "2026-01-10T00:00:00Z", "--end", "2026-01-10T00:01:00Z"]


def test_fake_cli_from_documented_command():
    process = subprocess.run([sys.executable, "-m", "m3", "--mode", "fake", *WINDOW], capture_output=True, text=True, timeout=10)
    assert process.returncode == 0, process.stderr
    result = InvestigationResult.model_validate_json(process.stdout)
    assert result.status == "completed"
    assert result.findings[0].observed_events.failed_logons == 3


def test_invalid_cli_configuration_is_structured():
    process = subprocess.run([sys.executable, "-m", "m3", *WINDOW, "--max-events", "0"], capture_output=True, text=True, timeout=10)
    assert process.returncode == 2
    assert json.loads(process.stdout)["error_code"] == "invalid_configuration_or_fixture"


def test_schema_command_needs_no_window_or_model():
    process = subprocess.run([sys.executable, "-m", "m3", "--schema"], capture_output=True, text=True, timeout=10)
    assert process.returncode == 0
    assert json.loads(process.stdout) == InvestigationResult.model_json_schema()
