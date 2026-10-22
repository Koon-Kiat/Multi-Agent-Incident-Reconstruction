"""Exercise stage parsing and overwrite guards without invoking a model server."""

from pathlib import Path
import shutil
import subprocess

import pytest

SHELL = shutil.which("pwsh") or shutil.which("powershell")
pytestmark = pytest.mark.skipif(SHELL is None, reason="PowerShell is not installed")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-evaluation.ps1"


def test_evaluation_script_parses():
    command = (
        "$tokens=$null; $errors=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{SCRIPT.as_posix()}',[ref]$tokens,[ref]$errors) | Out-Null; "
        "if ($errors.Count) { $errors | Out-String | Write-Output; exit 1 }"
    )
    result = subprocess.run([SHELL, "-NoProfile", "-Command", command], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("stage,mode", [
    ("generalist", "single-agent"), ("specialist", "multi-agent"), ("verified-specialist", "full"),
    ("B", "single-agent"), ("C", "multi-agent"), ("D", "full"),
    ("b,generalist", "single-agent"), ("prep,B,C,D", "single-agent"),
])
def test_descriptive_and_legacy_stages_reach_the_same_overwrite_guard(tmp_path, stage, mode):
    target = tmp_path / "runs" / mode
    target.mkdir(parents=True)
    result = subprocess.run(
        [SHELL, "-NoProfile", "-File", str(SCRIPT), "-Out", str(tmp_path), "-Only", stage, "-AllowDirty"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "refusing to overwrite" in result.stderr
    assert mode in result.stderr
    assert not (tmp_path / "logs").exists()


def test_unknown_stage_fails_before_creating_output(tmp_path):
    result = subprocess.run(
        [SHELL, "-NoProfile", "-File", str(SCRIPT), "-Out", str(tmp_path), "-Only", "unknown"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "unknown stage(s)" in result.stderr
    assert not (tmp_path / "logs").exists()
