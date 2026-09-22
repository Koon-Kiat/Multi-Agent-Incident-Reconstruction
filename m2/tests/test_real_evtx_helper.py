"""The EVTX-availability helper is what keeps the suite green in CI (lfs: false)."""

from __future__ import annotations

from pathlib import Path

import pytest

from m2.tests.conftest import (
    M2_DATASETS_DIR_ENV_VAR,
    REPO_ROOT,
    datasets_dir,
    is_lfs_pointer,
    real_datasets,
    real_evtx,
)

LFS_POINTER = b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 1118208\n"


def test_lfs_pointer_is_detected(tmp_path: Path):
    pointer = tmp_path / "Security.evtx"
    pointer.write_bytes(LFS_POINTER)
    assert is_lfs_pointer(pointer) is True


def test_real_binary_is_not_an_lfs_pointer(tmp_path: Path):
    binary = tmp_path / "Security.evtx"
    binary.write_bytes(b"ElfFile\x00" + b"\x00" * 4096)
    assert is_lfs_pointer(binary) is False


def test_missing_file_is_not_reported_as_a_pointer(tmp_path: Path):
    assert is_lfs_pointer(tmp_path / "absent.evtx") is False


def test_real_evtx_skips_when_the_scenario_is_absent():
    with pytest.raises(pytest.skip.Exception) as skip_info:
        real_evtx("S99", "Security")
    assert "absent" in str(skip_info.value)


def test_real_evtx_skips_on_an_lfs_pointer(tmp_path: Path, monkeypatch):
    scenario_dir = tmp_path / "S99" / "raw"
    scenario_dir.mkdir(parents=True)
    (scenario_dir / "Security.evtx").write_bytes(LFS_POINTER)
    monkeypatch.delenv(M2_DATASETS_DIR_ENV_VAR, raising=False)
    monkeypatch.setattr("m2.tests.conftest.DATASETS_DIR", tmp_path)
    with pytest.raises(pytest.skip.Exception) as skip_info:
        real_evtx("S99", "Security")
    assert "LFS pointer" in str(skip_info.value)


def test_datasets_dir_defaults_to_the_repo_datasets(monkeypatch):
    monkeypatch.delenv(M2_DATASETS_DIR_ENV_VAR, raising=False)
    assert datasets_dir() == REPO_ROOT / "datasets"


def test_the_datasets_dir_env_var_overrides_the_default(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(M2_DATASETS_DIR_ENV_VAR, str(tmp_path))
    assert datasets_dir() == tmp_path


def test_the_env_var_simulates_ci_by_making_every_real_helper_skip(tmp_path: Path, monkeypatch):
    # An empty override directory is the local stand-in for `actions/checkout` with `lfs: false`:
    # no export exists, so each real-data test skips with a reason instead of failing.
    monkeypatch.setenv(M2_DATASETS_DIR_ENV_VAR, str(tmp_path))
    with pytest.raises(pytest.skip.Exception) as skip_info:
        real_evtx("S02", "Security")
    assert "absent" in str(skip_info.value)
    with pytest.raises(pytest.skip.Exception) as datasets_skip:
        real_datasets()
    assert "absent" in str(datasets_skip.value)


def test_real_evtx_rejects_an_unknown_channel():
    with pytest.raises(ValueError, match="unknown channel"):
        real_evtx("S02", "Application")


def test_real_evtx_returns_the_path_when_evidence_is_present(real_evtx_path):
    path = real_evtx_path("S02", "Security")
    assert path.is_file()
    assert path.name == "Security.evtx"
    assert not is_lfs_pointer(path)
