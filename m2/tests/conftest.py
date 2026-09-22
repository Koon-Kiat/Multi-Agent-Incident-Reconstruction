"""Shared M2 test helpers.

``real_evtx(scenario, channel)`` returns the path to an original EVTX export and skips the
test when the file is absent or is a Git LFS pointer. CI checks out the datasets with
``lfs: false``, so the original evidence is never present there and those tests must skip
rather than fail. Skips are explicit and name the reason; nothing is marked ``xfail``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from m2.manifest import is_lfs_pointer

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS_DIR = REPO_ROOT / "datasets"

CHANNEL_FILENAMES = {
    "Security": "Security.evtx",
    "Microsoft-Windows-Sysmon/Operational": "Sysmon.evtx",
}


def _display(path: Path) -> str:
    """Repo-relative path for messages; absolute when the path lives outside the repo."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def real_evtx(scenario: str, channel: str) -> Path:
    """Return ``datasets/<scenario>/raw/<channel>.evtx``, skipping when it is not usable.

    ``channel`` is the Windows channel name (``Security`` or
    ``Microsoft-Windows-Sysmon/Operational``), not a filename.
    """
    try:
        filename = CHANNEL_FILENAMES[channel]
    except KeyError:
        raise ValueError(f"unknown channel {channel!r}; expected one of {sorted(CHANNEL_FILENAMES)}") from None
    path = DATASETS_DIR / scenario / "raw" / filename
    if not path.is_file():
        pytest.skip(f"original evidence {_display(path)} is absent (Git LFS content not fetched)")
    if is_lfs_pointer(path):
        pytest.skip(f"original evidence {_display(path)} is a Git LFS pointer (Git LFS content not fetched)")
    return path


@pytest.fixture(name="real_evtx_path")
def real_evtx_path_fixture():
    """Fixture form of :func:`real_evtx`, for tests that take fixtures."""
    return real_evtx


SCENARIOS = ("S01", "S02", "S03")


def real_datasets() -> Path:
    """Return the ``datasets/`` root, skipping when any of the six exports is unusable."""
    for scenario in SCENARIOS:
        for channel in CHANNEL_FILENAMES:
            real_evtx(scenario, channel)
    return DATASETS_DIR
