"""Shared M2 test helpers.

``real_evtx(scenario, channel)`` returns the path to an original EVTX export and skips the
test when the file is absent or is a Git LFS pointer. CI checks out the datasets with
``lfs: false``, so the original evidence is never present there and those tests must skip
rather than fail. Skips are explicit and name the reason; nothing is marked ``xfail``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS_DIR = REPO_ROOT / "datasets"

# A Git LFS pointer is a tiny text file; real EVTX exports start with the "ElfFile" magic.
LFS_POINTER_PREFIX = b"version https://git-lfs"
LFS_POINTER_MAX_BYTES = 1024

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


def is_lfs_pointer(path: Path) -> bool:
    """True when ``path`` holds an unfetched Git LFS pointer instead of real content."""
    try:
        if path.stat().st_size > LFS_POINTER_MAX_BYTES:
            return False
        with path.open("rb") as handle:
            return handle.read(len(LFS_POINTER_PREFIX)) == LFS_POINTER_PREFIX
    except OSError:
        return False


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
