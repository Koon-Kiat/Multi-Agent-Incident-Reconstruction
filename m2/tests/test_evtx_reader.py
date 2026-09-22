"""T1.5 reader acceptance on S01 (skipped in CI).

``FileHeader.chunk_count`` is not trustworthy for the exported S01 files, and python-evtx
trusts it. These tests pin the resulting record totals against Windows' own parser::

    Get-WinEvent -Path datasets/S01/raw/Security.evtx -Oldest | Measure-Object   # 1807
    Get-WinEvent -Path datasets/S01/raw/Sysmon.evtx   -Oldest | Measure-Object   # 893

Without reading the chunks the header calls inactive, the reader sees 93 and 54 records and
every S01 event after 17:46:43.7 is missing from the corpus. S02/S03 counts are pinned by
``test_real_corpus.py`` (349/1581 and 352/1679) and by the anchors in ``test_normalise.py``.
"""

from __future__ import annotations

import pytest

from m2.evtx_reader import RawRecord, iter_records
from m2.tests.conftest import real_evtx
from m2.timeutil import filetime_to_ticks, ticks_to_iso

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"

EXPECTED = {
    SECURITY: (1807, 31212963, 31214769),
    SYSMON: (893, 35811493, 35812385),
}


@pytest.fixture(scope="module")
def s01_records() -> dict[str, list[RawRecord]]:
    """Each S01 file is parsed once for the whole module; a full S01 pass is not cheap."""
    return {channel: list(iter_records(real_evtx("S01", channel))) for channel in EXPECTED}


@pytest.mark.parametrize("channel", sorted(EXPECTED))
def test_every_s01_record_is_read(channel: str, s01_records: dict[str, list[RawRecord]]):
    count, first, last = EXPECTED[channel]
    record_ids = [record.record_id for record in s01_records[channel]]
    assert len(record_ids) == count
    # Consecutive record numbers prove the extra chunks belong to the same capture, not to
    # a stale or rotated log.
    assert record_ids == sorted(record_ids)
    assert (min(record_ids), max(record_ids)) == (first, last)
    assert max(record_ids) - min(record_ids) + 1 == count


def test_s01_sysmon_covers_the_burst_the_m6_note_describes(s01_records: dict[str, list[RawRecord]]):
    """Sub-millisecond ordering only exists if these records are not truncated away."""
    ticks = sorted(filetime_to_ticks(record.filetime) for record in s01_records[SYSMON])
    assert len(ticks) == len(set(ticks))
    in_second = [tick for tick in ticks if ticks_to_iso(tick).startswith("2022-08-31T17:47:04")]
    assert len(in_second) > 5
    assert min(b - a for a, b in zip(in_second, in_second[1:])) < 1000  # under 100 us apart
