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

from event_processing.evtx_reader import (
    EVENT_NAMESPACE,
    EvtxStructureError,
    RawRecord,
    _raw_record,
    iter_records,
    verify_chunk,
)
from event_processing.tests.conftest import real_evtx
from event_processing.timeutil import filetime_to_ticks, ticks_to_iso

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


class _StubRecord:
    """Only what ``_raw_record`` reads from a python-evtx ``Record``."""

    def __init__(self, xml: str) -> None:
        self._xml = xml

    def xml(self) -> str:
        return self._xml


def system_xml(*, computer: str | None) -> str:
    element = "" if computer is None else f"<Computer>{computer}</Computer>"
    return (
        f'<Event xmlns="{EVENT_NAMESPACE}"><System>'
        "<EventRecordID>7</EventRecordID><EventID>4688</EventID>"
        f"<Channel>{SECURITY}</Channel>{element}</System></Event>"
    )


@pytest.mark.parametrize(("computer", "expected"), [(None, None), ("", ""), ("MAIR-WIN11-LAB", "MAIR-WIN11-LAB")])
def test_computer_is_passed_through_verbatim(computer: str | None, expected: str | None, monkeypatch):
    """An absent element is None; a present-but-empty element stays "", not None."""
    monkeypatch.setattr("event_processing.evtx_reader.read_filetime", lambda record: 0)
    assert _raw_record(_StubRecord(system_xml(computer=computer))).computer == expected


# --- chunk-trust decisions (no EVTX needed) ---------------------------------------


def check_chunk(**overrides):
    """Call the decision function with a healthy continuation, then the overrides."""
    arguments = {
        "index": 1,
        "header_chunk_count": 1,
        "magic_valid": True,
        "checksum_valid": True,
        "record_ids": [5, 6, 7],
        "previous_record_id": 4,
    }
    arguments.update(overrides)
    verify_chunk(**arguments)


def test_verify_chunk_accepts_a_continuing_chunk():
    check_chunk()


def test_verify_chunk_accepts_a_gap_but_not_a_step_backwards():
    check_chunk(record_ids=[8, 9], previous_record_id=4)
    with pytest.raises(EvtxStructureError, match="does not continue record 7"):
        check_chunk(record_ids=[5, 6, 7], previous_record_id=7)


def test_verify_chunk_ignores_an_empty_slot():
    check_chunk(record_ids=[], magic_valid=False, checksum_valid=False, previous_record_id=None)


def test_verify_chunk_rejects_a_record_bearing_chunk_with_invalid_magic():
    with pytest.raises(EvtxStructureError, match="magic"):
        check_chunk(magic_valid=False)


def test_verify_chunk_rejects_a_record_bearing_chunk_with_a_failing_checksum():
    with pytest.raises(EvtxStructureError, match="checksum"):
        check_chunk(checksum_valid=False)


def test_verify_chunk_rejects_record_numbers_that_do_not_increase():
    with pytest.raises(EvtxStructureError, match="repeats or reorders"):
        check_chunk(record_ids=[5, 5, 7])


def test_verify_chunk_does_not_judge_the_sequence_inside_the_declared_count():
    """The file header vouches for those chunks; only chunks read on trust need continuing."""
    check_chunk(index=0, header_chunk_count=3, record_ids=[9, 10], previous_record_id=100)

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


def test_s01_sysmon_covers_the_burst_the_verification_note_describes(s01_records: dict[str, list[RawRecord]]):
    """Sub-millisecond ordering only exists if these records are not truncated away."""
    ticks = sorted(filetime_to_ticks(record.filetime) for record in s01_records[SYSMON])
    assert len(ticks) == len(set(ticks))
    in_second = [tick for tick in ticks if ticks_to_iso(tick).startswith("2022-08-31T17:47:04")]
    assert len(in_second) > 5
    assert min(b - a for a, b in zip(in_second, in_second[1:])) < 1000  # under 100 us apart
