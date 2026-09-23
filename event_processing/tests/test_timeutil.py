"""T1.2 / AGENTS I2: integer-only 100 ns tick arithmetic that matches authentication_agent.models.utc_ticks."""

from __future__ import annotations

import pytest

from event_processing.timeutil import (
    FILETIME_EPOCH_TICKS,
    MAX_TICKS,
    MIN_TICKS,
    TICKS_PER_SECOND,
    filetime_to_ticks,
    iso_to_ticks,
    ticks_to_filetime,
    ticks_to_iso,
)
from authentication_agent.models import utc_ticks

# Values chosen to cover 7 fractional digits, a 6-digit source, both Z and +00:00, and the
# 214 us burst Evidence Verification & Evaluation measured inside one second of S01.
UTC_VALUES = (
    "2026-09-21T02:05:30.0430374Z",
    "2026-09-21T02:25:15.6704553Z",
    "2022-08-31T17:46:45.197821Z",
    "0001-01-01T00:00:00.0000000Z",
    "9999-12-31T23:59:59.9999999Z",
    "2026-09-21T02:04:38.943927+00:00",
    "2026-09-21T02:06:18.3Z",
)


@pytest.mark.parametrize("value", UTC_VALUES)
def test_matches_authentication_ticks_exactly(value: str):
    assert iso_to_ticks(value) == utc_ticks(value)


@pytest.mark.parametrize("value", UTC_VALUES)
def test_round_trip_through_iso(value: str):
    # +00:00 normalises to Z; everything else must render canonically to seven digits.
    rendered = ticks_to_iso(iso_to_ticks(value))
    assert rendered.endswith("Z")
    assert iso_to_ticks(rendered) == iso_to_ticks(value)
    assert rendered == ticks_to_iso(iso_to_ticks(rendered))


def test_renders_exactly_seven_fractional_digits():
    assert ticks_to_iso(iso_to_ticks("2022-08-31T17:46:45.197821Z")) == "2022-08-31T17:46:45.1978210Z"
    assert ticks_to_iso(iso_to_ticks("2026-09-21T02:05:30.0430374Z")) == "2026-09-21T02:05:30.0430374Z"
    assert ticks_to_iso(iso_to_ticks("0001-01-01T00:00:00Z")) == "0001-01-01T00:00:00.0000000Z"


def test_214_microsecond_gap_stays_distinct_and_ordered():
    base = iso_to_ticks("2022-08-31T17:47:04.0000000Z")
    later = base + 2140  # 2140 * 100 ns = 214 us
    assert later - base == 2140
    assert base < later
    assert ticks_to_iso(base) == "2022-08-31T17:47:04.0000000Z"
    assert ticks_to_iso(later) == "2022-08-31T17:47:04.0002140Z"


def test_one_tick_apart_stays_distinct():
    base = iso_to_ticks("2026-09-21T02:05:30.0430374Z")
    assert base + 1 != base
    assert ticks_to_iso(base + 1).endswith("0430375Z")


def test_millisecond_truncation_would_tie_the_burst_pair():
    # Documents the failure mode I2 exists to prevent: two distinct ticks inside one ms.
    first = iso_to_ticks("2022-08-31T17:47:04.0001000Z")
    second = iso_to_ticks("2022-08-31T17:47:04.0003140Z")
    assert first != second
    assert first // (TICKS_PER_SECOND // 1000) == second // (TICKS_PER_SECOND // 1000)


def test_filetime_epoch_offset():
    assert FILETIME_EPOCH_TICKS == 504912096000000000
    assert filetime_to_ticks(0) == FILETIME_EPOCH_TICKS
    assert ticks_to_iso(filetime_to_ticks(0)) == "1601-01-01T00:00:00.0000000Z"
    # Independent cross-check: the well-known FILETIME of the Unix epoch.
    assert filetime_to_ticks(116444736000000000) == iso_to_ticks("1970-01-01T00:00:00Z")


def test_filetime_round_trip_preserves_the_last_two_digits():
    ticks = iso_to_ticks("2026-09-21T02:05:30.0430374Z")
    filetime = ticks_to_filetime(ticks)
    assert filetime_to_ticks(filetime) == ticks
    # The float path python-evtx uses would render ...043036, i.e. 14 ticks less.
    assert ticks % 100 == 74


@pytest.mark.parametrize(
    "value",
    [
        "2026-09-21T02:05:30.0430374+02:00",
        "2026-09-21T02:05:30.0430374-00:00",
        "2026-09-21T02:05:30.04303740Z",
        "2026-09-21T02:05:30.0430374",
        "2026-09-21 02:05:30Z",
        "2026-13-21T02:05:30Z",
        "2026-09-32T02:05:30Z",
        "2026-09-21T24:00:00Z",
        "2026-09-21T02:60:00Z",
        "2026-09-21T02:05:60Z",
        "0000-01-01T00:00:00Z",
        "",
        "now",
    ],
)
def test_invalid_timestamps_are_rejected(value: str):
    with pytest.raises(ValueError):
        iso_to_ticks(value)


def test_non_string_timestamp_is_rejected():
    with pytest.raises(ValueError, match="must be a str"):
        iso_to_ticks(1234)  # type: ignore[arg-type]


@pytest.mark.parametrize("filetime", [-1, True, 1.5, "0"])
def test_invalid_filetime_is_rejected(filetime):
    with pytest.raises(ValueError, match="filetime"):
        filetime_to_ticks(filetime)


@pytest.mark.parametrize("ticks", [MIN_TICKS - 1, MAX_TICKS + 1, True, 1.5, "0"])
def test_out_of_range_ticks_are_rejected(ticks):
    with pytest.raises(ValueError, match="ticks"):
        ticks_to_iso(ticks)


def test_min_and_max_ticks_render_canonically():
    assert ticks_to_iso(MIN_TICKS) == "0001-01-01T00:00:00.0000000Z"
    assert ticks_to_iso(MAX_TICKS) == "9999-12-31T23:59:59.9999999Z"
    assert iso_to_ticks(ticks_to_iso(MIN_TICKS)) == MIN_TICKS
    assert iso_to_ticks(ticks_to_iso(MAX_TICKS)) == MAX_TICKS
