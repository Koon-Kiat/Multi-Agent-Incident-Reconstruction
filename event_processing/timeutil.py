"""100 ns tick arithmetic on Authentication Investigation Agent's epoch (AGENTS.md I2).

Contract
--------

``timestamp_ticks`` counts 100 ns units from the same origin as ``authentication_agent.models.utc_ticks``:
``date(year, month, day).toordinal() * 86400 + hh * 3600 + mm * 60 + ss`` seconds, times
10 000 000, plus the fractional 100 ns ticks. A Windows ``FILETIME`` counts the same units
from 1601-01-01, so :func:`filetime_to_ticks` only adds a constant offset.

Every conversion here is integer-only. Ticks are never passed through ``datetime``,
``float`` or ``time``: a ``datetime`` holds microseconds, so round-tripping ticks through it
would silently drop the last two decimal places (``...0430374`` becomes ``...043036`` in
python-evtx's own renderer). ``datetime.date`` is used only for day-level calendar
conversion, which is exact integer arithmetic and has no sub-day component to lose.

``ticks_to_iso`` always emits exactly seven fractional digits and ``Z``:
``YYYY-MM-DDTHH:MM:SS.fffffffZ``.
"""

from __future__ import annotations

import re
from datetime import date

TICKS_PER_SECOND = 10_000_000
SECONDS_PER_DAY = 86_400

# FILETIME's origin is 1601-01-01; Authentication Investigation Agent's is date.min (0001-01-01).
FILETIME_EPOCH_ORDINAL = date(1601, 1, 1).toordinal()
FILETIME_EPOCH_TICKS = FILETIME_EPOCH_ORDINAL * SECONDS_PER_DAY * TICKS_PER_SECOND

_MIN_ORDINAL = 1
_MAX_ORDINAL = date.max.toordinal()
MIN_TICKS = _MIN_ORDINAL * SECONDS_PER_DAY * TICKS_PER_SECOND
MAX_TICKS = (_MAX_ORDINAL + 1) * SECONDS_PER_DAY * TICKS_PER_SECOND - 1

# Same shape as authentication_agent.models.utc_ticks: 1..7 fractional digits, "Z" or "+00:00" only, so a
# local offset can never be read as UTC.
_UTC_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(Z|\+00:00)$")


def filetime_to_ticks(filetime: int) -> int:
    """Convert a raw Windows FILETIME (100 ns units since 1601-01-01) to shared-epoch ticks."""
    if isinstance(filetime, bool) or not isinstance(filetime, int):
        raise ValueError(f"filetime must be an int of 100 ns units, got {type(filetime).__name__}")
    if filetime < 0:
        raise ValueError(f"filetime {filetime!r} must not be negative")
    return filetime + FILETIME_EPOCH_TICKS


def iso_to_ticks(value: str) -> int:
    """Parse a UTC ISO 8601 timestamp with up to seven fractional digits into ticks.

    Rejects non-UTC offsets (only ``Z`` and ``+00:00`` are UTC), more than seven fractional
    digits, and impossible dates or clock times. Equivalent to ``authentication_agent.models.utc_ticks``.
    """
    if not isinstance(value, str):
        raise ValueError(f"timestamp must be a str, got {type(value).__name__}")
    match = _UTC_RE.fullmatch(value)
    if match is None:
        raise ValueError(
            f"timestamp {value!r} must be UTC ISO 8601 (YYYY-MM-DDTHH:MM:SS[.f{{1,7}}]Z) "
            "with at most seven fractional digits"
        )
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    if hour > 23 or minute > 59 or second > 59:
        raise ValueError(f"timestamp {value!r} has an invalid time of day")
    seconds = date(year, month, day).toordinal() * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second
    return seconds * TICKS_PER_SECOND + int((match.group(7) or "").ljust(7, "0"))


def ticks_to_iso(ticks: int) -> str:
    """Render ticks as ``YYYY-MM-DDTHH:MM:SS.fffffffZ`` with exactly seven fractional digits."""
    if isinstance(ticks, bool) or not isinstance(ticks, int):
        raise ValueError(f"ticks must be an int of 100 ns units, got {type(ticks).__name__}")
    if ticks < MIN_TICKS or ticks > MAX_TICKS:
        raise ValueError(f"ticks {ticks!r} is outside the representable range 0001-01-01..9999-12-31")
    seconds, fraction = divmod(ticks, TICKS_PER_SECOND)
    ordinal, remainder = divmod(seconds, SECONDS_PER_DAY)
    day = date.fromordinal(ordinal)
    hour, remainder = divmod(remainder, 3600)
    minute, second = divmod(remainder, 60)
    return f"{day.isoformat()}T{hour:02d}:{minute:02d}:{second:02d}.{fraction:07d}Z"


def ticks_to_filetime(ticks: int) -> int:
    """Inverse of :func:`filetime_to_ticks`, for cross-checking against a source record."""
    if isinstance(ticks, bool) or not isinstance(ticks, int):
        raise ValueError(f"ticks must be an int of 100 ns units, got {type(ticks).__name__}")
    return ticks - FILETIME_EPOCH_TICKS
