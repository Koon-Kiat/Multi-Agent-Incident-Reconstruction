"""Raw record -> :class:`m2.schema.NormalisedEvent` mapping.

Mapping table
-------------

============================ ==================================================================================
``evidence_id``              ``make_evidence_id(scenario_id, channel, record_id)`` (AGENTS.md I1)
``scenario_id``              the scenario the file belongs to, taken from the manifest, never from a path at query time
``channel``                  ``System/Channel`` of the record
``source_type``              from ``channel``: ``Security`` -> ``windows_security``, Sysmon -> ``sysmon``
``record_id``                ``System/EventRecordID``, unmodified
``source_event_id``          ``System/EventID``
``timestamp_ticks``          ``filetime_to_ticks(TimeCreated/@SystemTime FILETIME)``; integer 100 ns units (I2)
``timestamp_utc``            ``ticks_to_iso(...)``: ``YYYY-MM-DDTHH:MM:SS.fffffffZ`` (I2)
``host``                     ``System/Computer``, ``None`` (plus a warning) when absent
``user``                     see below; never case-folded, never domain-stripped
``event_data``               every ``EventData/Data`` name/value pair, values verbatim strings
``raw_reference``            ``evtx://datasets/<scenario>/raw/<file>#EventRecordID=<record_id>``
``source_sha256``            manifest digest of the file, passed in by the caller
``raw_xml``                  the original record XML, unmodified
``in_scenario_window``       ``window_start_ticks <= ticks <= window_end_ticks`` — **inclusive at both ends**
``parse_warnings``           one entry per missing or odd field; a record is never dropped for one
============================ ==================================================================================

``user`` is chosen by channel and event ID:

* Domain ``Security`` event 4624, 4625, 4634, 4647 or 4648 -> ``EventData/TargetUserName``
* any other ``Security`` event -> ``EventData/SubjectUserName``
* Sysmon -> ``EventData/User``
* field absent -> ``None`` and a ``parse_warnings`` entry

A present but empty field stays ``""``: "no value" and "absent" are different facts, and the
query API distinguishes them too. ``in_scenario_window`` is inclusive at both ends because a
scenario window is a declared capture interval, unlike a query window, which is
``[start, end)``.
"""

from __future__ import annotations

from m2.evtx_reader import RawRecord
from m2.ids import make_evidence_id
from m2.schema import CHANNEL_SOURCE_TYPES, NormalisedEvent
from m2.timeutil import filetime_to_ticks, ticks_to_iso

LOGON_EVENT_IDS = frozenset({4624, 4625, 4634, 4647, 4648})
SYSMON_USER_FIELD = "User"
SECURITY_FALLBACK_USER_FIELD = "SubjectUserName"


def make_raw_reference(scenario_id: str, source_filename: str, record_id: int) -> str:
    """The logical reference M6 can re-derive an event from, independent of the local mount point."""
    return f"evtx://datasets/{scenario_id}/raw/{source_filename}#EventRecordID={record_id}"


def user_field_for(channel: str, event_id: int) -> str:
    """Name of the EventData field that carries ``user`` for this channel and event ID."""
    if channel == "Security":
        return "TargetUserName" if event_id in LOGON_EVENT_IDS else SECURITY_FALLBACK_USER_FIELD
    if channel == "Microsoft-Windows-Sysmon/Operational":
        return SYSMON_USER_FIELD
    raise ValueError(f"unsupported channel {channel!r}")


def normalise_record(
    raw: RawRecord,
    *,
    scenario_id: str,
    source_filename: str,
    source_sha256: str,
    window_start_ticks: int,
    window_end_ticks: int,
) -> NormalisedEvent:
    """Map one :class:`RawRecord` onto a :class:`NormalisedEvent`."""
    try:
        source_type = CHANNEL_SOURCE_TYPES[raw.channel]
    except KeyError:
        raise ValueError(f"unsupported channel {raw.channel!r} in record {raw.record_id}") from None

    warnings: list[str] = []
    ticks = filetime_to_ticks(raw.filetime)
    host = raw.computer
    if host is None:
        warnings.append("System/Computer is absent; host set to None")
    user = _user_of(raw, warnings)
    return NormalisedEvent(
        evidence_id=make_evidence_id(scenario_id, raw.channel, raw.record_id),
        scenario_id=scenario_id,
        channel=raw.channel,  # type: ignore[arg-type]
        source_type=source_type,  # type: ignore[arg-type]
        record_id=raw.record_id,
        source_event_id=raw.event_id,
        timestamp_utc=ticks_to_iso(ticks),
        timestamp_ticks=ticks,
        host=host,
        user=user,
        event_data=raw.event_data,
        raw_reference=make_raw_reference(scenario_id, source_filename, raw.record_id),
        source_sha256=source_sha256,
        raw_xml=raw.raw_xml,
        in_scenario_window=window_start_ticks <= ticks <= window_end_ticks,
        parse_warnings=tuple(warnings),
    )


def _user_of(raw: RawRecord, warnings: list[str]) -> str | None:
    field = user_field_for(raw.channel, raw.event_id)
    value = raw.event_data.get(field)
    if value is None:
        warnings.append(f"EventData field {field!r} is absent; user set to None")
        return None
    return value
