"""T1.5: the raw-record -> normalised-event mapping, and the 6 public anchors end to end."""

from __future__ import annotations

from pathlib import Path

import pytest

from event_processing.evtx_reader import RawRecord, iter_records
from event_processing.normalise import LOGON_EVENT_IDS, make_raw_reference, normalise_record, user_field_for
from event_processing.timeutil import iso_to_ticks, ticks_to_filetime
from event_processing.tests.conftest import real_evtx

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SHA = "A" * 64

WINDOW_START = "2026-09-21T02:04:38.9439270Z"
WINDOW_END = "2026-09-21T02:06:18.3126076Z"
WINDOW_START_TICKS = iso_to_ticks(WINDOW_START)
WINDOW_END_TICKS = iso_to_ticks(WINDOW_END)


def filetime_of(utc: str) -> int:
    return ticks_to_filetime(iso_to_ticks(utc))


def raw_record(**overrides) -> RawRecord:
    fields: dict = {
        "record_id": 43584,
        "event_id": 4624,
        "channel": SECURITY,
        "computer": "MAIR-WIN11-LAB",
        "filetime": filetime_of("2026-09-21T02:05:30.0430374Z"),
        "event_data": {"TargetUserName": "MAIR\\analyst", "LogonType": "10"},
        "raw_xml": "<Event><System><EventID>4624</EventID></System></Event>",
    }
    fields.update(overrides)
    return RawRecord(**fields)


def normalise(raw: RawRecord, scenario_id: str = "S02", filename: str = "Security.evtx"):
    return normalise_record(
        raw,
        scenario_id=scenario_id,
        source_filename=filename,
        source_sha256=SHA,
        window_start_ticks=WINDOW_START_TICKS,
        window_end_ticks=WINDOW_END_TICKS,
    )


def test_security_logon_uses_target_user_name():
    event = normalise(raw_record())
    assert event.user == "MAIR\\analyst"
    assert event.host == "MAIR-WIN11-LAB"
    assert event.source_type == "windows_security"
    assert event.timestamp_utc == "2026-09-21T02:05:30.0430374Z"
    assert event.parse_warnings == ()


def test_security_process_creation_uses_subject_user_name():
    event = normalise(
        raw_record(
            record_id=43628,
            event_id=4688,
            event_data={"SubjectUserName": "MAIR$", "NewProcessName": "C:\\Windows\\System32\\whoami.exe"},
        )
    )
    assert event.user == "MAIR$"
    assert event.event_data["NewProcessName"].endswith("whoami.exe")


@pytest.mark.parametrize("event_id", sorted(LOGON_EVENT_IDS))
def test_every_logon_event_reads_target_user_name(event_id: int):
    event = normalise(raw_record(event_id=event_id, event_data={"TargetUserName": "analyst", "SubjectUserName": "OTHER"}))
    assert event.user == "analyst"


@pytest.mark.parametrize("event_id", sorted(LOGON_EVENT_IDS))
def test_logon_events_require_target_user_name(event_id: int):
    event = normalise(raw_record(event_id=event_id, event_data={"SubjectUserName": "analyst"}))
    assert event.user is None
    assert event.parse_warnings == ("EventData field 'TargetUserName' is absent; user set to None",)


def test_sysmon_process_creation_uses_user():
    event = normalise(
        raw_record(
            record_id=25891,
            event_id=1,
            channel=SYSMON,
            event_data={"User": "MAIR\\analyst", "Image": "C:\\Windows\\System32\\cmd.exe"},
        ),
        filename="Sysmon.evtx",
    )
    assert event.user == "MAIR\\analyst"
    assert event.source_type == "sysmon"
    assert event.channel == SYSMON
    assert event.evidence_id == "S02-SYS-25891"
    assert event.raw_reference == "evtx://datasets/S02/raw/Sysmon.evtx#EventRecordID=25891"


def test_sysmon_file_create_uses_user():
    event = normalise(
        raw_record(record_id=25900, event_id=11, channel=SYSMON, event_data={"User": "MAIR\\analyst", "TargetFilename": "x"}),
        filename="Sysmon.evtx",
    )
    assert event.user == "MAIR\\analyst"


def test_missing_user_field_gives_none_and_a_warning():
    event = normalise(raw_record(event_data={}))
    assert event.user is None
    assert event.parse_warnings == ("EventData field 'TargetUserName' is absent; user set to None",)


def test_missing_sysmon_user_field_gives_none_and_a_warning():
    event = normalise(raw_record(event_id=3, channel=SYSMON, event_data={}), filename="Sysmon.evtx")
    assert event.user is None
    assert event.parse_warnings == ("EventData field 'User' is absent; user set to None",)


def test_empty_user_field_is_kept_as_an_empty_string_without_a_warning():
    event = normalise(raw_record(event_data={"SubjectUserName": ""}, event_id=4688, record_id=1))
    assert event.user == ""
    assert event.parse_warnings == ()


def test_unknown_security_event_id_is_still_normalised():
    event = normalise(raw_record(event_id=9999, record_id=7, event_data={"SubjectUserName": "analyst"}))
    assert event.source_event_id == 9999
    assert event.user == "analyst"
    assert event.evidence_id == "S02-SEC-7"


def test_missing_computer_gives_none_and_a_warning():
    event = normalise(raw_record(computer=None))
    assert event.host is None
    assert event.parse_warnings == ("System/Computer is absent; host set to None",)


def test_empty_computer_field_is_kept_as_an_empty_string_without_a_warning():
    event = normalise(raw_record(computer=""))
    assert event.host == ""
    assert event.parse_warnings == ()


def test_values_are_kept_verbatim_without_case_folding_or_domain_stripping():
    event = normalise(raw_record(event_data={"SubjectUserName": "MAIR\\Administrator", "Extra": "MiXeD"}, event_id=4688))
    assert event.user == "MAIR\\Administrator"
    assert event.event_data["SubjectUserName"] == "MAIR\\Administrator"
    assert event.event_data["Extra"] == "MiXeD"


def test_unsupported_channel_is_rejected():
    with pytest.raises(ValueError, match="unsupported channel"):
        normalise(raw_record(channel="Application"))


def test_raw_reference_format():
    assert make_raw_reference("S02", "Security.evtx", 43584) == "evtx://datasets/S02/raw/Security.evtx#EventRecordID=43584"


@pytest.mark.parametrize(
    ("channel", "event_id", "expected"),
    [
        (SECURITY, 4624, "TargetUserName"),
        (SECURITY, 4625, "TargetUserName"),
        (SECURITY, 4634, "TargetUserName"),
        (SECURITY, 4647, "TargetUserName"),
        (SECURITY, 4648, "TargetUserName"),
        (SECURITY, 4688, "SubjectUserName"),
        (SECURITY, 1102, "SubjectUserName"),
        (SYSMON, 1, "User"),
        (SYSMON, 11, "User"),
    ],
)
def test_user_field_mapping_table(channel: str, event_id: int, expected: str):
    assert user_field_for(channel, event_id) == expected


def test_user_field_mapping_rejects_an_unknown_channel():
    with pytest.raises(ValueError, match="unsupported channel"):
        user_field_for("Application", 1)


@pytest.mark.parametrize(
    ("utc", "expected"),
    [
        (WINDOW_START, True),
        (WINDOW_END, True),
        ("2026-09-21T02:04:38.9439269Z", False),
        ("2026-09-21T02:06:18.3126077Z", False),
    ],
)
def test_in_scenario_window_is_inclusive_at_both_ends(utc: str, expected: bool):
    assert normalise(raw_record(filetime=filetime_of(utc))).in_scenario_window is expected


def test_record_ids_collide_but_evidence_ids_do_not():
    first = normalise(raw_record(), scenario_id="S02")
    second = normalise(raw_record(), scenario_id="S03")
    assert first.record_id == second.record_id == 43584
    assert first.evidence_id == "S02-SEC-43584"
    assert second.evidence_id == "S03-SEC-43584"


# --- real evidence ---------------------------------------------------------------

ANCHORS = {
    ("S02", 43584): (4624, "2026-09-21T02:05:30.0430374Z", None),
    ("S03", 43584): (4688, "2026-09-21T02:25:15.6704553Z", "dllhost.exe"),
    ("S02", 43628): (4688, None, "msedgewebview2.exe"),
    ("S03", 43628): (4688, None, "whoami.exe"),
    ("S02", 43571): (4625, None, None),
    ("S03", 43571): (4688, None, "sppsvc.exe"),
}


def test_real_security_anchors_through_the_full_normaliser(real_evtx_path):
    events: dict[tuple[str, int], object] = {}
    for scenario in ("S02", "S03"):
        path: Path = real_evtx(scenario, SECURITY)
        info = _scenario_window(path)
        for raw in iter_records(path):
            event = normalise_record(
                raw,
                scenario_id=scenario,
                source_filename=path.name,
                source_sha256=SHA,
                window_start_ticks=info[0],
                window_end_ticks=info[1],
            )
            events[(scenario, event.record_id)] = event

    for (scenario, record_id), (event_id, timestamp, image) in ANCHORS.items():
        event = events[(scenario, record_id)]
        assert event.evidence_id == f"{scenario}-SEC-{record_id}"
        assert event.source_event_id == event_id
        if timestamp is not None:
            assert event.timestamp_utc == timestamp
        if image is not None:
            path_value = event.event_data.get("NewProcessName") or event.event_data.get("Image") or ""
            assert path_value.rsplit("\\", 1)[-1].lower() == image
        assert event.in_scenario_window is True


def _scenario_window(path: Path) -> tuple[int, int]:
    from event_processing.manifest import load_scenario

    info = load_scenario(path.parent.parent)
    return info.window_start_ticks, info.window_end_ticks
