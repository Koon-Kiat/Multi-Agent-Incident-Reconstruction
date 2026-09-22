"""T1.4 / AGENTS I4: every required field, every consistency validator, lossless JSON."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from m2.ids import make_evidence_id
from m2.schema import (
    CHANNEL_SOURCE_TYPES,
    SCHEMA_VERSION,
    NormalisedEvent,
    event_from_json,
    event_to_json,
)

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def sample_event(**overrides) -> NormalisedEvent:
    fields: dict = {
        "evidence_id": "S02-SEC-43584",
        "scenario_id": "S02",
        "channel": SECURITY,
        "source_type": "windows_security",
        "record_id": 43584,
        "source_event_id": 4624,
        "timestamp_utc": "2026-09-21T02:05:30.0430374Z",
        "timestamp_ticks": 639256395300430374,
        "host": "MAIR-WIN11-LAB",
        "user": "MAIR\\analyst",
        "event_data": {"TargetUserName": "analyst", "LogonType": "10"},
        "raw_reference": "evtx://datasets/S02/raw/Security.evtx#EventRecordID=43584",
        "source_sha256": "D396CE599723189331D440EDD55CC055C28EB4B6AD45A421D07A8E83A2F0EBA7",
        "raw_xml": "<Event><System><EventID>4624</EventID></System></Event>",
        "in_scenario_window": True,
        "parse_warnings": (),
    }
    fields.update(overrides)
    return NormalisedEvent(**fields)


def test_schema_version_is_pinned():
    assert SCHEMA_VERSION == "m2-event-v1"


def test_channel_source_type_map():
    assert CHANNEL_SOURCE_TYPES == {SECURITY: "windows_security", SYSMON: "sysmon"}


def test_valid_security_event():
    event = sample_event()
    assert event.evidence_id == "S02-SEC-43584"
    assert event.user == "MAIR\\analyst"
    assert event.event_data["TargetUserName"] == "analyst"
    assert event.parse_warnings == ()


def test_valid_sysmon_event():
    event = sample_event(
        evidence_id="S02-SYS-25891",
        channel=SYSMON,
        source_type="sysmon",
        record_id=25891,
        source_event_id=1,
        raw_reference="evtx://datasets/S02/raw/Sysmon.evtx#EventRecordID=25891",
        user=None,
        host=None,
    )
    assert event.user is None and event.host is None


def test_ticks_that_really_match_the_timestamp():
    # Guards the fixture above: the model must accept the timestamp it declares.
    from m2.timeutil import iso_to_ticks

    assert sample_event().timestamp_ticks == iso_to_ticks("2026-09-21T02:05:30.0430374Z")


def test_evidence_id_must_match_the_scope():
    with pytest.raises(ValidationError, match="evidence_id"):
        sample_event(evidence_id="S03-SEC-43584")


def test_evidence_id_cannot_be_derived_from_another_channel():
    with pytest.raises(ValidationError, match="evidence_id"):
        sample_event(evidence_id="S02-SYS-43584")


@pytest.mark.parametrize("evidence_id", ["43584", "S02-43584", "s02-sec-43584", "S02-SEC-0", ""])
def test_malformed_evidence_ids_are_rejected(evidence_id: str):
    with pytest.raises(ValidationError):
        sample_event(evidence_id=evidence_id)


def test_record_id_cannot_be_negative_or_zero():
    with pytest.raises(ValidationError):
        sample_event(record_id=0)
    with pytest.raises(ValidationError):
        sample_event(record_id=-43584)


def test_ticks_must_match_the_timestamp():
    with pytest.raises(ValidationError, match="timestamp_utc"):
        sample_event(timestamp_ticks=638989515300430375)


def test_timestamp_must_be_canonical_seven_digit_utc():
    for value in ("2026-09-21T02:05:30.043037Z", "2026-09-21T02:05:30.0430374+00:00", "2026-09-21T02:05:30Z"):
        with pytest.raises(ValidationError):
            sample_event(timestamp_utc=value)


def test_source_type_must_match_the_channel():
    with pytest.raises(ValidationError, match="source_type"):
        sample_event(source_type="sysmon")


@pytest.mark.parametrize("channel", ["Application", "security", "", "Microsoft-Windows-Sysmon"])
def test_channel_is_a_closed_set(channel: str):
    with pytest.raises(ValidationError):
        sample_event(channel=channel)


@pytest.mark.parametrize("scenario_id", ["", "s 02", "S" * 81])
def test_scenario_id_pattern(scenario_id: str):
    with pytest.raises(ValidationError):
        sample_event(scenario_id=scenario_id, evidence_id=make_evidence_id("S02", SECURITY, 43584))


def test_extra_fields_are_forbidden():
    with pytest.raises(ValidationError, match="extra_forbidden"):
        sample_event(command_line="whoami")


def test_int_fields_are_strict():
    with pytest.raises(ValidationError):
        sample_event(record_id="43584")
    with pytest.raises(ValidationError):
        sample_event(timestamp_ticks="639256395300430374")
    with pytest.raises(ValidationError):
        sample_event(in_scenario_window="true")


def test_event_data_values_must_be_strings():
    with pytest.raises(ValidationError):
        sample_event(event_data={"EventID": 4624})


def test_source_sha256_must_be_a_hex_digest():
    for value in ("", "abc", "Z" * 64, "0" * 63):
        with pytest.raises(ValidationError):
            sample_event(source_sha256=value)


def test_raw_reference_and_raw_xml_cannot_be_empty():
    with pytest.raises(ValidationError):
        sample_event(raw_reference="")
    with pytest.raises(ValidationError):
        sample_event(raw_xml="")


def test_event_is_frozen():
    event = sample_event()
    with pytest.raises(ValidationError):
        event.user = "someone-else"  # type: ignore[misc]


def test_json_round_trip_is_lossless():
    event = sample_event(
        user=None,
        host=None,
        event_data={"Image": "C:\\Windows\\System32\\whoami.exe", "Utc\u00e9": ""},
        parse_warnings=("EventData field 'User' is absent; user set to None",),
    )
    payload = event_to_json(event)
    assert event_from_json(payload) == event
    assert json.loads(payload)["parse_warnings"] == list(event.parse_warnings)
    assert event_to_json(event_from_json(payload)) == payload


def test_json_keys_are_sorted_and_ascii_is_preserved():
    payload = event_to_json(sample_event(event_data={"b": "2", "a": "\u00e9"}))
    assert payload.index('"a"') < payload.index('"b"')
    assert "\u00e9" in payload
