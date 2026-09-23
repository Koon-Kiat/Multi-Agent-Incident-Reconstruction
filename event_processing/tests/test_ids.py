"""T1.1 / AGENTS I1: evidence IDs are scenario-scoped, exact and round-trippable."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from event_processing.ids import CHANNEL_CODES, EvidenceRef, make_evidence_id, parse_evidence_id
from authentication_agent.models import evidence_id_for

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def test_channel_codes_are_the_agreed_ones():
    assert CHANNEL_CODES == {SECURITY: "SEC", SYSMON: "SYS"}


@pytest.mark.parametrize(
    ("scenario", "channel", "record", "expected"),
    [
        ("S02", SECURITY, 43584, "S02-SEC-43584"),
        ("S02", SYSMON, 25891, "S02-SYS-25891"),
        ("S01", SECURITY, 31213331, "S01-SEC-31213331"),
        ("SYN-A", SECURITY, 1, "SYN-A-SEC-1"),
        ("a_b-c1", SYSMON, 9, "a_b-c1-SYS-9"),
    ],
)
def test_make_evidence_id(scenario: str, channel: str, record: int, expected: str):
    assert make_evidence_id(scenario, channel, record) == expected


@pytest.mark.parametrize(
    ("scenario", "channel", "record"),
    [
        ("S02", SECURITY, 43584),
        ("S02", SYSMON, 25891),
        ("SYN-A", SECURITY, 1),
        ("S", SYSMON, 10**30),
    ],
)
def test_round_trip(scenario: str, channel: str, record: int):
    evidence_id = make_evidence_id(scenario, channel, record)
    parsed = parse_evidence_id(evidence_id)
    assert parsed == EvidenceRef(scenario_id=scenario, channel=channel, record_id=record)
    assert parsed.evidence_id == evidence_id


def test_scenario_with_hyphens_parses_from_the_right():
    parsed = parse_evidence_id("SYN-A-SEC-1")
    assert parsed.scenario_id == "SYN-A"
    assert parsed.channel == SECURITY
    assert parsed.record_id == 1


def test_scenario_that_contains_sec_parses_from_the_right():
    parsed = parse_evidence_id("S02-SEC-SEC-7")
    assert (parsed.scenario_id, parsed.channel, parsed.record_id) == ("S02-SEC", SECURITY, 7)


def test_scenario_may_end_with_a_hyphen_because_the_agreed_pattern_allows_it():
    # Consequences of the agreed I1 pattern: the scenario group admits "-", so the double
    # hyphen is a valid scenario boundary, not a malformed ID. Pinned so it is not "fixed"
    # into a divergence from Authentication Investigation Agent/Evidence Verification & Evaluation.
    parsed = parse_evidence_id("S02--SEC-1")
    assert (parsed.scenario_id, parsed.channel, parsed.record_id) == ("S02-", SECURITY, 1)
    assert make_evidence_id("S02-", SECURITY, 1) == "S02--SEC-1"


@pytest.mark.parametrize(
    "value",
    [
        "S02-43584",
        "S02-SEC-0",
        "S02-SEC-01",
        "S02-SEC-",
        "S02-XYZ-1",
        "s02-sec-1",
        "-SEC-1",
        "S02-SEC-1 ",
        " S02-SEC-1",
        "S02-SEC-1\n",
        "S02-SEC-1-2",
        "",
        "S02-SEC-1.0",
        "S02-SEC--1",
    ],
)
def test_malformed_ids_are_rejected(value: str):
    with pytest.raises(ValueError):
        parse_evidence_id(value)


def test_non_string_is_rejected():
    with pytest.raises(ValueError, match="must be a str"):
        parse_evidence_id(43584)  # type: ignore[arg-type]


def test_unknown_channel_is_rejected():
    with pytest.raises(ValueError, match="unsupported channel"):
        make_evidence_id("S02", "Application", 1)


@pytest.mark.parametrize("record", [0, -1, True, 1.0, "1"])
def test_invalid_record_id_is_rejected(record):
    with pytest.raises(ValueError, match="record_id"):
        make_evidence_id("S02", SECURITY, record)


@pytest.mark.parametrize("scenario", ["", "s 02", "S" * 81, "S02/1"])
def test_invalid_scenario_id_is_rejected(scenario: str):
    with pytest.raises(ValueError, match="scenario_id"):
        make_evidence_id(scenario, SECURITY, 1)


def test_record_ids_collide_across_scenarios_but_ids_do_not():
    assert make_evidence_id("S02", SECURITY, 43584) != make_evidence_id("S03", SECURITY, 43584)


@pytest.mark.parametrize(
    ("scenario", "record"),
    [("S01", 31213331), ("S02", 43584), ("S02", 1), ("SYN-A", 42)],
)
def test_matches_authentication_evidence_id_for_security_events(scenario: str, record: int):
    assert make_evidence_id(scenario, SECURITY, record) == evidence_id_for(scenario, record)


def test_parsed_ref_is_frozen():
    ref = parse_evidence_id("S02-SEC-43584")
    with pytest.raises(ValidationError):
        ref.record_id = 1  # type: ignore[misc]
