"""MITRE ATT&CK candidates for reconstructed stages, with how strongly the evidence shows them.

The Event Processing & Detection Engine names one primary technique per detection. This table
adds the technique's name and tactics, any secondary candidate, and the strength of the link
between the rule's observable and the technique:

* ``defining``: the trigger event *is* the technique's observable (a 1102 is a cleared Security
  log; a discovery binary ran). The mapping is ``supported`` when selected.
* ``indicative``: the observable is consistent with the technique but other explanations are
  ordinary (a 4648 is not proof of valid-account abuse; a script written to a temp folder is not
  proof it was transferred in). The mapping is at most ``tentative``.

Any mapping becomes ``uncertain`` when the stage narrative judged the evidence insufficient or
the model did not select it. No mapping asserts intent or compromise.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

Strength = Literal["defining", "indicative"]
MappingStatus = Literal["supported", "tentative", "uncertain"]


class Technique(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    technique_id: str
    name: str
    tactics: tuple[str, ...]


TECHNIQUES: dict[str, Technique] = {t.technique_id: t for t in (
    Technique(technique_id="T1003.001", name="OS Credential Dumping: LSASS Memory", tactics=("Credential Access",)),
    Technique(technique_id="T1016", name="System Network Configuration Discovery", tactics=("Discovery",)),
    Technique(technique_id="T1033", name="System Owner/User Discovery", tactics=("Discovery",)),
    Technique(technique_id="T1053.005", name="Scheduled Task/Job: Scheduled Task",
              tactics=("Execution", "Persistence", "Privilege Escalation")),
    Technique(technique_id="T1057", name="Process Discovery", tactics=("Discovery",)),
    Technique(technique_id="T1059", name="Command and Scripting Interpreter", tactics=("Execution",)),
    Technique(technique_id="T1059.001", name="Command and Scripting Interpreter: PowerShell", tactics=("Execution",)),
    Technique(technique_id="T1070.001", name="Indicator Removal: Clear Windows Event Logs", tactics=("Defense Evasion",)),
    Technique(technique_id="T1078", name="Valid Accounts",
              tactics=("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access")),
    Technique(technique_id="T1082", name="System Information Discovery", tactics=("Discovery",)),
    Technique(technique_id="T1087.002", name="Account Discovery: Domain Account", tactics=("Discovery",)),
    Technique(technique_id="T1105", name="Ingress Tool Transfer", tactics=("Command and Control",)),
    Technique(technique_id="T1110", name="Brute Force", tactics=("Credential Access",)),
    Technique(technique_id="T1135", name="Network Share Discovery", tactics=("Discovery",)),
    Technique(technique_id="T1204", name="User Execution", tactics=("Execution",)),
    Technique(technique_id="T1482", name="Domain Trust Discovery", tactics=("Discovery",)),
    Technique(technique_id="T1543.003", name="Create or Modify System Process: Windows Service",
              tactics=("Persistence", "Privilege Escalation")),
    Technique(technique_id="T1547.001", name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
              tactics=("Persistence", "Privilege Escalation")),
)}

# (rule_id, technique_id) -> strength and the justification recorded with the mapping.
RULE_TECHNIQUES: dict[tuple[str, str], tuple[Strength, str]] = {
    ("R-AUTH-01", "T1110"): ("indicative", "Repeated failed logons for one account and host preceded a success; "
                             "mistyped passwords produce the same pattern."),
    ("R-AUTH-01", "T1078"): ("indicative", "A successful logon followed the failures, so the account was then used; "
                             "whether the user was legitimate is not established."),
    ("R-AUTH-02", "T1110"): ("indicative", "Repeated failed logons for one account and host with no confirming success."),
    ("R-AUTH-03", "T1078"): ("indicative", "Security 4648 records a logon with explicitly supplied credentials; "
                             "services and run-as use produce it routinely."),
    ("R-CRED-01", "T1003.001"): ("defining", "Sysmon 10 records a process opening lsass.exe with an access mask "
                                 "documented for credential reading."),
    ("R-EXEC-01", "*discovery*"): ("defining", "Sysmon/Security process creation of a host or account enumeration "
                                   "binary; administrators also run these."),
    ("R-EXEC-02", "T1059.001"): ("defining", "PowerShell started with encoded, hidden-window or download arguments."),
    ("R-EXEC-03", "T1204"): ("indicative", "A document, browser or WMI host spawned a shell; user action is inferred."),
    ("R-EXEC-03", "T1059"): ("defining", "A command or script interpreter process was created."),
    ("R-FILE-01", "T1105"): ("indicative", "An executable or script was written under a user-writable directory; "
                             "its origin outside the host is not shown by the file event."),
    ("R-LOG-01", "T1070.001"): ("defining", "Security 1102 records that the Security audit log was cleared."),
    ("R-PERSIST-01", "T1543.003"): ("defining", "Security 4697 records a service installation."),
    ("R-PERSIST-02", "T1053.005"): ("defining", "Security 4698 records a scheduled task creation."),
    ("R-PERSIST-03", "T1547.001"): ("defining", "Sysmon 13 records a Run/RunOnce registry value being set."),
}
DISCOVERY_TECHNIQUE_IDS = frozenset({"T1016", "T1033", "T1057", "T1082", "T1087.002", "T1135", "T1482"})
SECONDARY_TECHNIQUES: dict[str, tuple[str, ...]] = {"R-AUTH-01": ("T1078",), "R-EXEC-03": ("T1059",)}


def rule_strength(rule_id: str, technique_id: str) -> tuple[Strength, str]:
    """Strength and justification for one rule/technique pair; unknown pairs are indicative only."""
    key = (rule_id, "*discovery*") if technique_id in DISCOVERY_TECHNIQUE_IDS and rule_id == "R-EXEC-01" else (rule_id, technique_id)
    return RULE_TECHNIQUES.get(key, ("indicative", "The detection rule names this technique; the rule's observable "
                                                   "is not specific to it."))


def candidates_for(rule_id: str, primary: str | None) -> tuple[str, ...]:
    """The primary technique the detection named, then any secondary candidate for that rule."""
    ordered = ([primary] if primary else []) + list(SECONDARY_TECHNIQUES.get(rule_id, ()))
    return tuple(dict.fromkeys(t for t in ordered if t))


def status_for(strength: Strength, selected: bool, insufficient: bool) -> MappingStatus:
    if not selected or insufficient:
        return "uncertain"
    return "supported" if strength == "defining" else "tentative"


def describe(technique_id: str) -> Technique:
    """Catalogue entry, or a placeholder that keeps an unknown ID visible rather than dropping it."""
    return TECHNIQUES.get(technique_id, Technique(technique_id=technique_id, name="(not in local catalogue)", tactics=()))
