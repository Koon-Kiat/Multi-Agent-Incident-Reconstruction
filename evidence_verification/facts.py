"""Facts the verifier reads straight from corpus events.

The verifier forms its own view of the evidence. Nothing here consults the orchestrator's stage
builder, an agent finding or a detection: an identifier, account, process or time is whatever the
recorded event itself says. Values keep their original case and form; comparisons that need to
ignore case or a domain prefix do so explicitly and say so.
"""

from __future__ import annotations

import re
from pathlib import PureWindowsPath

from event_processing.schema import NormalisedEvent

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"

# Event-data fields that name an account. Order is irrelevant; every one that is present counts.
ACCOUNT_FIELDS = ("TargetUserName", "SubjectUserName", "User", "SourceUser", "TargetUser")

# Identities that are not a person: matching on them proves nothing about a shared actor.
_SYSTEM_ACCOUNT = re.compile(r"^(system|local service|network service|anonymous logon|-|(dwm|umfd)-\d+|.*\$)$", re.I)


def account_key(value: str | None) -> str | None:
    """Comparable account name: domain prefix removed, case-folded; ``None`` for non-person identities."""
    if not value:
        return None
    name = value.rsplit("\\", 1)[-1].strip()
    if not name or _SYSTEM_ACCOUNT.match(name):
        return None
    return name.casefold()


def event_accounts(event: NormalisedEvent) -> set[str]:
    """Person-account keys an event names, from its normalised user and every account field."""
    values = [event.user, *(event.event_data.get(name) for name in ACCOUNT_FIELDS)]
    return {key for key in (account_key(value) for value in values) if key}


def stem(path: str | None) -> str | None:
    """Case-folded executable name without directory or extension (``C:\\X\\Whoami.EXE`` -> ``whoami``)."""
    if not path:
        return None
    name = PureWindowsPath(path.strip().strip('"')).stem
    return name.casefold() or None


def is_process_creation(event: NormalisedEvent) -> bool:
    return (event.channel == SYSMON and event.source_event_id == 1) or (
        event.channel == SECURITY and event.source_event_id == 4688)


def process_image(event: NormalisedEvent) -> str | None:
    """Image path of the process a creation event records."""
    data = event.event_data
    if event.channel == SYSMON and event.source_event_id == 1:
        return data.get("Image")
    if event.channel == SECURITY and event.source_event_id == 4688:
        return data.get("NewProcessName")
    return None


def parent_image(event: NormalisedEvent) -> str | None:
    data = event.event_data
    if event.channel == SYSMON and event.source_event_id == 1:
        return data.get("ParentImage")
    if event.channel == SECURITY and event.source_event_id == 4688:
        return data.get("ParentProcessName")
    return None


def command_line(event: NormalisedEvent) -> str:
    return event.event_data.get("CommandLine") or ""


def process_guid(event: NormalisedEvent) -> str | None:
    """The process an event is about: the creator for Sysmon 10, otherwise the event's own process."""
    if event.channel != SYSMON:
        return None
    return event.event_data.get("SourceProcessGUID" if event.source_event_id == 10 else "ProcessGuid") or None


def parent_process_guid(event: NormalisedEvent) -> str | None:
    if event.channel == SYSMON and event.source_event_id == 1:
        return event.event_data.get("ParentProcessGuid") or None
    return None


def value_pool(events) -> set[str]:
    """Every string an event records: normalised user and host, and each ``EventData`` value."""
    pool: set[str] = set()
    for event in events:
        for value in (event.user, event.host, *event.event_data.values()):
            if value:
                pool.add(value)
    return pool


def grounded(entity: str, pool: set[str], folded_pool: set[str]) -> bool:
    """True when ``entity`` is a recorded value: exactly, ignoring case, or as the account part of ``DOMAIN\\name``."""
    if entity in pool or entity.casefold() in folded_pool:
        return True
    if "\\" in entity and not entity[1:3] == ":\\":
        return entity.rsplit("\\", 1)[-1].casefold() in folded_pool
    return False


def folded(pool: set[str]) -> set[str]:
    return {value.casefold() for value in pool}
