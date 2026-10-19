"""Conservative authentication principal keys, independent of detection or verdicts.

Raw values stay unchanged. Correlation is case-insensitive and host-scoped. A
missing/NULL SID can inherit a SID only from an unambiguous matching host,
domain and username in the supplied snapshot. Conflicting SIDs never merge.
"""

from collections import defaultdict
from dataclasses import dataclass, field
import re

from event_processing.schema import NormalisedEvent
from event_processing.timeutil import iso_to_ticks


def available(value: str | None) -> str | None:
    return value.strip() if isinstance(value,str) and value.strip() not in ("", "-") else None


def qualified_account(name: str | None, domain: str | None = None) -> str | None:
    name, domain = available(name), available(domain)
    if name is None:
        return None
    return f"{domain}\\{name}" if domain and "\\" not in name else name


@dataclass(frozen=True)
class AuthenticationPrincipal:
    key: tuple[str, ...]
    user: str | None = field(compare=False)
    host: str | None = field(compare=False)


def authentication_principals(events) -> dict[str, AuthenticationPrincipal]:
    """Map Security 4624/4625 records to principals without guessing a domain.

    Missing identity/host and internally contradictory domain names remain
    record-specific. NULL SID S-1-0-0 is not an identity. Domain-less evidence
    cannot borrow a SID from a domain-qualified alias.
    """
    rows = []
    aliases = defaultdict(set)
    def order(event):
        ticks=getattr(event,"timestamp_ticks",None)
        return (ticks if ticks is not None else iso_to_ticks(event.timestamp_utc),event.evidence_id)
    for event in sorted(events,key=order):
        if event.channel != "Security" or event.source_event_id not in (4624, 4625):
            continue
        name = available(event.event_data.get("TargetUserName")) or available(event.user)
        domain = available(event.event_data.get("TargetDomainName"))
        conflict = False
        if name and "\\" in name:
            prefix, name = name.rsplit("\\", 1)
            conflict = bool(domain and prefix.casefold() != domain.casefold())
            domain = domain or prefix
        host = available(event.host)
        alias = tuple((v or "").casefold() for v in (host, domain, name))
        sid = available(event.event_data.get("TargetUserSid"))
        if not sid or not re.fullmatch(r"S-1-(?:\d+-)+\d+", sid, re.I) or sid.casefold() == "s-1-0-0":
            sid = None
        if sid and host and name and not conflict:
            aliases[alias].add(sid.casefold())
        rows.append((event, name, domain, host, alias, sid, conflict))
    result = {}
    for event, name, domain, host, alias, sid, conflict in rows:
        candidates = aliases[alias]
        resolved = sid.casefold() if sid else next(iter(candidates)) if len(candidates) == 1 else None
        if conflict or not host or not name or (not sid and len(candidates) > 1):
            key = (alias[0], "unknown", event.evidence_id)
        elif resolved:
            key = (alias[0], "sid", resolved)
        else:
            key = (alias[0], "name", alias[1], alias[2])
        result[event.evidence_id] = AuthenticationPrincipal(key, qualified_account(name, domain), event.host)
    return result
