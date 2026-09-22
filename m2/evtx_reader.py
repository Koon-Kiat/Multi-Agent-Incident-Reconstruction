"""Read-only EVTX record reader.

``iter_records(path)`` yields one :class:`RawRecord` per ``<Event>`` in an ``.evtx`` file and
never writes to the file: python-evtx opens it with ``open(path, "rb")`` and maps it
``ACCESS_READ``. Nothing here interprets or rewrites event content, so a caller can always
fall back to ``raw_xml``.

Timestamps come from the **raw 64-bit FILETIME** of ``TimeCreated/@SystemTime``, reached
through the binary-XML template's substitution node. python-evtx's own
``BinaryParser.parse_filetime`` is unusable for AGENTS.md I2: it renders
``datetime.fromtimestamp(float(qword) * 1e-7 - 11644473600)``, which drops to microsecond
precision and, for S02-SEC-43584, prints ``.043036`` where the record holds ``.0430374``.
``Record.timestamp()`` therefore must not be used on the tick path.

``event_data`` keeps every named ``EventData/Data`` value as the string the record holds;
a ``Data`` element without a ``Name`` attribute cannot be keyed and is skipped — it stays
visible verbatim in ``raw_xml``, so nothing is lost. Child elements of ``UserData`` are not
``EventData`` fields and are left to ``raw_xml``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from Evtx.Evtx import Evtx, Record
from Evtx.Nodes import (
    AttributeNode,
    ConditionalSubstitutionNode,
    FiletimeTypeNode,
    OpenStartElementNode,
    ValueNode,
)
from pydantic import BaseModel, ConfigDict, Field

EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"

# Nodes that cannot contain a TimeCreated element; stopping at them avoids walking whole
# substitution blobs.
_LEAF_NODE_TYPES = (AttributeNode, ConditionalSubstitutionNode, ValueNode)


class EvtxRecordError(ValueError):
    """A record is missing a field M2 needs, so it cannot be normalised honestly."""


class RawRecord(BaseModel):
    """One original record, still un-normalised. Values are verbatim."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)

    record_id: int = Field(gt=0)
    event_id: int = Field(gt=0)
    channel: str
    computer: str | None = None
    filetime: int = Field(ge=0)
    event_data: dict[str, str] = Field(default_factory=dict)
    raw_xml: str = Field(min_length=1)


def _time_created_substitution(node: Any) -> Any:
    """Find the substitution node feeding ``TimeCreated/@SystemTime``, or ``None``."""
    if isinstance(node, OpenStartElementNode) and node.tag_name() == "TimeCreated":
        for child in node.children():
            if isinstance(child, AttributeNode) and child.attribute_name().string() == "SystemTime":
                return child.attribute_value()
        return None
    if isinstance(node, _LEAF_NODE_TYPES):
        return None
    try:
        children = node.children()
    except AttributeError:
        return None
    for child in children:
        found = _time_created_substitution(child)
        if found is not None:
            return found
    return None


def read_filetime(record: Record) -> int:
    """Return the raw 64-bit FILETIME of ``TimeCreated/@SystemTime`` for one record."""
    root = record.root()
    substitution = _time_created_substitution(root.template())
    if substitution is None or not hasattr(substitution, "index"):
        raise EvtxRecordError("record has no TimeCreated/@SystemTime substitution")
    value = root.substitutions()[substitution.index()]
    if not isinstance(value, FiletimeTypeNode):
        raise EvtxRecordError(f"TimeCreated/@SystemTime is {type(value).__name__}, not a FILETIME")
    return int(value.unpack_qword(0))


def iter_records(path: Path | str) -> Iterator[RawRecord]:
    """Yield every record of ``path`` in file order, opening the file read-only.

    Chunks marked *inactive* by the file header are read too. ``FileHeader.chunk_count`` is
    not trustworthy for the exported S01 files: it declares 1 chunk for a Security file that
    holds 49 and 1 for a Sysmon file that holds 33, so python-evtx's default chunk iteration
    silently stops after 93 and 54 records. Counting every 64 KB chunk recovers 1807 and 893
    records with consecutive record numbers, which is exactly what Windows' own
    ``Get-WinEvent`` reports for the same files, and leaves the S02/S03 totals unchanged
    (their extra chunks hold no records).
    """
    with Evtx(str(path)) as log:
        for chunk in log.get_file_header().chunks(include_inactive=True):
            for record in chunk.records():
                yield _raw_record(record)


def read_records(path: Path | str) -> tuple[RawRecord, ...]:
    """Eager form of :func:`iter_records`, for callers that want a fixed sequence."""
    return tuple(iter_records(path))


def _raw_record(record: Record) -> RawRecord:
    xml = record.xml()
    element = ET.fromstring(xml)
    system = element.find(_tag("System"))
    if system is None:
        raise EvtxRecordError("record XML has no System element")
    channel = system.findtext(_tag("Channel"))
    if not channel:
        raise EvtxRecordError("record XML has no System/Channel")
    computer = system.findtext(_tag("Computer"))
    return RawRecord(
        record_id=_required_int(system, "EventRecordID"),
        event_id=_required_int(system, "EventID"),
        channel=channel,
        computer=computer or None,
        filetime=read_filetime(record),
        event_data=_event_data(element),
        raw_xml=xml,
    )


def _event_data(element: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    for node in element.findall(_tag("EventData", "Data")):
        name = node.get("Name")
        if name is None:
            continue
        data[name] = node.text or ""
    return data


def _required_int(system: ET.Element, tag: str) -> int:
    text = system.findtext(_tag(tag))
    if text is None:
        raise EvtxRecordError(f"record XML has no System/{tag}")
    try:
        return int(text)
    except ValueError:
        raise EvtxRecordError(f"System/{tag} is not an integer: {text!r}") from None


def _tag(*names: str) -> str:
    return "/".join(f"{{{EVENT_NAMESPACE}}}{name}" for name in names)
