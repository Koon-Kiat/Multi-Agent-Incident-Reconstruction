"""The normalised event model and its wire format (AGENTS.md I4, I1, I2).

Contract
--------

Every event Event Processing & Detection Engine exposes carries all of the following, and nothing else:

============================ ==========================================================
``evidence_id``              ``<scenario>-<SEC|SYS>-<record_id>`` (I1)
``scenario_id``              explicit, never inferred from a path at query time
``channel``                  ``Security`` or ``Microsoft-Windows-Sysmon/Operational``
``source_type``              ``windows_security`` or ``sysmon``, derived from the channel
``record_id``                original ``EventRecordID``, unmodified
``source_event_id``          the Windows Event ID (4624, 4688, Sysmon 1, 11, ...)
``timestamp_utc``            exact ``YYYY-MM-DDTHH:MM:SS.fffffffZ`` string (I2)
``timestamp_ticks``          100 ns units on Authentication Investigation Agent's epoch, integer (I2)
``host``                     ``System/Computer``, may be ``None``
``user``                     best-effort account, may be ``None``; never case-folded
``event_data``               every original ``EventData`` name/value pair, verbatim strings
``raw_reference``            ``evtx://datasets/<scenario>/raw/<file>#EventRecordID=<id>``
``source_sha256``            manifest digest of the file the event came from
``raw_xml``                  the original record XML, unmodified
``in_scenario_window``       whether the event falls inside the metadata window, inclusive
``parse_warnings``           what was missing or odd; the record is never dropped for it
============================ ==========================================================

The model is frozen, strict and extra-forbid: a consumer cannot mutate a corpus event, and
a typo or a type slip is an error rather than a silent attribute. The validators make the
three invariants that can be checked inside one event true by construction: the evidence ID
must equal the ID derived from ``scenario_id`` + ``channel`` + ``record_id``, the timestamp
must equal the canonical rendering of ``timestamp_ticks``, and ``source_type`` must match
``channel``.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from event_processing.ids import SCENARIO_ID_RE, make_evidence_id
from event_processing.timeutil import ticks_to_iso

SCHEMA_VERSION = "security-event-v1"

Channel = Literal["Security", "Microsoft-Windows-Sysmon/Operational"]
SourceType = Literal["windows_security", "sysmon"]

CHANNEL_SOURCE_TYPES: dict[str, SourceType] = {
    "Security": "windows_security",
    "Microsoft-Windows-Sysmon/Operational": "sysmon",
}

SHA256_PATTERN = r"^[0-9A-Fa-f]{64}$"


class NormalisedEvent(BaseModel):
    """One original EVTX record, normalised and self-consistent."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)

    evidence_id: str = Field(min_length=1)
    scenario_id: str = Field(pattern=SCENARIO_ID_RE.pattern)
    channel: Channel
    source_type: SourceType
    record_id: int = Field(gt=0)
    source_event_id: int = Field(gt=0)
    timestamp_utc: str
    timestamp_ticks: int = Field(ge=0)
    host: str | None = None
    user: str | None = None
    event_data: dict[str, str] = Field(default_factory=dict)
    raw_reference: str = Field(min_length=1)
    source_sha256: str = Field(pattern=SHA256_PATTERN)
    raw_xml: str = Field(min_length=1)
    in_scenario_window: bool
    parse_warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def evidence_id_is_scoped_consistently(self) -> NormalisedEvent:
        expected = make_evidence_id(self.scenario_id, self.channel, self.record_id)
        if self.evidence_id != expected:
            raise ValueError(f"evidence_id {self.evidence_id!r} must equal {expected!r}")
        return self

    @model_validator(mode="after")
    def timestamp_is_canonical(self) -> NormalisedEvent:
        expected = ticks_to_iso(self.timestamp_ticks)
        if self.timestamp_utc != expected:
            raise ValueError(f"timestamp_utc {self.timestamp_utc!r} must equal {expected!r} for the given ticks")
        return self

    @model_validator(mode="after")
    def source_type_matches_channel(self) -> NormalisedEvent:
        expected = CHANNEL_SOURCE_TYPES[self.channel]
        if self.source_type != expected:
            raise ValueError(f"source_type {self.source_type!r} must be {expected!r} for channel {self.channel!r}")
        return self


def event_to_json(event: NormalisedEvent) -> str:
    """Serialise one event as a single JSON line with sorted keys and no ASCII escaping."""
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)


def event_from_json(payload: str) -> NormalisedEvent:
    """Inverse of :func:`event_to_json`; re-runs every validator."""
    return NormalisedEvent.model_validate_json(payload)
