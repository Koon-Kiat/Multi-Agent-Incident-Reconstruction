"""Scenario-scoped evidence identifiers (AGENTS.md I1).

Contract
--------

``evidence_id = f"{scenario_id}-{CHANNEL_CODE}-{record_id}"`` where ``CHANNEL_CODE`` is
``SEC`` for the ``Security`` channel and ``SYS`` for ``Microsoft-Windows-Sysmon/Operational``.

Windows ``EventRecordID`` values are **not** unique across the MAIR corpus: S02 and S03 were
both recorded after restoring the same VM snapshot, so record ``43584`` is a ``4624`` in S02
and a ``4688`` in S03. Nothing may key on the record ID alone, which is why the scenario and
the channel are part of the ID. ``record_id`` is the original ``EventRecordID``, unmodified.

The scenario part may itself contain hyphens (Authentication Investigation Agent's synthetic fixtures use ``SYN-A``), so the
pattern below matches the scenario group greedily and the parse is effectively taken from the
right. ``s02-sec-1``, ``S02-SEC-01``, ``S02-43584`` and ``S02-XYZ-1`` are all rejected: there
is no fuzzy matching, no case folding and no "did you mean".
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

CHANNEL_CODES: dict[str, str] = {
    "Security": "SEC",
    "Microsoft-Windows-Sysmon/Operational": "SYS",
}

_CODE_CHANNELS: dict[str, str] = {code: channel for channel, code in CHANNEL_CODES.items()}

# AGENTS.md I1, verbatim. The scenario group is greedy, so ``SYN-A-SEC-1`` parses as
# scenario ``SYN-A`` rather than failing on the embedded hyphen.
EVIDENCE_ID_RE = re.compile(r"^(?P<scenario>[A-Za-z0-9_-]{1,80})-(?P<code>SEC|SYS)-(?P<record>[1-9][0-9]*)$")

# Same character set as the scenario group of the pattern above (authentication_agent.models.ScenarioId).
SCENARIO_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")

# ``detect`` writes one ``<scenario_id>.json`` per scenario plus its own ``summary.json``, so a
# scenario whose id is ``summary`` would make the two collide. The name is reserved everywhere a
# scenario id enters Event Processing & Detection Engine (the dataset manifest and the detection engine), case-insensitively
# because a Windows filesystem would collide ``Summary.json`` with ``summary.json`` anyway.
RESERVED_SCENARIO_IDS = frozenset({"summary"})


def is_reserved_scenario_id(scenario_id: str) -> bool:
    """True when ``scenario_id`` is a name an Event Processing & Detection Engine artefact already owns."""
    return scenario_id.casefold() in RESERVED_SCENARIO_IDS


class EvidenceRef(BaseModel):
    """The three parts an ``evidence_id`` round-trips to."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    scenario_id: str
    channel: str
    record_id: int = Field(gt=0)

    @property
    def evidence_id(self) -> str:
        return make_evidence_id(self.scenario_id, self.channel, self.record_id)


def make_evidence_id(scenario_id: str, channel: str, record_id: int) -> str:
    """Build ``<scenario>-<SEC|SYS>-<record_id>``, rejecting anything that cannot round-trip."""
    try:
        code = CHANNEL_CODES[channel]
    except KeyError:
        raise ValueError(f"unsupported channel {channel!r}; expected one of {sorted(CHANNEL_CODES)}") from None
    if not SCENARIO_ID_RE.fullmatch(scenario_id):
        raise ValueError(f"scenario_id {scenario_id!r} must match {SCENARIO_ID_RE.pattern}")
    # ``bool`` is an ``int`` subclass; ``True`` would render as ``-True-`` instead of a record number.
    if isinstance(record_id, bool) or not isinstance(record_id, int) or record_id < 1:
        raise ValueError(f"record_id {record_id!r} must be a positive int")
    return f"{scenario_id}-{code}-{record_id}"


def parse_evidence_id(value: str) -> EvidenceRef:
    """Parse an ``evidence_id`` back into its scenario, channel and record ID.

    Raises ``ValueError`` for anything malformed; a malformed ID is never coerced to a
    best-effort parse.
    """
    if not isinstance(value, str):
        raise ValueError(f"evidence_id must be a str, got {type(value).__name__}")
    match = EVIDENCE_ID_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"malformed evidence_id {value!r}; expected <scenario>-<SEC|SYS>-<record_id>")
    return EvidenceRef(
        scenario_id=match.group("scenario"),
        channel=_CODE_CHANNELS[match.group("code")],
        record_id=int(match.group("record")),
    )
