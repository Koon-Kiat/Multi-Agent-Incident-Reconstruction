"""Classifies each claim against the key: aligned, neutral or unaligned.

``aligned``    the claim cites at least one record the key attributes to a ground-truth stage.
``neutral``    not aligned, but resting only on activity that is deliberately outside the scored stages:
               records outside the declared scenario window (the operator's own session), logon-session
               records for service or virtual identities, or records the key's owner designated contextual.
               Neutral claims are tallied separately; they are neither a match nor a false positive.
``unaligned``  anything else: the claim asserts activity the key does not attribute to any stage. These
               are the extra claims that count against precision.

Alignment is by cited evidence, never by claim text. A claim that cites no resolvable record cannot be
neutral: it is unaligned, because nothing about it can be excused.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from event_processing.query import EventStore
from event_processing.schema import NormalisedEvent
from evidence_verification import facts
from incident_reconstruction.claims import Claim

from .groundtruth import Stage

Alignment = Literal["aligned", "neutral", "unaligned"]
SESSION_EVENTS = frozenset({4624, 4634, 4647, 4648, 4672})


@dataclass(frozen=True)
class ClaimAlignment:
    claim_id: str
    alignment: Alignment
    stage_ids: tuple[str, ...]
    reason: str


def _session_noise(event: NormalisedEvent) -> bool:
    """A logon-session record that names no person: service, virtual-session or machine identities only."""
    return event.channel == facts.SECURITY and event.source_event_id in SESSION_EVENTS and not facts.event_accounts(event)


def _why_neutral(events: list[NormalisedEvent], neutral_ids: frozenset[str]) -> str | None:
    if all(event.evidence_id in neutral_ids for event in events):
        return "rests only on records designated contextual by the key's owner"
    if all(not event.in_scenario_window for event in events):
        return "rests only on records outside the declared scenario window"
    if all(_session_noise(event) for event in events):
        return "rests only on logon-session records for non-person identities"
    if all(event.evidence_id in neutral_ids or not event.in_scenario_window or _session_noise(event)
           for event in events):
        return "rests only on out-of-scope records"
    return None


def align_claim(claim: Claim, stages: tuple[Stage, ...], neutral_ids: frozenset[str], store: EventStore) -> ClaimAlignment:
    cited = set(claim.evidence_ids)
    matched = tuple(stage.stage_id for stage in stages if cited & set(stage.evidence_ids))
    if matched:
        return ClaimAlignment(claim.claim_id, "aligned", matched, "cites records the key attributes to a stage")
    events = []
    for evidence_id in claim.evidence_ids:
        result = store.lookup(evidence_id)
        if result.event is None:
            return ClaimAlignment(claim.claim_id, "unaligned", (), f"cites {evidence_id}, which does not resolve")
        events.append(result.event)
    reason = _why_neutral(events, neutral_ids) if events else None
    if reason:
        return ClaimAlignment(claim.claim_id, "neutral", (), reason)
    return ClaimAlignment(claim.claim_id, "unaligned", (), "cites records no ground-truth stage attributes activity to")
