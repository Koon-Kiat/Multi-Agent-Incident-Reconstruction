"""Connection point for Evidence Verification & Evaluation (full MAIR, configuration D).

This module does not judge claims. It defines what the pipeline hands a verifier and what it
accepts back, and records the decisions **unchanged** in a separate ``verification-report-v1``
document; claims keep ``verification_status="not_verified"`` and the report is displayed beside
them.

Interface
---------

A verifier is any object with ``metadata() -> dict`` and
``verify(reconstruction, store) -> Iterable[VerificationDecision]``. It receives the claims
(text, cited and context evidence IDs, entities, ATT&CK mappings) and read-only corpus access;
it never receives the orchestration trace, agent reasoning or an answer key. Load one with
``--verifier package.module:factory``; ``factory`` is called with no arguments.

Integrity, not judgement: a decision for an unknown claim is set aside, a claim with no decision
gets ``unverified`` with reason ``no_decision_returned``, and a verifier that raises leaves every
claim ``unverified`` with ``verifier_failed:<Type>``. Each such step is listed in
``integrity_notes``. Until the real verifier is connected, :class:`PendingVerifier` marks every
claim ``unverified`` so a full run is executable and never implies support it has not checked.
"""

from __future__ import annotations

import importlib
import time
from collections.abc import Iterable
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from event_processing.query import EventStore

from .claims import Reconstruction

VERIFICATION_SCHEMA_VERSION = "verification-report-v1"
Verdict = Literal["confirmed", "partially_supported", "unverified", "rejected"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class VerificationDecision(Model):
    claim_id: str
    verdict: Verdict
    reason: str = Field(min_length=1)
    checked_evidence_ids: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()


class VerificationReport(Model):
    schema_version: Literal["verification-report-v1"] = VERIFICATION_SCHEMA_VERSION
    scenario_id: str
    verifier: dict[str, JsonValue]
    decisions: tuple[VerificationDecision, ...]
    integrity_notes: tuple[str, ...] = ()
    latency_seconds: float = Field(ge=0)

    @model_validator(mode="after")
    def one_decision_per_claim(self) -> VerificationReport:
        ids = [decision.claim_id for decision in self.decisions]
        if len(ids) != len(set(ids)):
            raise ValueError("a claim may carry only one verification decision")
        return self

    def verdicts(self) -> dict[str, Verdict]:
        return {decision.claim_id: decision.verdict for decision in self.decisions}


class Verifier(Protocol):
    def metadata(self) -> dict: ...

    def verify(self, reconstruction: Reconstruction, store: EventStore) -> Iterable[VerificationDecision]: ...


class PendingVerifier:
    """Placeholder until the independent verifier is connected; it checks nothing."""

    def metadata(self) -> dict:
        return {"verifier": "pending", "note": "independent verifier not connected"}

    def verify(self, reconstruction: Reconstruction, store: EventStore) -> list[VerificationDecision]:
        return [VerificationDecision(claim_id=claim.claim_id, verdict="unverified",
                                     reason="independent verifier not connected") for claim in reconstruction.claims]


def load_verifier(spec: str) -> Verifier:
    """``package.module:factory`` -> the object ``factory()`` returns, checked for the interface."""
    module_name, _, attribute = spec.partition(":")
    if not module_name or not attribute:
        raise ValueError("verifier must be given as package.module:factory")
    verifier = getattr(importlib.import_module(module_name), attribute)()
    if not callable(getattr(verifier, "verify", None)) or not callable(getattr(verifier, "metadata", None)):
        raise ValueError(f"{spec} does not provide verify() and metadata()")
    return verifier


def run_verification(verifier: Verifier, reconstruction: Reconstruction, store: EventStore) -> VerificationReport:
    started = time.perf_counter()
    claim_ids = [claim.claim_id for claim in reconstruction.claims]
    notes: list[str] = []
    try:
        returned = list(verifier.verify(reconstruction, store))
        if not all(isinstance(decision, VerificationDecision) for decision in returned):
            raise TypeError("verify() must return VerificationDecision objects")
    except Exception as error:  # A verifier fault never becomes support; its message is not kept.
        notes.append(f"verifier_failed:{type(error).__name__}")
        returned = [VerificationDecision(claim_id=claim_id, verdict="unverified",
                                         reason=f"verifier_failed:{type(error).__name__}") for claim_id in claim_ids]
    decisions: dict[str, VerificationDecision] = {}
    for decision in returned:
        if decision.claim_id not in claim_ids:
            notes.append(f"decision for unknown claim {decision.claim_id} set aside")
        elif decision.claim_id in decisions:
            notes.append(f"duplicate decision for {decision.claim_id} set aside; the first was kept")
        else:
            decisions[decision.claim_id] = decision
    for claim_id in claim_ids:
        if claim_id not in decisions:
            notes.append(f"no decision returned for {claim_id}")
            decisions[claim_id] = VerificationDecision(claim_id=claim_id, verdict="unverified",
                                                       reason="no_decision_returned")
    try:
        metadata = dict(verifier.metadata())
    except Exception as error:
        metadata = {"verifier": "unknown", "metadata_error": type(error).__name__}
    return VerificationReport(
        scenario_id=reconstruction.scenario_id,
        verifier=metadata,
        decisions=tuple(decisions[claim_id] for claim_id in claim_ids),
        integrity_notes=tuple(notes),
        latency_seconds=round(time.perf_counter() - started, 3),
    )
