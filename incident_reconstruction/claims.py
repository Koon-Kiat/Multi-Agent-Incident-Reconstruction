"""Reconstructed claims: the timeline handed to Evidence Verification & Evaluation.

Contract (``reconstruction-v1``)
--------------------------------

* One :class:`Claim` per reconstructed stage, ordered by ``position`` (1-based, by first event
  time). ``claim_id`` is ``<scenario>-CLM-<position:02d>`` and is stable for a given orchestration
  run, so verification decisions can be joined back to claims.
* ``evidence_ids`` are the records the claim text relies on; they are always a subset of
  ``context_evidence_ids``, the records the stage was built from. Both resolve through the
  corpus ``EventStore``. ``detection_ids`` and ``supporting_finding_ids`` name the detection and
  agent outputs the stage came from.
* ``attack`` mappings are tentative by construction: each carries a status, a justification and
  the evidence it rests on (see :mod:`incident_reconstruction.attack`).
* ``assessment`` is the reconstruction's own reading of the stage, not a verdict.
  ``verification_status`` is always ``not_verified`` here; only Evidence Verification &
  Evaluation decides support, and its decisions are displayed alongside, never written into, a
  claim.
* ``narrative_source`` is ``model`` when the local model's reply passed every host check, and
  ``template`` when the deterministic text was used instead; ``uncertainty`` then says why.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from event_processing.ids import SCENARIO_ID_RE

from .attack import MappingStatus

RECONSTRUCTION_SCHEMA_VERSION = "reconstruction-v1"

Assessment = Literal["requires_review", "benign_possible", "insufficient_evidence"]
# single-agent: evaluation configuration B; multi-agent: C (no verifier); full: D (with verifier).
Mode = Literal["single-agent", "multi-agent", "full"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AttackMapping(Model):
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    status: MappingStatus
    justification: str
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class ClaimEntities(Model):
    accounts: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    processes: tuple[str, ...] = ()
    process_guids: tuple[str, ...] = ()
    files: tuple[str, ...] = ()


class ClaimLink(Model):
    claim_id: str
    reason: str


class Claim(Model):
    claim_id: str
    position: int = Field(ge=1)
    claim_type: str
    claim_text: str = Field(min_length=1, max_length=1000)
    rationale: str = Field(min_length=1, max_length=2000)
    assessment: Assessment
    first_utc: str
    last_utc: str
    entities: ClaimEntities
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    context_evidence_ids: tuple[str, ...] = Field(min_length=1)
    # Empty only for single-agent baseline claims that cite no detection trigger.
    detection_ids: tuple[str, ...] = ()
    supporting_finding_ids: tuple[str, ...] = ()
    attack: tuple[AttackMapping, ...] = ()
    related_claims: tuple[ClaimLink, ...] = ()
    uncertainty: tuple[str, ...] = ()
    narrative_source: Literal["model", "template"]
    verification_status: Literal["not_verified"] = "not_verified"

    @model_validator(mode="after")
    def evidence_is_scoped(self) -> Claim:
        context = set(self.context_evidence_ids)
        if not set(self.evidence_ids) <= context:
            raise ValueError("a claim may only cite evidence from its own stage")
        for mapping in self.attack:
            if not set(mapping.evidence_ids) <= context:
                raise ValueError("an ATT&CK mapping may only rest on the claim's stage evidence")
        return self


class Reconstruction(Model):
    schema_version: Literal["reconstruction-v1"] = RECONSTRUCTION_SCHEMA_VERSION
    mode: Mode = "multi-agent"
    prompt_version: str
    scenario_id: str = Field(pattern=SCENARIO_ID_RE.pattern)
    corpus_manifest_sha256: str
    # The orchestration run this timeline was built from; None for the single-agent baseline.
    orchestration_started_utc: str | None = None
    llm: dict[str, JsonValue]
    claims: tuple[Claim, ...]
    unlinked_findings: dict[str, int]
    investigation_gaps: tuple[str, ...]
    model_calls: int = Field(ge=0)
    latency_seconds: float = Field(ge=0)

    @model_validator(mode="after")
    def claims_are_ordered_and_linked(self) -> Reconstruction:
        if [claim.position for claim in self.claims] != list(range(1, len(self.claims) + 1)):
            raise ValueError("claim positions must run 1..n in order")
        ids = {claim.claim_id for claim in self.claims}
        if len(ids) != len(self.claims):
            raise ValueError("claim_id values must be unique")
        for claim in self.claims:
            if any(link.claim_id not in ids or link.claim_id == claim.claim_id for link in claim.related_claims):
                raise ValueError(f"claim {claim.claim_id} links to an unknown claim or itself")
        return self
