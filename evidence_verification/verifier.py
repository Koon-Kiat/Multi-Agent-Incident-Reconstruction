"""The deterministic evidence verifier: the connection point the orchestrator loads.

``make_verifier`` returns an object with ``metadata()`` and ``verify(reconstruction, store)``,
the interface the Incident Reconstruction Orchestrator defines. It receives the claims and
read-only corpus access and nothing else: no orchestration trace, agent reasoning, detection
label or answer key. It resolves every reference through the store itself, so it never trusts an
identifier, timestamp or entity a claim supplies.

The verdict comes from code, not from a model. :class:`~evidence_verification.agent.AgentVerifier`
adds an independently prompted model on top, but that layer can only *lower* a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from event_processing.query import EventStore
from incident_reconstruction.claims import Claim, Reconstruction
from incident_reconstruction.verification import VerificationDecision

from . import checks as C

VERIFIER_VERSION = "1"
_ORDER = {"reject": 0, "insufficient": 1, "partial": 2}


@dataclass(frozen=True)
class ClaimAssessment:
    """Everything the checks established about one claim, before any model is consulted."""

    claim: Claim
    checks: tuple[C.Check, ...]
    verdict: str
    evidence: C.ClaimEvidence

    @property
    def failed(self) -> tuple[C.Check, ...]:
        return tuple(sorted((c for c in self.checks if c.status == "fail"), key=lambda c: _ORDER[c.grade]))

    @property
    def conflicts(self) -> tuple[str, ...]:
        return tuple(f"{c.conflict_type}: {c.detail}" for c in self.failed)

    @property
    def checked_evidence_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*self.claim.evidence_ids, *self.claim.context_evidence_ids)))

    @property
    def reason(self) -> str:
        if not self.failed:
            applied = sum(1 for c in self.checks if c.status == "pass")
            skipped = sum(1 for c in self.checks if c.status == "not_applicable")
            note = f"; {skipped} not applicable" if skipped else ""
            return (f"All {applied} applicable checks passed{note}: every referenced record exists in the claim's "
                    "scenario and the claim's times, entities, stated event types and mapped techniques agree "
                    "with those records.")
        lead = {"rejected": "Rejected", "unverified": "Unverified", "partially_supported": "Partially supported"}[
            self.verdict]
        return f"{lead}: " + " | ".join(c.detail for c in self.failed[:3]) + (
            f" (+{len(self.failed) - 3} more)" if len(self.failed) > 3 else "")

    def decision(self) -> VerificationDecision:
        return VerificationDecision(claim_id=self.claim.claim_id, verdict=self.verdict, reason=self.reason,
                                    checked_evidence_ids=self.checked_evidence_ids, conflicts=self.conflicts)


def assess(reconstruction: Reconstruction, store: EventStore) -> list[ClaimAssessment]:
    """Run every deterministic check over every claim of one scenario's reconstruction."""
    gathered = {claim.claim_id: C.gather(claim, reconstruction.scenario_id, store) for claim in reconstruction.claims}
    order = C.order_checks(reconstruction, gathered)
    assessments: list[ClaimAssessment] = []
    for claim in reconstruction.claims:
        evidence = gathered[claim.claim_id]
        results: list[C.Check] = [C.resolution_check(evidence)]
        if len(evidence.problems) > 1:
            results.extend(evidence.problems[1:])
        results.extend(C.time_checks(evidence))
        results.extend(C.entity_checks(evidence))
        results.extend(C.text_checks(evidence))
        results.append(C.structure_check(evidence))
        results.extend(C.attack_checks(evidence))
        results.extend(C.link_checks(evidence, gathered))
        results.append(order[claim.claim_id])
        assessments.append(ClaimAssessment(claim, tuple(results), C.verdict_for(results), evidence))
    return assessments


class DeterministicVerifier:
    """Verdicts from recorded events alone."""

    def metadata(self) -> dict:
        return {"verifier": "evidence-verifier", "version": VERIFIER_VERSION, "mode": "deterministic",
                "independent_lookup": True, "model": None,
                "checks": ["reference_resolves", "span_is_valid", "span_endpoints_recorded",
                           "cited_events_inside_span", "entities_recorded", "host_agrees", "text_times_recorded",
                           "text_event_types_recorded", "text_files_recorded", "text_failed_logon_count",
                           "claim_type_structure", "attack_*", "link_*", "timeline_order"]}

    def verify(self, reconstruction: Reconstruction, store: EventStore) -> list[VerificationDecision]:
        return [assessment.decision() for assessment in assess(reconstruction, store)]


def make_verifier() -> DeterministicVerifier:
    """Factory for ``--verifier evidence_verification.verifier:make_verifier``."""
    return DeterministicVerifier()
