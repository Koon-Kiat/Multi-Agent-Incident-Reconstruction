"""Reconstruction Agent: turn one orchestration run into an ordered, evidence-referenced timeline.

``reconstruct`` builds stages deterministically (:mod:`incident_reconstruction.stages`), asks the
local model to narrate each one (:mod:`incident_reconstruction.narrative`), attaches ATT&CK
mappings (:mod:`incident_reconstruction.attack`) and returns a :class:`Reconstruction` whose
claims all carry ``verification_status="not_verified"``. The corpus is read only through
``EventStore``; no answer key or verifier output is consulted.
"""

from __future__ import annotations

import time

from authentication_agent.config import Limits
from event_processing.query import EventStore
from event_processing.timeutil import ticks_to_iso

from .attack import describe, rule_strength, status_for
from .claims import AttackMapping, Claim, Mode, Reconstruction
from .models import OrchestrationRun
from .narrative import PROMPT_VERSION, Narrative, narrate
from .stages import Stage, build_stages, unlinked_counts

RECONSTRUCTION_LIMITS = Limits(model_timeout_seconds=180, max_output_tokens=1024)


def reconstruct(run: OrchestrationRun, store: EventStore, llm=None, limits: Limits | None = None, *,
                mode: Mode = "multi-agent") -> Reconstruction:
    started = time.perf_counter()
    limits = limits or RECONSTRUCTION_LIMITS
    stages = build_stages(run, store)
    by_id = {stage.claim_id: stage for stage in stages}
    claims, model_calls = [], 0
    for stage in stages:
        narrative, called = narrate(stage, by_id, llm, limits)
        model_calls += called
        claims.append(_claim(stage, narrative))
    return Reconstruction(
        mode=mode,
        prompt_version=PROMPT_VERSION,
        scenario_id=run.scenario_id,
        corpus_manifest_sha256=run.corpus_manifest_sha256,
        orchestration_started_utc=run.started_utc,
        llm=llm.metadata() if llm is not None else {"runtime": "none"},
        claims=tuple(claims),
        unlinked_findings=unlinked_counts(run, stages),
        investigation_gaps=_run_gaps(run),
        model_calls=model_calls,
        latency_seconds=round(time.perf_counter() - started, 3),
    )


def _claim(stage: Stage, narrative: Narrative) -> Claim:
    insufficient = narrative.assessment == "insufficient_evidence"
    attack = []
    for technique_id in stage.candidate_techniques:
        rules = [d.rule_id for d in stage.detections]
        strength, justification = rule_strength(rules[0], technique_id)
        technique = describe(technique_id)
        attack.append(AttackMapping(
            technique_id=technique_id, name=technique.name, tactics=technique.tactics,
            status=status_for(strength, technique_id in narrative.technique_ids, insufficient),
            justification=justification, evidence_ids=stage.trigger_ids,
        ))
    entities = stage.entities()
    return Claim(
        claim_id=stage.claim_id,
        position=stage.position,
        claim_type=stage.claim_type,
        claim_text=narrative.claim_text,
        rationale=narrative.rationale,
        assessment=narrative.assessment,
        first_utc=ticks_to_iso(stage.first_ticks),
        last_utc=ticks_to_iso(stage.last_ticks),
        entities=entities,
        evidence_ids=narrative.cited_evidence_ids,
        context_evidence_ids=stage.context_evidence_ids,
        detection_ids=tuple(d.detection_id for d in stage.detections),
        supporting_finding_ids=tuple(f.finding_id for f in stage.findings),
        attack=tuple(attack),
        related_claims=tuple(stage.links),
        uncertainty=(*narrative.uncertainty, *stage.gaps),
        narrative_source=narrative.source,
    )


def _run_gaps(run: OrchestrationRun) -> tuple[str, ...]:
    gaps = [f"detection {d} had no completed agent investigation" for d in run.uninvestigated_detection_ids()]
    gaps += [f"task {t} did not complete" for t in run.unresolved_task_ids()]
    return tuple(gaps)
