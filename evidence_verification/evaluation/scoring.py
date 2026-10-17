"""Scores one configuration's claims for one scenario. Pure functions over claims, stages and verdicts.

Units, fixed in the evaluation protocol before any scored run:

* reconstruction: the ground-truth stage. A stage is *matched* when some claim cites at least one record
  the key attributes to it. Order is scored separately from recall, so a system that finds every stage
  but misorders them differs from one that misses stages.
* evidence support: the claim. The four verdicts stay distinct; none is folded into a single "supported".
* every figure is a raw count with its denominator. Nothing here computes a scenario-level percentage as
  a headline, because three scenarios are too few to estimate one.

A rate is ``None`` when its denominator is zero: undefined, not zero.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from itertools import combinations

from incident_reconstruction.claims import Claim

from .alignment import ClaimAlignment
from .groundtruth import Stage

VERDICTS = ("confirmed", "partially_supported", "unverified", "rejected")
ALIGNMENTS = ("aligned", "neutral", "unaligned")
FABRICATION_PREFIXES = ("unresolved_reference", "invalid_reference", "scenario_mismatch")


def rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


@dataclass
class ReconstructionScore:
    scenario_id: str
    configuration: str
    stages_total: int
    stages_matched: int
    stage_recall: float | None
    mean_stage_coverage: float | None
    claims_total: int
    claims_aligned: int
    claims_neutral: int
    claims_unaligned: int
    claim_precision: float | None
    order_pairs: int
    order_concordant: int
    order_discordant: int
    order_ties: int
    order_accuracy: float | None
    matched_stages: dict[str, list[str]]
    missed_stages: list[str]
    assessment: dict[str, int]
    attack: dict[str, int]
    alignments: list[dict] = field(default_factory=list)


def _technique_hits(stage: Stage, claims: list[Claim]) -> tuple[bool, bool]:
    named = {m.technique_id for claim in claims for m in claim.attack if m.status in ("supported", "tentative")}
    exact = any(t in named for t in stage.techniques)
    parent = any(t.split(".")[0] in {n.split(".")[0] for n in named} for t in stage.techniques)
    return exact, parent


def score_reconstruction(scenario_id: str, configuration: str, claims: tuple[Claim, ...], stages: tuple[Stage, ...],
                         alignments: dict[str, ClaimAlignment]) -> ReconstructionScore:
    by_id = {claim.claim_id: claim for claim in claims}
    matched: dict[str, list[str]] = {}
    coverage: list[float] = []
    first_position: dict[int, int] = {}
    assessment = Counter()
    attack = Counter()
    for stage in stages:
        hits = [claim for claim in claims if set(claim.evidence_ids) & set(stage.evidence_ids)]
        if not hits:
            continue
        matched[stage.stage_id] = [claim.claim_id for claim in hits]
        best = max(len(set(claim.evidence_ids) & set(stage.evidence_ids)) for claim in hits)
        coverage.append(best / len(stage.evidence_ids))
        first_position[stage.order] = min(claim.position for claim in hits)
        flagged = any(claim.assessment == "requires_review" for claim in hits)
        key = ("true_flag" if flagged else "under_call") if stage.label == "malicious" else (
            "over_call" if flagged else "true_benign")
        assessment[key] += 1
        if stage.techniques:
            exact, parent = _technique_hits(stage, hits)
            attack["stages_with_technique"] += 1
            attack["technique_exact"] += exact
            attack["technique_parent"] += parent
    pairs = concordant = discordant = ties = 0
    for first, second in combinations(sorted(first_position), 2):
        pairs += 1
        a, b = first_position[first], first_position[second]
        concordant += a < b
        discordant += a > b
        ties += a == b
    decided = concordant + discordant
    counts = Counter(alignments[claim.claim_id].alignment for claim in claims)
    return ReconstructionScore(
        scenario_id=scenario_id, configuration=configuration,
        stages_total=len(stages), stages_matched=len(matched), stage_recall=rate(len(matched), len(stages)),
        mean_stage_coverage=round(sum(coverage) / len(coverage), 4) if coverage else None,
        claims_total=len(claims), claims_aligned=counts["aligned"], claims_neutral=counts["neutral"],
        claims_unaligned=counts["unaligned"],
        claim_precision=rate(counts["aligned"], counts["aligned"] + counts["unaligned"]),
        order_pairs=pairs, order_concordant=concordant, order_discordant=discordant, order_ties=ties,
        order_accuracy=rate(concordant, decided),
        matched_stages=matched, missed_stages=[s.stage_id for s in stages if s.stage_id not in matched],
        assessment={k: assessment[k] for k in ("true_flag", "under_call", "over_call", "true_benign")},
        attack={k: attack[k] for k in ("stages_with_technique", "technique_exact", "technique_parent")},
        alignments=[{"claim_id": c.claim_id, "alignment": alignments[c.claim_id].alignment,
                     "stage_ids": list(alignments[c.claim_id].stage_ids), "reason": alignments[c.claim_id].reason}
                    for c in claims],
    )


@dataclass
class SupportScore:
    scenario_id: str
    configuration: str
    source: str
    claims: int
    verdicts: dict[str, int]
    confirmed_rate: float | None
    fabricated_reference_claims: int
    by_alignment: dict[str, dict[str, int]]


def summarise_support(scenario_id: str, configuration: str, source: str, verdicts: dict[str, str],
                      conflicts: dict[str, tuple[str, ...]], alignments: dict[str, ClaimAlignment]) -> SupportScore:
    tally = Counter(verdicts.values())
    fabricated = sum(any(c.startswith(FABRICATION_PREFIXES) for c in conflicts.get(claim_id, ()))
                     for claim_id in verdicts)
    cross: dict[str, dict[str, int]] = {a: {v: 0 for v in VERDICTS} for a in ALIGNMENTS}
    for claim_id, verdict in verdicts.items():
        cross[alignments[claim_id].alignment][verdict] += 1
    return SupportScore(scenario_id, configuration, source, len(verdicts), {v: tally[v] for v in VERDICTS},
                        rate(tally["confirmed"], len(verdicts)), fabricated, cross)


def sum_counts(items: list[dict[str, int]]) -> dict[str, int]:
    total: Counter = Counter()
    for item in items:
        total.update(item)
    return dict(total)
