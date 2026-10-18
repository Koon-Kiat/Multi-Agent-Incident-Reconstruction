"""Scores every written run against the key and compares the four configurations.

Reads runs that already exist (``<runs>/<mode>/<scenario>.*.json``); it never starts an investigation,
so the key is opened only after an investigation has finished. Every figure is reproducible from the
inputs named in ``results.json``: the corpus digest, the code revision, the protocol hashes and the
verifier's parameters.

Fake-model runs check plumbing only and are refused unless explicitly allowed, and then labelled.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from event_processing.detection.engine import corpus_manifest_digest
from event_processing.query import EventStore
from evidence_verification import checks
from evidence_verification.agent import PROMPT_VERSION
from evidence_verification.verifier import VERIFIER_VERSION, assess
from incident_reconstruction.claims import Reconstruction
from incident_reconstruction.verification import VerificationReport

from .alignment import align_claim
from .detection import score_detections
from .groundtruth import load_ground_truth, load_neutral_evidence
from .scoring import VERDICTS, ALIGNMENTS, score_reconstruction, sum_counts, summarise_support

RESULTS_SCHEMA = "evaluation-results-v1"
MODES = {"single-agent": "B_single_agent", "multi-agent": "C_multi_agent_no_verifier", "full": "D_full_mair"}
PROTOCOL_PUBLIC = "docs/EVALUATION_PROTOCOL.md"
PROTOCOL_PRIVATE = "ground_truth/private/EVALUATION_PROTOCOL_PRIVATE.md"
FROZEN_PATHS = ("evidence_verification", PROTOCOL_PUBLIC)


class EvaluationError(RuntimeError):
    pass


def _sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _git(repo: Path, *args: str) -> str | None:
    try:
        done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def provenance(repo: Path, hardware_note: str) -> dict:
    status = _git(repo, "status", "--porcelain", "--", *FROZEN_PATHS)
    package = repo / "evidence_verification"
    return {
        "git_commit": _git(repo, "rev-parse", "HEAD"),
        "verifier_code_clean": status == "" if status is not None else None,
        "verifier_files_sha256": {str(p.relative_to(repo)).replace("\\", "/"): _sha256(p)
                                  for p in sorted(package.rglob("*.py")) if "tests" not in p.parts},
        "protocol_public_sha256": _sha256(repo / PROTOCOL_PUBLIC),
        "protocol_private_sha256": _sha256(repo / PROTOCOL_PRIVATE),
        "verifier": {"version": VERIFIER_VERSION, "prompt_version": PROMPT_VERSION,
                     "span_tolerance_seconds": checks.SPAN_TOLERANCE_SECONDS},
        "hardware": {"platform": platform.platform(), "processor": platform.processor(),
                     "logical_cpus": os.cpu_count(), "note": hardware_note},
    }


def _load(path: Path, model):
    return model.model_validate_json(path.read_text(encoding="utf-8"))


def _runtimes(pipeline: dict) -> set[str]:
    return {str(v.get("runtime")) for v in (pipeline.get("llm") or {}).values() if isinstance(v, dict)}


def evaluate(*, corpus: Path, runs: Path, ground_truth: Path, out: Path, detections: Path | None = None,
             allow_fake: bool = False, hardware_note: str = "", repo: Path | None = None,
             label: str | None = None) -> dict:
    repo = repo or Path.cwd()
    store = EventStore.load(corpus)
    digest = corpus_manifest_digest(corpus)
    stages_by_scenario = load_ground_truth(ground_truth, store.scenario_ids)
    neutral = load_neutral_evidence(ground_truth)
    out.mkdir(parents=True, exist_ok=True)

    per_run: list[dict] = []
    claim_rows: list[dict] = []
    fake = False
    for mode, configuration in MODES.items():
        for scenario in store.scenario_ids:
            base = runs / mode / scenario
            reconstruction_path = Path(f"{base}.reconstruction.json")
            if not reconstruction_path.is_file():
                per_run.append({"configuration": configuration, "scenario_id": scenario, "status": "missing_run"})
                continue
            reconstruction = _load(reconstruction_path, Reconstruction)
            pipeline = json.loads(Path(f"{base}.pipeline.json").read_text(encoding="utf-8"))
            if reconstruction.corpus_manifest_sha256 != digest:
                raise EvaluationError(f"{mode}/{scenario} was computed from a different corpus revision")
            is_fake = "fake" in _runtimes(pipeline)
            fake |= is_fake
            if is_fake and not allow_fake:
                raise EvaluationError(f"{mode}/{scenario} used a fake model; it checks plumbing only and must not "
                                      "be scored (pass --allow-fake to inspect it, labelled)")
            stages = stages_by_scenario[scenario]
            alignments = {c.claim_id: align_claim(c, stages, neutral.get(scenario, frozenset()), store)
                          for c in reconstruction.claims}
            reconstruction_score = score_reconstruction(scenario, configuration, reconstruction.claims, stages, alignments)

            scoring_pass = assess(reconstruction, store)
            deterministic = {a.claim.claim_id: a.verdict for a in scoring_pass}
            conflicts = {a.claim.claim_id: a.conflicts for a in scoring_pass}
            support = {"scoring_pass": asdict(summarise_support(scenario, configuration, "scoring_pass",
                                                                  deterministic, conflicts, alignments))}
            verification = None
            if mode == "full":
                report = _load(Path(f"{base}.verification.json"), VerificationReport)
                pipeline_conflicts = {d.claim_id: d.conflicts for d in report.decisions}
                support["pipeline"] = asdict(summarise_support(scenario, configuration, "pipeline", report.verdicts(),
                                                               pipeline_conflicts, alignments))
                verification = {
                    "verifier": report.verifier, "integrity_notes": list(report.integrity_notes),
                    "latency_seconds": report.latency_seconds,
                    "changed_by_agent": [
                        {"claim_id": cid, "deterministic": deterministic[cid], "final": verdict,
                         "alignment": alignments[cid].alignment}
                        for cid, verdict in report.verdicts().items() if verdict != deterministic[cid]]}
            for claim in reconstruction.claims:
                cid = claim.claim_id
                claim_rows.append({
                    "configuration": configuration, "scenario_id": scenario, "claim_id": cid,
                    "claim_type": claim.claim_type, "assessment": claim.assessment,
                    "alignment": alignments[cid].alignment, "stage_ids": ";".join(alignments[cid].stage_ids),
                    "verdict_scoring_pass": deterministic[cid],
                    "verdict_pipeline": (verification and {d.claim_id: d.verdict for d in report.decisions}[cid]) or "",
                    "evidence_ids": len(claim.evidence_ids), "narrative_source": claim.narrative_source})
            per_run.append({
                "configuration": configuration, "scenario_id": scenario, "status": "scored",
                "plumbing_only": is_fake, "reconstruction": asdict(reconstruction_score), "support": support,
                "verification": verification,
                "latency": {"total_seconds": pipeline["latency_seconds"], "phases": pipeline["phases"],
                            "model_calls": pipeline["model_calls"], "claims": pipeline["claims"],
                            "llm": pipeline["llm"]},
                "investigation_gaps": list(reconstruction.investigation_gaps)})

    results = {
        "schema_version": RESULTS_SCHEMA, "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scored": not fake, "plumbing_only": fake, "label": label,
        "inputs": {"corpus_manifest_sha256": digest, "runs": str(runs), "scenarios": list(store.scenario_ids)},
        "provenance": provenance(repo, hardware_note),
        "runs": per_run, "totals": _totals(per_run),
    }
    if detections is not None:
        results["configuration_A_rules_only"] = score_detections(corpus, detections, out, stages_by_scenario, neutral, store)

    (out / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    with (out / "claims.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(claim_rows[0]) if claim_rows else ["claim_id"])
        writer.writeheader()
        writer.writerows(claim_rows)
    from .report import render
    (out / "results.md").write_text(render(results), encoding="utf-8")
    return results


def _totals(per_run: list[dict]) -> dict:
    """Per configuration, summed over scenarios: raw counts only."""
    totals: dict[str, dict] = {}
    for configuration in MODES.values():
        scored = [r for r in per_run if r["configuration"] == configuration and r["status"] == "scored"]
        if not scored:
            continue
        rec = [r["reconstruction"] for r in scored]
        entry = {
            "scenarios_scored": len(scored),
            "stages_total": sum(r["stages_total"] for r in rec),
            "stages_matched": sum(r["stages_matched"] for r in rec),
            "claims_total": sum(r["claims_total"] for r in rec),
            "claims_aligned": sum(r["claims_aligned"] for r in rec),
            "claims_neutral": sum(r["claims_neutral"] for r in rec),
            "claims_unaligned": sum(r["claims_unaligned"] for r in rec),
            "order_concordant": sum(r["order_concordant"] for r in rec),
            "order_discordant": sum(r["order_discordant"] for r in rec),
            "order_ties": sum(r["order_ties"] for r in rec),
            "assessment": sum_counts([r["assessment"] for r in rec]),
            "attack": sum_counts([r["attack"] for r in rec]),
            "support_scoring_pass": {v: sum(r["support"]["scoring_pass"]["verdicts"][v] for r in scored) for v in VERDICTS},
            "fabricated_reference_claims": sum(r["support"]["scoring_pass"]["fabricated_reference_claims"] for r in scored),
            "support_by_alignment": {a: {v: sum(r["support"]["scoring_pass"]["by_alignment"][a][v] for r in scored)
                                         for v in VERDICTS} for a in ALIGNMENTS},
            "latency_total_seconds": round(sum(r["latency"]["total_seconds"] for r in scored), 3),
            "model_calls": sum(r["latency"]["model_calls"] for r in scored),
        }
        if configuration == "D_full_mair":
            entry["support_pipeline"] = {v: sum(r["support"]["pipeline"]["verdicts"][v] for r in scored) for v in VERDICTS}
            entry["verifier_vs_key"] = {a: {v: sum(r["support"]["pipeline"]["by_alignment"][a][v] for r in scored)
                                            for v in VERDICTS} for a in ALIGNMENTS}
            entry["claims_changed_by_agent"] = sum(len(r["verification"]["changed_by_agent"]) for r in scored)
            entry["verification_seconds"] = round(sum(next((p["seconds"] for p in r["latency"]["phases"]
                                                            if p["phase"] == "verification"), 0.0) for r in scored), 3)
        totals[configuration] = entry
    return totals
