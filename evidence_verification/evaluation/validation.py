"""Validate comparison inputs before a result can be described as a scored run."""

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from event_processing.provenance import implementation_digest, json_digest
from incident_reconstruction.pipeline import PipelineSummary
from incident_reconstruction.claims import Reconstruction
from incident_reconstruction.verification import VerificationReport
from incident_reconstruction.models import OrchestrationRun


class EvaluationError(ValueError):
    pass


def load(path, model):
    try:
        return model.model_validate_json(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, ValidationError) as error:
        raise EvaluationError(f"invalid {path.name}: {type(error).__name__}") from error


def profile(value, *, allow_fake, where):
    if not isinstance(value, dict):
        raise EvaluationError(f"{where}: missing model metadata")
    runtime = value.get("runtime")
    if runtime != "ollama":
        if not allow_fake:
            raise EvaluationError(f"{where}: non-Ollama/fake runtime is plumbing only; use --allow-fake for inspection")
        return None
    config = value.get("configuration", value)
    if not isinstance(config,dict):
        raise EvaluationError(f"{where}: invalid model configuration")
    required = ("model", "temperature", "seed", "num_ctx", "think")
    if any(k not in config for k in required):
        raise EvaluationError(f"{where}: incomplete model configuration")
    if (not isinstance(value.get("digest"),str) or len(value["digest"]) != 64
            or not isinstance(value.get("version"),str) or not value["version"]):
        raise EvaluationError(f"{where}: model digest and runtime version are required")
    if (not isinstance(config["model"],str) or config["model"] != value.get("model")
            or type(config["num_ctx"]) is not int or config["num_ctx"] <= 0
            or type(config["seed"]) is not int or config["think"] is not False
            or type(config["temperature"]) not in (int,float) or config["temperature"] != 0):
        raise EvaluationError(f"{where}: invalid shared local model profile")
    try:
        int(value["digest"],16)
    except ValueError as error:
        raise EvaluationError(f"{where}: invalid model digest") from error
    return (runtime,value["model"],value["digest"].lower(),value["version"],
            *(config[k] for k in required[1:]))


def validate_run(base: Path, mode: str, scenario: str, digest: str, *, allow_fake=False,
                 allow_partial=False, expected_profile=None):
    rec = load(Path(f"{base}.reconstruction.json"), Reconstruction)
    pipeline = load(Path(f"{base}.pipeline.json"), PipelineSummary)
    for item in (rec,pipeline):
        if item.mode != mode or item.scenario_id != scenario or item.corpus_manifest_sha256 != digest:
            raise EvaluationError(f"{mode}/{scenario}: mode, scenario or corpus revision mismatch")
    if pipeline.claims != len(rec.claims):
        raise EvaluationError(f"{mode}/{scenario}: pipeline claim count mismatch")
    if pipeline.implementation_sha256 != implementation_digest():
        raise EvaluationError(f"{mode}/{scenario}: stale or missing implementation fingerprint; generate a labelled current-code run")
    if not pipeline.detection_sha256:
        raise EvaluationError(f"{mode}/{scenario}: missing detection fingerprint")
    required = [f"{scenario}.reconstruction.json"]
    if mode != "single-agent":
        required.append(f"{scenario}.orchestration.json")
    if mode == "full":
        required.append(f"{scenario}.verification.json")
    for filename in required:
        path = base.parent/filename
        if (filename not in pipeline.artifacts or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != pipeline.artifact_sha256.get(filename)):
            raise EvaluationError(f"{mode}/{scenario}: stale/missing artifact {filename}")
    clients = [rec.llm]
    if mode != "single-agent":
        orchestration = load(Path(f"{base}.orchestration.json"),OrchestrationRun)
        if (orchestration.scenario_id != scenario or orchestration.corpus_manifest_sha256 != digest
                or rec.orchestration_started_utc != orchestration.started_utc
                or json_digest([d.model_dump(mode="json") for d in orchestration.detections]) != pipeline.detection_sha256):
            raise EvaluationError(f"{mode}/{scenario}: orchestration does not belong to this reconstruction")
        clients += [task.result.metadata.llm for task in orchestration.tasks if task.result is not None]
    roles = ("single_agent",) if mode == "single-agent" else ("authentication","endpoint","reconstruction")
    models = [(role,pipeline.llm.get(role)) for role in roles]
    report = None
    if mode == "full":
        report = load(Path(f"{base}.verification.json"), VerificationReport)
        if report.scenario_id != scenario or report.reconstruction_sha256 != json_digest(rec.model_dump(mode="json")):
            raise EvaluationError(f"{mode}/{scenario}: verification does not belong to this reconstruction")
        if len(report.decisions)!=len(rec.claims) or set(report.verdicts()) != {c.claim_id for c in rec.claims}:
            raise EvaluationError(f"{mode}/{scenario}: verification claim set mismatch")
        if report.verifier.get("mode") != "deterministic_and_agent":
            raise EvaluationError(f"{mode}/{scenario}: independent model verifier is required for configuration D")
        models.append(("verifier",report.verifier.get("model")))
        for decision in report.decisions:
            claim = next(c for c in rec.claims if c.claim_id == decision.claim_id)
            if set(decision.checked_evidence_ids) != set(claim.context_evidence_ids):
                raise EvaluationError(f"{mode}/{scenario}: checked references differ from claim context")
    fake = False
    for role,metadata in models:
        current = profile(metadata,allow_fake=allow_fake,where=f"{mode}/{scenario}/{role}")
        fake |= current is None
        if current is not None:
            if expected_profile is not None and current != expected_profile:
                raise EvaluationError(f"{mode}/{scenario}: models or decoding settings differ across roles/configurations")
            expected_profile = current
    for client in clients:
        if not isinstance(client,dict) or client.get("runtime") != "ollama":
            if not allow_fake:
                raise EvaluationError(f"{mode}/{scenario}: fake/missing model in saved reconstruction or agent output")
            fake = True
            continue
        config = client.get("configuration",client)
        if not isinstance(config,dict):
            raise EvaluationError(f"{mode}/{scenario}: invalid actual model configuration")
        if expected_profile is not None and (
                config.get("model") != expected_profile[1]
                or tuple(config.get(k) for k in ("temperature","seed","num_ctx","think")) != expected_profile[4:]):
            raise EvaluationError(f"{mode}/{scenario}: actual agent/reconstruction settings differ from the declared profile")
    return rec,pipeline.model_dump(mode="json"),report,fake,expected_profile
