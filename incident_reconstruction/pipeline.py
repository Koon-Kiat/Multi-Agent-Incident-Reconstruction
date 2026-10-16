"""Run one evaluation configuration end to end with consistent timing points.

========================  ============================================================
mode                      phases (each timed separately, in this order)
========================  ============================================================
``single-agent`` (B)      detection -> single_agent
``multi-agent`` (C)       detection -> investigation -> reconstruction
``full`` (D)              detection -> investigation -> reconstruction -> verification
========================  ============================================================

Every mode starts its clock immediately before the conventional triggers are read and stops it
after its last phase, on the same corpus, triggers, providers, limits and local model, so the
latency columns of a comparison measure the same span. Configuration A (rules only) is the Event
Processing & Detection Engine's own baseline and is not run here.

Outputs per scenario go to ``<out>/<mode>/``: ``<scenario>.pipeline.json`` (this summary),
``<scenario>.reconstruction.json``, and, where produced, ``<scenario>.orchestration.json`` and
``<scenario>.verification.json``.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from event_processing.query import EventStore

from .claims import Mode, Reconstruction
from .models import OrchestrationRun
from .orchestrator import IncidentOrchestrator
from .reconstruction import reconstruct
from .single_agent import SingleAgentInvestigator
from .verification import VerificationReport, Verifier, run_verification

PIPELINE_SCHEMA_VERSION = "pipeline-run-v1"
MODES: tuple[Mode, ...] = ("single-agent", "multi-agent", "full")
Phase = Literal["detection", "investigation", "reconstruction", "single_agent", "verification"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PhaseTiming(Model):
    phase: Phase
    seconds: float = Field(ge=0)


class PipelineSummary(Model):
    schema_version: Literal["pipeline-run-v1"] = PIPELINE_SCHEMA_VERSION
    mode: Mode
    scenario_id: str
    corpus_manifest_sha256: str
    started_utc: str
    finished_utc: str
    latency_seconds: float = Field(ge=0)
    phases: tuple[PhaseTiming, ...]
    llm: dict[str, JsonValue]
    detections: int = Field(ge=0)
    claims: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    verdicts: dict[str, int] | None = None
    artifacts: tuple[str, ...] = ()


@dataclass(frozen=True)
class PipelineOutput:
    summary: PipelineSummary
    reconstruction: Reconstruction
    orchestration: OrchestrationRun | None = None
    verification: VerificationReport | None = None

    def write(self, out_dir: Path | str) -> tuple[Path, ...]:
        directory = Path(out_dir) / self.summary.mode
        directory.mkdir(parents=True, exist_ok=True)
        scenario = self.summary.scenario_id
        documents = {"reconstruction": self.reconstruction, "orchestration": self.orchestration,
                     "verification": self.verification}
        written = []
        for kind, document in documents.items():
            if document is not None:
                written.append(_write(directory / f"{scenario}.{kind}.json", document))
        artifacts = tuple(path.name for path in written)
        summary = self.summary.model_copy(update={"artifacts": artifacts})
        written.append(_write(directory / f"{scenario}.pipeline.json", summary))
        return tuple(written)


class Pipeline:
    """One configured system; ``run(mode, scenario)`` executes any of the three LLM configurations."""

    def __init__(self, store: EventStore, engine, *, orchestrator: IncidentOrchestrator | None = None,
                 reconstruction_llm=None, single_agent: SingleAgentInvestigator | None = None,
                 verifier: Verifier | None = None, llm_metadata: dict | None = None) -> None:
        self._store = store
        self._engine = engine
        self._orchestrator = orchestrator
        self._reconstruction_llm = reconstruction_llm
        self._single_agent = single_agent
        self._verifier = verifier
        self._llm_metadata = dict(llm_metadata or {})

    def run(self, mode: Mode, scenario_id: str) -> PipelineOutput:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}; expected one of {MODES}")
        if mode == "single-agent" and self._single_agent is None:
            raise ValueError("single-agent mode needs a SingleAgentInvestigator")
        if mode != "single-agent" and self._orchestrator is None:
            raise ValueError(f"{mode} mode needs an IncidentOrchestrator")
        if mode == "full" and self._verifier is None:
            raise ValueError("full mode needs a verifier")
        if scenario_id not in self._store.scenario_ids:
            raise ValueError(f"scenario {scenario_id!r} is not in the corpus")

        started_utc, started = _now_utc(), time.perf_counter()
        phases: list[PhaseTiming] = []

        def timed(phase: Phase, work):
            begin = time.perf_counter()
            value = work()
            phases.append(PhaseTiming(phase=phase, seconds=round(time.perf_counter() - begin, 3)))
            return value

        detections = timed("detection", lambda: self._engine.triggers_for(scenario_id))
        orchestration = verification = None
        if mode == "single-agent":
            result = timed("single_agent", lambda: self._single_agent.investigate(
                scenario_id, detections, corpus_manifest_sha256=self._engine.corpus_manifest_sha256))
            model_calls = result.model_calls
        else:
            orchestration = timed("investigation", lambda: self._orchestrator.run(scenario_id, detections))
            result = timed("reconstruction", lambda: reconstruct(orchestration, self._store,
                                                                 self._reconstruction_llm, mode=mode))
            model_calls = result.model_calls + sum(task.result.metadata.model_calls for task in orchestration.tasks
                                                   if task.result is not None)
            if mode == "full":
                verification = timed("verification", lambda: run_verification(self._verifier, result, self._store))

        summary = PipelineSummary(
            mode=mode,
            scenario_id=scenario_id,
            corpus_manifest_sha256=self._engine.corpus_manifest_sha256,
            started_utc=started_utc,
            finished_utc=_now_utc(),
            latency_seconds=round(time.perf_counter() - started, 3),
            phases=tuple(phases),
            llm=self._llm_metadata,
            detections=len(detections),
            claims=len(result.claims),
            model_calls=model_calls,
            verdicts=dict(Counter(d.verdict for d in verification.decisions)) if verification else None,
        )
        return PipelineOutput(summary=summary, reconstruction=result, orchestration=orchestration,
                              verification=verification)


def _write(path: Path, document: BaseModel) -> Path:
    path.write_text(document.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
