"""Run MAIR over a normalised corpus in one evaluation configuration.

Modes: single-agent (configuration B), multi-agent (C: specialist agents + reconstruction, no
verifier) and full (D: C + independent verification). Each scenario writes to <out>/<mode>/:
<scenario>.pipeline.json (timing and counts), <scenario>.reconstruction.json (claims) and, where
produced, <scenario>.orchestration.json and <scenario>.verification.json.

--reconstruct-only (multi-agent/full) re-reads <out>/<mode>/<scenario>.orchestration.json, so
narration and verification can be repeated without dispatching the investigation agents.

Exit codes: 0 complete; 1 written but incomplete (an investigation stayed unresolved, the
single-agent run ended early, or the verifier failed); 2 invalid input or setup; 3 the local
model runtime or verifier could not be prepared.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from authentication_agent.config import Limits, OllamaConfig
from event_processing.detection.engine import DetectionEngine, DetectionError, corpus_manifest_digest
from event_processing.protected_paths import protected_output_component
from event_processing.query import EventStore

from .models import OrchestrationRun, WindowPolicy, default_policies
from .narrative import FakeReconstructionLLM
from .orchestrator import (
    DEFAULT_MAX_SPLIT_DEPTH,
    DEFAULT_MODEL_TOOL_CALLS,
    DEFAULT_TASK_TIMEOUT_SECONDS,
    IncidentOrchestrator,
    OrchestrationError,
    corpus_investigators,
)
from .pipeline import MODES, Pipeline, PipelineOutput
from .reconstruction import reconstruct
from .report import write_reports
from .single_agent import DEFAULT_TOOL_CALLS, FakeSingleAgentLLM, SingleAgentInvestigator
from .verification import PendingVerifier, load_verifier, run_verification


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="incident_reconstruction", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True, help="normalised corpus directory")
    parser.add_argument("--mode", choices=MODES, default="multi-agent", help="evaluation configuration (default multi-agent)")
    parser.add_argument("--scenario", action="append", help="scenario to run (repeatable); default: all")
    parser.add_argument("--llm", choices=("fake", "ollama"), required=True,
                        help="'ollama' for real local inference; 'fake' for deterministic plumbing checks")
    parser.add_argument("--model", default="qwen3:8b", help="installed local Ollama model (default qwen3:8b)")
    parser.add_argument("--num-ctx", type=int, default=8192)
    parser.add_argument("--out", type=Path, help="output root; files go to <out>/<mode>/")
    parser.add_argument("--plan-only", action="store_true", help="print the multi-agent investigation plan and exit")
    parser.add_argument("--reconstruct-only", action="store_true",
                        help="multi-agent/full: reuse <out>/<mode>/<scenario>.orchestration.json")
    parser.add_argument("--verifier", help="full mode: package.module:factory; default marks every claim unverified")
    parser.add_argument("--authentication-context", type=int, default=60,
                        help="seconds of context around each authentication trigger (default 60)")
    parser.add_argument("--endpoint-context", type=int, default=15,
                        help="seconds of context around each endpoint trigger (default 15)")
    parser.add_argument("--max-split-depth", type=int, default=DEFAULT_MAX_SPLIT_DEPTH,
                        help="times a window may be halved after exceeding an agent's context")
    parser.add_argument("--model-tool-calls", type=int, default=DEFAULT_MODEL_TOOL_CALLS,
                        help="tool calls left to each specialist after the initial query and trigger seeds")
    parser.add_argument("--single-agent-tool-calls", type=int, default=DEFAULT_TOOL_CALLS,
                        help=f"tool budget of the single-agent baseline (default {DEFAULT_TOOL_CALLS})")
    parser.add_argument("--no-finish-guard", action="store_true",
                        help="let specialist agents' models keep choosing tools after a repeat or with no budget left")
    parser.add_argument("--task-timeout", type=float, default=DEFAULT_TASK_TIMEOUT_SECONDS)
    parser.add_argument("--run-timeout", type=float, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.plan_only and args.out is None:
        return _fail(2, "--out is required unless --plan-only is given")
    if args.out is not None and protected_output_component(args.out) is not None:
        return _fail(2, f"--out {args.out} is inside a protected evidence tree")
    if args.reconstruct_only and args.mode == "single-agent":
        return _fail(2, "--reconstruct-only applies to multi-agent and full modes")
    if args.verifier and args.mode != "full":
        return _fail(2, "--verifier applies to full mode only")

    try:
        store = EventStore.load(args.corpus)
        engine = DetectionEngine(store, corpus_manifest_sha256=corpus_manifest_digest(args.corpus))
        policies = _policies(args)
        limits = Limits()
        scenarios = args.scenario or list(store.scenario_ids)
        unknown = sorted(set(scenarios) - set(store.scenario_ids))
        if unknown:
            raise ValueError(f"unknown scenarios {unknown}; known: {list(store.scenario_ids)}")
    except (OSError, ValueError, DetectionError) as error:
        return _fail(2, f"cannot load corpus: {error}")

    if args.plan_only:
        orchestrator = IncidentOrchestrator(store, engine, {}, policies=policies, limits=limits)
        plans = [plan.model_dump(mode="json") for scenario in scenarios for plan in orchestrator.plan(scenario)]
        print(json.dumps(plans, indent=2, ensure_ascii=False))
        return 0

    try:
        models = _models(args)
        verifier = (load_verifier(args.verifier) if args.verifier else PendingVerifier()) if args.mode == "full" else None
    except Exception as error:  # Preflight: connection, missing weights, invalid configuration or verifier import.
        return _fail(3, f"setup failed ({type(error).__name__}): {error}")
    authentication_llm, endpoint_llm, reconstruction_llm, single_llm, llm_metadata = models

    if args.reconstruct_only:
        return _reconstruct_only(args, scenarios, store, reconstruction_llm, verifier)

    try:
        orchestrator = None
        if args.mode != "single-agent":
            investigators = corpus_investigators(store, authentication_llm=authentication_llm, endpoint_llm=endpoint_llm,
                                                 limits=limits, model_tool_calls=args.model_tool_calls,
                                                 finish_guard=not args.no_finish_guard)
            orchestrator = IncidentOrchestrator(store, engine, investigators, policies=policies, limits=limits,
                                                llm_metadata=llm_metadata, task_timeout_seconds=args.task_timeout,
                                                run_timeout_seconds=args.run_timeout,
                                                max_split_depth=args.max_split_depth)
        single_agent = (SingleAgentInvestigator(store, single_llm, limits=limits, tool_calls=args.single_agent_tool_calls)
                        if args.mode == "single-agent" else None)
    except (OrchestrationError, ValueError) as error:
        return _fail(2, str(error))
    pipeline = Pipeline(store, engine, orchestrator=orchestrator, reconstruction_llm=reconstruction_llm,
                        single_agent=single_agent, verifier=verifier, llm_metadata=llm_metadata)

    incomplete = False
    for scenario in scenarios:
        output = pipeline.run(args.mode, scenario)
        output.write(args.out)
        incomplete |= _report(output, args.out)
    print(f"reports -> {write_reports(args.out, store)[-1]}")
    return 1 if incomplete else 0


def _reconstruct_only(args, scenarios, store, reconstruction_llm, verifier) -> int:
    directory = args.out / args.mode
    incomplete = False
    for scenario in scenarios:
        source = directory / f"{scenario}.orchestration.json"
        try:
            run = OrchestrationRun.model_validate_json(source.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            return _fail(2, f"cannot read {source}: {error}")
        result = reconstruct(run, store, reconstruction_llm, mode=args.mode)
        verification = run_verification(verifier, result, store) if verifier else None
        for kind, document in (("reconstruction", result), ("verification", verification)):
            if document is not None:
                (directory / f"{scenario}.{kind}.json").write_text(document.model_dump_json(indent=2) + "\n",
                                                                   encoding="utf-8", newline="\n")
        incomplete |= bool(verification and verification.integrity_notes)
        print(f"{scenario}: {len(result.claims)} claims re-narrated -> {directory}")
    print(f"reports -> {write_reports(args.out, store)[-1]}")
    return 1 if incomplete else 0


def _report(output: PipelineOutput, out: Path) -> bool:
    summary, run = output.summary, output.orchestration
    phases = ", ".join(f"{p.phase} {p.seconds}s" for p in summary.phases)
    sources = [claim.narrative_source for claim in output.reconstruction.claims]
    line = (f"{summary.scenario_id} [{summary.mode}]: {summary.detections} detections, {summary.claims} claims "
            f"({sources.count('template')} template), {summary.model_calls} model calls, {summary.latency_seconds}s "
            f"({phases})")
    if run is not None:
        line += f"; {len(run.tasks)} tasks, {len(run.unresolved_task_ids())} unresolved"
    if summary.verdicts is not None:
        line += f"; verdicts {summary.verdicts}"
    print(f"{line} -> {out / summary.mode}")
    incomplete = bool(run and run.unresolved_task_ids())
    incomplete |= bool(output.verification and output.verification.integrity_notes)
    incomplete |= summary.mode == "single-agent" and any("ended without" in gap
                                                          for gap in output.reconstruction.investigation_gaps)
    return incomplete


def _policies(args):
    defaults = default_policies()
    return {
        "authentication": WindowPolicy.model_validate({**defaults["authentication"].model_dump(),
            "context_before_seconds": args.authentication_context, "context_after_seconds": args.authentication_context}),
        "endpoint": WindowPolicy.model_validate({**defaults["endpoint"].model_dump(),
            "context_before_seconds": args.endpoint_context, "context_after_seconds": args.endpoint_context}),
    }


def _models(args):
    """(authentication, endpoint, reconstruction, single-agent, metadata); one model for every role."""
    if args.llm == "fake":
        from authentication_agent.llm.fake import FakeLLM as AuthenticationFake
        from endpoint_agent.llm.fake import FakeLLM as EndpointFake

        llms = (AuthenticationFake(), EndpointFake(), FakeReconstructionLLM(), FakeSingleAgentLLM())
        roles = ("authentication", "endpoint", "reconstruction", "single_agent")
        return (*llms, {role: llm.metadata() for role, llm in zip(roles, llms)})

    from authentication_agent.investigate_corpus import local_model_runtime
    from authentication_agent.llm.ollama_client import OllamaClient

    config = OllamaConfig(model=args.model, num_ctx=args.num_ctx, think=False, temperature=0.0, seed=0)
    runtime = local_model_runtime(config)
    return (OllamaClient(config), OllamaClient(config), OllamaClient(config), OllamaClient(config),
            {role: runtime for role in ("authentication", "endpoint", "reconstruction", "single_agent")})


def _fail(code: int, message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
