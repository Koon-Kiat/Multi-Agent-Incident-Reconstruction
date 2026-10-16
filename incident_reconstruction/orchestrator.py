"""Dispatch planned windows to the investigation agents and collect their structured results.

Contract
--------

* The orchestrator reads the corpus only through :class:`~event_processing.query.EventStore` and
  takes its triggers from :class:`~event_processing.detection.engine.DetectionEngine`. It never
  writes into ``datasets/`` or ``ground_truth/`` and never sees an answer key.
* Agents are called through their published ``investigate`` functions; nothing in an agent is
  reimplemented here. Each call runs in a daemon worker thread with a per-task deadline, because
  the agents are synchronous and a local model call cannot be cancelled from outside. A task that
  overruns is recorded as ``timeout`` and the run moves on; its thread is abandoned, not reused.
* An agent's ``failed`` result is kept as-is. An exception, an overrun, a result of the wrong type
  or for the wrong window is an orchestration outcome with no findings. Detections whose every
  window failed are listed as uninvestigated, never as clean.
* Tasks run one at a time in plan order, so a run against a single local model is reproducible
  and latency per task is not inflated by contention.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from datetime import datetime, timezone

from authentication_agent import RequiredOperations, ToolCall
from authentication_agent import investigate as investigate_authentication
from authentication_agent.config import Limits
from authentication_agent.models import InvestigationRequest as AuthenticationRequest
from authentication_agent.models import InvestigationResult as AuthenticationResult
from endpoint_agent import investigate as investigate_endpoint
from endpoint_agent.models import InvestigationRequest as EndpointRequest
from endpoint_agent.models import InvestigationResult as EndpointResult
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.adapters.endpoint_provider import CorpusEndpointProvider
from event_processing.detection.engine import DetectionEngine
from event_processing.detection.schema import Detection
from event_processing.query import EventStore

from .models import (
    AgentType,
    DetectionCoverage,
    OrchestrationRun,
    PlannedInvestigation,
    TaskOutcome,
    WindowPolicy,
    default_policies,
)
from .routing import plan_investigations, split_plan

AgentResult = AuthenticationResult | EndpointResult
Investigator = Callable[[PlannedInvestigation], AgentResult]
EXPECTED_RESULT: dict[AgentType, type] = {"authentication": AuthenticationResult, "endpoint": EndpointResult}

DEFAULT_MODEL_TOOL_CALLS = 7
DEFAULT_TASK_TIMEOUT_SECONDS = 900.0
DEFAULT_MAX_SPLIT_DEPTH = 3
# Agent failures that a smaller window can avoid. Budget, model and provider failures are not
# retried: a smaller window would not change them.
SPLITTABLE_ERRORS = frozenset({"context_size_limit"})


class OrchestrationError(ValueError):
    """The run cannot start: unknown scenario, missing investigator or invalid settings."""


def task_limits(base: Limits, plan: PlannedInvestigation, model_tool_calls: int = DEFAULT_MODEL_TOOL_CALLS) -> Limits:
    """Tool budget for one task: the initial query, every trusted seed, then the model's own choices.

    Both agents count seeds against ``max_tool_calls``; without this a window with many triggers
    would leave the model no room to investigate, or fail outright on the budget.
    """
    budget = min(100, 1 + len(plan.seed_evidence_ids) + model_tool_calls)
    return base.model_copy(update={"max_tool_calls": max(base.max_tool_calls, budget)})


class FinishGuard:
    """Model transport wrapper that lets an agent's model only finish once looping is futile.

    Neither investigation agent narrows its reply schema when no tool budget remains, so a local
    model that keeps choosing tools (observed: ``qwen3:8b`` repeating one identical query) runs
    into ``tool_budget_exhausted`` and the agent discards everything it gathered. This wrapper
    reads the agent's own turn context and, when ``tool_calls_remaining`` is zero or the model's
    previous call was an exact repeat (``reused_from`` set), passes only the agent's own
    ``_FinishReply`` branch to the decoder. Nothing else changes: the agent still parses and
    validates the reply itself. The single-agent baseline applies the same rule to itself.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.forced_finishes = 0

    def metadata(self) -> dict:
        return {**self._inner.metadata(), "finish_guard": "budget_or_repeat"}

    def complete(self, messages, schema, limits):
        if self._should_finish(messages) and "_FinishReply" in schema.get("$defs", {}):
            schema = {"$defs": schema["$defs"], "$ref": "#/$defs/_FinishReply"}
            self.forced_finishes += 1
        return self._inner.complete(messages, schema, limits)

    @staticmethod
    def _should_finish(messages) -> bool:
        try:
            context = json.loads(messages[-1]["content"])
        except (ValueError, KeyError, IndexError, TypeError):
            return False
        if not isinstance(context, dict):
            return False
        remaining = context.get("tool_calls_remaining")
        history = context.get("operation_history") or []
        last = history[-1] if history and isinstance(history[-1], dict) else {}
        repeated = last.get("origin") == "model" and last.get("reused_from") is not None
        return (isinstance(remaining, int) and remaining <= 0) or repeated


def corpus_investigators(store: EventStore, *, authentication_llm, endpoint_llm, limits: Limits | None = None,
                         model_tool_calls: int = DEFAULT_MODEL_TOOL_CALLS,
                         finish_guard: bool = True) -> dict[AgentType, Investigator]:
    """The two production investigators over one corpus, sharing one set of base limits."""
    limits = limits or Limits()
    if finish_guard:
        authentication_llm, endpoint_llm = FinishGuard(authentication_llm), FinishGuard(endpoint_llm)
    authentication_provider = CorpusAuthenticationProvider(store, limits)
    endpoint_provider = CorpusEndpointProvider(store, limits)

    def authentication(plan: PlannedInvestigation) -> AuthenticationResult:
        request = AuthenticationRequest(scenario_id=plan.scenario_id, start_utc=plan.start_utc, end_utc=plan.end_utc)
        required = None
        if plan.seed_evidence_ids:
            required = RequiredOperations.from_calls(*(
                ToolCall(name="get_authentication_event", arguments={"evidence_id": evidence_id})
                for evidence_id in plan.seed_evidence_ids
            ))
        return investigate_authentication(request, authentication_provider, authentication_llm,
                                          task_limits(limits, plan, model_tool_calls), required_operations=required)

    def endpoint(plan: PlannedInvestigation) -> EndpointResult:
        request = EndpointRequest(scenario_id=plan.scenario_id, start_utc=plan.start_utc, end_utc=plan.end_utc,
                                  seed_evidence_ids=plan.seed_evidence_ids)
        return investigate_endpoint(request, endpoint_provider, endpoint_llm, task_limits(limits, plan, model_tool_calls))

    return {"authentication": authentication, "endpoint": endpoint}


class IncidentOrchestrator:
    def __init__(self, store: EventStore, engine: DetectionEngine, investigators: Mapping[AgentType, Investigator], *,
                 policies: Mapping[AgentType, WindowPolicy] | None = None, limits: Limits | None = None,
                 llm_metadata: Mapping[str, object] | None = None,
                 task_timeout_seconds: float = DEFAULT_TASK_TIMEOUT_SECONDS,
                 run_timeout_seconds: float | None = None,
                 max_split_depth: int = DEFAULT_MAX_SPLIT_DEPTH) -> None:
        if task_timeout_seconds <= 0 or (run_timeout_seconds is not None and run_timeout_seconds <= 0):
            raise OrchestrationError("timeouts must be positive")
        self._store = store
        self._engine = engine
        self._investigators = dict(investigators)
        self._policies = {**default_policies(), **(policies or {})}
        self._limits = limits or Limits()
        if any(policy.max_window_seconds > self._limits.max_window_seconds for policy in self._policies.values()):
            raise OrchestrationError("a window policy exceeds the agents' max_window_seconds")
        if not 0 <= max_split_depth <= 8:
            raise OrchestrationError("max_split_depth must be between 0 and 8")
        self._llm_metadata = dict(llm_metadata or {})
        self._task_timeout = task_timeout_seconds
        self._run_timeout = run_timeout_seconds
        self._max_split_depth = max_split_depth

    def plan(self, scenario_id: str) -> tuple[PlannedInvestigation, ...]:
        self._require_scenario(scenario_id)
        return plan_investigations(scenario_id, self._engine.triggers_for(scenario_id), self._store, self._policies)

    def run(self, scenario_id: str, detections: tuple[Detection, ...] | None = None) -> OrchestrationRun:
        """Investigate one scenario; ``detections`` defaults to the engine's triggers for it."""
        self._require_scenario(scenario_id)
        started_utc = _now_utc()
        started = time.perf_counter()
        detections = self._engine.triggers_for(scenario_id) if detections is None else tuple(detections)
        by_id = {detection.detection_id: detection for detection in detections}
        pending = deque(plan_investigations(scenario_id, detections, self._store, self._policies))
        missing = sorted({plan.agent_type for plan in pending} - set(self._investigators))
        if missing:
            raise OrchestrationError(f"no investigator configured for {missing}")

        outcomes: list[TaskOutcome] = []
        while pending:
            plan = pending.popleft()
            remaining = None if self._run_timeout is None else self._run_timeout - (time.perf_counter() - started)
            if remaining is not None and remaining <= 0:
                outcomes.append(TaskOutcome(plan=plan, status="not_run", error_code="run_deadline_exceeded",
                                            latency_seconds=0.0))
                continue
            deadline = self._task_timeout if remaining is None else min(self._task_timeout, remaining)
            outcome = self._dispatch(plan, deadline)
            if outcome.error_code in SPLITTABLE_ERRORS and plan.split_depth < self._max_split_depth:
                halves = split_plan(plan, by_id, self._store)
                if halves:
                    outcome = outcome.model_copy(update={"split_into": tuple(half.task_id for half in halves)})
                    # Children run next, so each agent's tasks stay in time order.
                    pending.extendleft(reversed(halves))
            outcomes.append(outcome)

        return OrchestrationRun(
            scenario_id=scenario_id,
            corpus_manifest_sha256=self._engine.corpus_manifest_sha256,
            started_utc=started_utc,
            finished_utc=_now_utc(),
            latency_seconds=_seconds(time.perf_counter() - started),
            policies=self._policies,
            limits=self._limits.model_dump(mode="json"),
            llm=self._llm_metadata,
            detections=detections,
            tasks=tuple(outcomes),
            coverage=_coverage(detections, outcomes),
        )

    def _dispatch(self, plan: PlannedInvestigation, deadline: float) -> TaskOutcome:
        started = time.perf_counter()
        box: dict[str, object] = {}

        def target() -> None:
            try:
                box["result"] = self._investigators[plan.agent_type](plan)
            except BaseException as error:  # Recorded as an outcome; never propagated into the run.
                box["error"] = error

        worker = threading.Thread(target=target, name=f"investigate-{plan.task_id}", daemon=True)
        worker.start()
        worker.join(deadline)
        latency = _seconds(time.perf_counter() - started)

        if worker.is_alive():
            return TaskOutcome(plan=plan, status="timeout", error_code="task_timeout", latency_seconds=latency)
        if "error" in box:
            return TaskOutcome(plan=plan, status="error", error_code=f"agent_exception:{type(box['error']).__name__}",
                               latency_seconds=latency)
        result = box.get("result")
        if not _result_matches(plan, result):
            return TaskOutcome(plan=plan, status="error", error_code="agent_contract_violation", latency_seconds=latency)
        field = "authentication_result" if plan.agent_type == "authentication" else "endpoint_result"
        return TaskOutcome(plan=plan, status=result.status, error_code=result.error_code if result.status != "completed" else None,
                           latency_seconds=latency, **{field: result})

    def _require_scenario(self, scenario_id: str) -> None:
        if scenario_id not in self._store.scenario_ids:
            raise OrchestrationError(f"scenario {scenario_id!r} is not in the corpus; known: {list(self._store.scenario_ids)}")


def _result_matches(plan: PlannedInvestigation, result: object) -> bool:
    if not isinstance(result, EXPECTED_RESULT[plan.agent_type]):
        return False
    request = result.request
    if (request.scenario_id, request.start_utc, request.end_utc) != (plan.scenario_id, plan.start_utc, plan.end_utc):
        return False
    if result.status == "failed" and not result.error_code:
        return False
    return all(finding.scenario_id == plan.scenario_id for finding in result.findings)


def _coverage(detections, outcomes: list[TaskOutcome]) -> tuple[DetectionCoverage, ...]:
    coverage = []
    for detection in detections:
        tasks = [outcome for outcome in outcomes if detection.detection_id in outcome.plan.detection_ids]
        coverage.append(DetectionCoverage(
            detection_id=detection.detection_id,
            task_ids=tuple(outcome.plan.task_id for outcome in tasks),
            investigated=any(outcome.status == "completed" for outcome in tasks),
        ))
    return tuple(coverage)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _seconds(value: float) -> float:
    return round(max(value, 0.0), 3)
