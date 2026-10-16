"""Orchestration run record: planned investigations, their outcomes and timing.

Contract
--------

* A :class:`PlannedInvestigation` is one bounded ``[start_utc, end_utc)`` window sent to exactly
  one investigation agent. It names the detections that caused it and the trigger evidence IDs
  supplied to the agent as trusted retrieval seeds. Planning is deterministic for a given corpus,
  detection run and :class:`WindowPolicy`.
* A :class:`TaskOutcome` records what happened when the plan was dispatched. ``completed`` and
  ``failed`` are the agent's own result statuses; ``timeout``, ``error`` and ``not_run`` are
  orchestration outcomes with no agent result. Only ``completed`` tasks contribute findings; a
  failed or missing investigation is never treated as a clean window.
* :class:`OrchestrationRun` keeps every detection and every task, so a reviewer can follow any
  finding back to the window, the detection and the evidence that produced it. Findings are not
  duplicated in the document; :meth:`OrchestrationRun.findings` derives them from task results.
* Nothing here is a verdict. Detections are rule firings, findings are agent observations, and
  verification status belongs to Evidence Verification & Evaluation.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from authentication_agent.models import Finding as AuthenticationFinding
from authentication_agent.models import InvestigationResult as AuthenticationResult
from endpoint_agent.models import Finding as EndpointFinding
from endpoint_agent.models import InvestigationResult as EndpointResult
from event_processing.detection.schema import Detection
from event_processing.ids import SCENARIO_ID_RE
from event_processing.timeutil import iso_to_ticks

ORCHESTRATION_RUN_SCHEMA_VERSION = "orchestration-run-v1"

AgentType = Literal["authentication", "endpoint"]
TaskStatus = Literal["completed", "failed", "timeout", "error", "not_run"]
AgentFinding = Annotated[Union[AuthenticationFinding, EndpointFinding], Field(discriminator="agent_type")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class WindowPolicy(Model):
    """How detection spans become agent windows.

    Each detection's closed span is padded by ``context_before_seconds`` and
    ``context_after_seconds`` so an agent sees the activity around a trigger, not only the trigger.
    Padded spans for the same agent are merged while the merged window stays within
    ``max_window_seconds``, which must not exceed the agents' own query window limit.
    """

    context_before_seconds: int = Field(default=60, ge=0, le=3600)
    context_after_seconds: int = Field(default=60, ge=0, le=3600)
    max_window_seconds: int = Field(default=3600, ge=1, le=86400)


def default_policies() -> dict[AgentType, WindowPolicy]:
    """Sysmon is far denser than logon telemetry, so endpoint windows carry less context."""
    return {
        "authentication": WindowPolicy(context_before_seconds=60, context_after_seconds=60, max_window_seconds=3600),
        "endpoint": WindowPolicy(context_before_seconds=15, context_after_seconds=15, max_window_seconds=600),
    }


class PlannedInvestigation(Model):
    task_id: str = Field(min_length=1)
    agent_type: AgentType
    scenario_id: str = Field(pattern=SCENARIO_ID_RE.pattern)
    start_utc: str
    end_utc: str
    detection_ids: tuple[str, ...] = Field(min_length=1)
    seed_evidence_ids: tuple[str, ...] = Field(default=(), max_length=99)
    notes: tuple[str, ...] = ()
    # Set on a half produced by splitting a window whose investigation exceeded the agent's context.
    parent_task_id: str | None = None

    @property
    def split_depth(self) -> int:
        return self.task_id.count(".")

    @model_validator(mode="after")
    def ordered_window(self) -> PlannedInvestigation:
        if iso_to_ticks(self.start_utc) >= iso_to_ticks(self.end_utc):
            raise ValueError("start_utc must precede end_utc")
        return self


class TaskOutcome(Model):
    plan: PlannedInvestigation
    status: TaskStatus
    error_code: str | None = None
    latency_seconds: float = Field(ge=0)
    authentication_result: AuthenticationResult | None = None
    endpoint_result: EndpointResult | None = None
    # Child task IDs that re-investigated this window in smaller parts after it failed.
    split_into: tuple[str, ...] = ()

    @property
    def resolved(self) -> bool:
        """Completed, or replaced by smaller investigations whose own outcomes are recorded."""
        return self.status == "completed" or bool(self.split_into)

    @model_validator(mode="after")
    def result_matches_status(self) -> TaskOutcome:
        result = self.result
        other = self.endpoint_result if self.plan.agent_type == "authentication" else self.authentication_result
        if other is not None:
            raise ValueError(f"a {self.plan.agent_type} task must not carry another agent's result")
        if self.status in ("completed", "failed"):
            if result is None:
                raise ValueError(f"status {self.status!r} requires the agent result")
            if result.status != self.status:
                raise ValueError("task status must equal the agent result status")
        elif result is not None:
            raise ValueError(f"status {self.status!r} must not carry an agent result")
        if self.status != "completed" and not self.error_code:
            raise ValueError("a task that did not complete must name an error_code")
        return self

    @property
    def result(self) -> AuthenticationResult | EndpointResult | None:
        if self.plan.agent_type == "authentication":
            return self.authentication_result
        return self.endpoint_result


class DetectionCoverage(Model):
    detection_id: str
    task_ids: tuple[str, ...]
    investigated: bool


class OrchestrationRun(Model):
    schema_version: Literal["orchestration-run-v1"] = ORCHESTRATION_RUN_SCHEMA_VERSION
    scenario_id: str = Field(pattern=SCENARIO_ID_RE.pattern)
    corpus_manifest_sha256: str
    started_utc: str
    finished_utc: str
    latency_seconds: float = Field(ge=0)
    policies: dict[AgentType, WindowPolicy]
    limits: dict[str, JsonValue]
    llm: dict[str, JsonValue]
    detections: tuple[Detection, ...]
    tasks: tuple[TaskOutcome, ...]
    coverage: tuple[DetectionCoverage, ...]

    @model_validator(mode="after")
    def references_are_consistent(self) -> OrchestrationRun:
        detection_ids = [detection.detection_id for detection in self.detections]
        if len(set(detection_ids)) != len(detection_ids):
            raise ValueError("detections must not repeat a detection_id")
        task_ids = [task.plan.task_id for task in self.tasks]
        if len(set(task_ids)) != len(task_ids):
            raise ValueError("tasks must not repeat a task_id")
        known = set(detection_ids)
        for task in self.tasks:
            if task.plan.scenario_id != self.scenario_id:
                raise ValueError(f"task {task.plan.task_id!r} belongs to another scenario")
            unknown = set(task.plan.detection_ids) - known
            if unknown:
                raise ValueError(f"task {task.plan.task_id!r} names unknown detections {sorted(unknown)}")
            if task.plan.parent_task_id is not None and task.plan.parent_task_id not in task_ids:
                raise ValueError(f"task {task.plan.task_id!r} names an unknown parent task")
            if set(task.split_into) - set(task_ids):
                raise ValueError(f"task {task.plan.task_id!r} was split into unknown tasks")
        if [item.detection_id for item in self.coverage] != detection_ids:
            raise ValueError("coverage must list every detection once, in detection order")
        return self

    def findings(self) -> tuple[AuthenticationFinding | EndpointFinding, ...]:
        """Findings of completed tasks, first occurrence of each ``finding_id`` kept, in task order.

        Overlapping windows can report the same deterministic finding twice; it is one finding.
        """
        seen: set[str] = set()
        collected: list[AuthenticationFinding | EndpointFinding] = []
        for task in self.tasks:
            if task.status != "completed" or task.result is None:
                continue
            for finding in task.result.findings:
                if finding.finding_id not in seen:
                    seen.add(finding.finding_id)
                    collected.append(finding)
        return tuple(collected)

    def unresolved_task_ids(self) -> tuple[str, ...]:
        return tuple(task.plan.task_id for task in self.tasks if not task.resolved)

    def uninvestigated_detection_ids(self) -> tuple[str, ...]:
        """Detections with no completed investigation; these must be reported, not presumed benign."""
        return tuple(item.detection_id for item in self.coverage if not item.investigated)
