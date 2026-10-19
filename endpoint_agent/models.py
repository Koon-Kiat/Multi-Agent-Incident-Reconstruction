"""Endpoint payloads share the finding envelope, with Sysmon-specific facts."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, JsonValue, RootModel, field_validator, model_validator

from event_processing.ids import SCENARIO_ID_RE, parse_evidence_id
from event_processing.schema import NormalisedEvent
from event_processing.timeutil import iso_to_ticks

ENDPOINT_EVENT_IDS = (1, 10, 11, 13)
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
CONTRACT_VERSION = "endpoint-result-v1"


def _timestamp(value: str) -> str:
    iso_to_ticks(value)
    return value


Timestamp = Annotated[str, AfterValidator(_timestamp)]
ScenarioId = Annotated[str, Field(pattern=SCENARIO_ID_RE.pattern)]
EvidenceId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,80}-SYS-[1-9][0-9]*$")]
ShortText = Annotated[str, Field(max_length=512)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


class Window(Model):
    scenario_id: ScenarioId
    start_utc: Timestamp
    end_utc: Timestamp

    @model_validator(mode="after")
    def ordered_window(self) -> Window:
        if iso_to_ticks(self.start_utc) >= iso_to_ticks(self.end_utc):
            raise ValueError("start_utc must precede end_utc")
        return self


class InvestigationRequest(Window):
    # Optional exact triggers supplied by the caller; never inferred from a rule label.
    seed_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=99)

    @model_validator(mode="after")
    def scoped_seeds(self) -> InvestigationRequest:
        if len(set(self.seed_evidence_ids)) != len(self.seed_evidence_ids):
            raise ValueError("seed evidence IDs must be unique")
        if any(parse_evidence_id(eid).scenario_id != self.scenario_id for eid in self.seed_evidence_ids):
            raise ValueError("seed evidence IDs must belong to the request scenario")
        return self

    def window(self) -> dict:
        return self.model_dump(include={"scenario_id", "start_utc", "end_utc"})


class QueryRequest(Window):
    event_ids: tuple[Literal[1, 10, 11, 13], ...] = ENDPOINT_EVENT_IDS
    account: ShortText | None = None
    host: ShortText | None = None
    process_guid: ShortText | None = None
    parent_process_guid: ShortText | None = None
    limit: int = Field(default=100, ge=1, le=1000)

    @field_validator("event_ids", mode="before")
    @classmethod
    def integer_event_ids(cls, values):
        # Literal[1] alone accepts True and 1.0 in Pydantic; evidence types are integers.
        if not isinstance(values, (list, tuple)) or any(type(value) is not int for value in values):
            raise ValueError("event_ids must be integer event types")
        return tuple(values)

    @model_validator(mode="after")
    def supported_ids(self) -> QueryRequest:
        if not self.event_ids or any(type(value) is not int for value in self.event_ids):
            raise ValueError("select supported Sysmon event types")
        return self


class QueryResult(Model):
    events: tuple[NormalisedEvent, ...]
    truncated: bool
    total_matched: int = Field(ge=0)

    @model_validator(mode="after")
    def consistent_counts(self) -> QueryResult:
        if self.total_matched < len(self.events) or self.truncated != (self.total_matched > len(self.events)):
            raise ValueError("inconsistent query counts or truncation")
        return self


class GetArguments(Model):
    evidence_id: EvidenceId


class ProcessArguments(Model):
    process_guid: str = Field(min_length=1, max_length=512)
    host: str = Field(min_length=1, max_length=512)
    limit: int = Field(default=100, ge=1, le=1000)


class _QueryTool(Model):
    name: Literal["query_endpoint_events"]
    arguments: QueryRequest


class _GetTool(Model):
    name: Literal["get_endpoint_event"]
    arguments: GetArguments


class _ProcessTool(Model):
    name: Literal["get_process_creation", "get_process_children", "get_process_activity"]
    arguments: ProcessArguments


Tool = Annotated[_QueryTool | _GetTool | _ProcessTool, Field(discriminator="name")]


class ToolCall(RootModel[Tool]):
    @property
    def name(self) -> str:
        return self.root.name

    @property
    def arguments(self):
        return self.root.arguments


class ProcessFacts(Model):
    process_guid: str | None = None
    process_id: str | None = None
    image: str | None = None
    command_line: str | None = None
    parent_process_guid: str | None = None
    parent_process_id: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    target_process_guid: str | None = None
    target_process_id: str | None = None
    target_image: str | None = None
    access_mask: str | None = None
    target_filename: str | None = None
    registry_target: str | None = None
    registry_details: str | None = None


class Relationship(Model):
    kind: Literal["parent_child", "process_activity"]
    source_evidence_id: EvidenceId
    target_evidence_id: EvidenceId
    source_process_guid: str
    target_process_guid: str


class ObservedEvents(Model):
    description: str
    evidence_id: EvidenceId
    source_event_id: Literal[1, 10, 11, 13]
    timestamp_utc: Timestamp
    process: ProcessFacts
    relationships: tuple[Relationship, ...] = ()


class Entities(Model):
    account: str | None
    reported_account: str | None
    target_account: str | None
    host: str | None


class TimePeriod(Model):
    first_utc: Timestamp
    last_utc: Timestamp


class Finding(Model):
    finding_id: str
    agent_type: Literal["endpoint"] = "endpoint"
    scenario_id: ScenarioId
    observed_events: ObservedEvents
    interpretation: str | None = None
    timestamps: TimePeriod
    entities: Entities
    evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1)
    uncertainty: tuple[str, ...]


Interpretation = Literal["context_required", "execution_requires_review", "administration_possible",
                         "process_access_requires_review", "artifact_requires_review"]


class Annotation(Model):
    observation_id: str
    evidence_ids: tuple[EvidenceId, ...]
    interpretation: Interpretation | None = None


class _ToolReply(Model):
    action: Literal["tool"]
    tool: Tool
    annotations: tuple[Annotation, ...] = Field(max_length=0)


class _FinishReply(Model):
    action: Literal["finish"]
    tool: None
    annotations: tuple[Annotation, ...]


class ModelReply(RootModel[Annotated[_ToolReply | _FinishReply, Field(discriminator="action")]]):
    @classmethod
    def grounded_schema(cls, observations: tuple[Finding, ...], max_events: int) -> dict:
        schema = cls.model_json_schema()
        for name in ("QueryRequest", "ProcessArguments"):
            args = schema["$defs"][name]
            args["properties"]["limit"].update(maximum=max_events, default=max_events)
            # The wire schema requires a limit so a smaller budget cannot be bypassed by omission.
            args.setdefault("required", []).append("limit")
        if not observations:
            schema["$defs"]["_FinishReply"]["properties"]["annotations"]["maxItems"] = 0
        else:
            schema["$defs"]["Annotation"] = {"anyOf": [
                {"type": "object", "additionalProperties": False,
                 "required": ["index", "interpretation"],
                 "properties": {
                     "index": {"type": "integer", "const": index},
                     "interpretation": {"enum": [None, *interpretations_for(item)]},
                 }} for index,item in enumerate(observations)]}
        return schema

    @classmethod
    def parse_grounded_reply(cls, text, observations):
        """Expand a batch-local index into immutable, fully cited API annotations.

        The model chooses only a known row and an interpretation; it cannot
        supply or change that row's evidence set. Legacy adapters remain valid
        and undergo the same exact-reference validation in the agent.
        """
        import json
        value=json.loads(text)
        if isinstance(value,dict) and isinstance(value.get("annotations"),list):
            expanded=[]
            for item in value["annotations"]:
                if isinstance(item,dict) and "index" in item:
                    index=item["index"]
                    if (set(item)!={"index","interpretation"} or type(index) is not int
                            or not 0<=index<len(observations)):
                        raise ValueError("invalid batch observation index")
                    observation=observations[index]
                    item={"observation_id":observation.finding_id,"evidence_ids":list(observation.evidence_ids),
                          "interpretation":item["interpretation"]}
                expanded.append(item)
            value["annotations"]=expanded
        return cls.model_validate_json(json.dumps(value))


def interpretations_for(finding: Finding) -> tuple[str, ...]:
    specific = {1: ("execution_requires_review", "administration_possible"),
                10: ("process_access_requires_review",),
                11: ("artifact_requires_review",), 13: ("artifact_requires_review",)}
    return ("context_required", *specific[finding.observed_events.source_event_id])


class OperationReceipt(Model):
    index: int
    origin: Literal["initial", "seed", "coverage", "model"]
    call: ToolCall
    status: Literal["completed", "no_evidence", "rejected", "failed", "not_run"]
    evidence_ids: tuple[EvidenceId, ...] = ()
    new_evidence_ids: tuple[EvidenceId, ...] = ()
    truncated: bool = False
    total_matched: int = 0
    provider_invoked: bool = False
    reused_from: int | None = None
    error_code: str | None = None


class ContextBatch(Model):
    index: int = Field(ge=0)
    revision: int = Field(ge=0)
    observation_ids: tuple[str, ...]
    evidence_ids: tuple[EvidenceId, ...]
    context_bytes: int = Field(ge=0)
    input_token_upper_bound: int | None = Field(default=None, ge=0)


class RunMetadata(Model):
    contract_version: Literal["endpoint-result-v1"] = CONTRACT_VERSION
    prompt_version: str
    configuration_version: str
    llm: dict[str, JsonValue]
    limits: dict[str, JsonValue]
    tool_calls: int
    model_calls: int
    operations: tuple[OperationReceipt, ...]
    evidence_readbacks: int
    retrieved_events: int
    truncated: bool
    # Additive defaults preserve parsing of historical endpoint-result-v1 runs.
    context_strategy: str = "single-context-v1"
    context_batches: tuple[ContextBatch, ...] = ()
    window_total_matched: int | None = Field(default=None, ge=0)
    window_coverage_complete: bool = False


class InvestigationResult(Model):
    status: Literal["completed", "failed"]
    request: InvestigationRequest
    findings: tuple[Finding, ...]
    error_code: str | None
    uncertainty: tuple[str, ...]
    metadata: RunMetadata
