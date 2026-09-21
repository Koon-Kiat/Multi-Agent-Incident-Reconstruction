"""M3-only provisional contracts. All timestamps retain the original string."""

from __future__ import annotations

import re
from datetime import date
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, AfterValidator, model_validator

TICKS_PER_SECOND = 10_000_000
AUTH_EVENT_IDS = (4624, 4625)
_UTC = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(Z|\+00:00)$")


def utc_ticks(value: str) -> int:
    """Integer 100ns ticks, without floating point or datetime truncation."""
    match = _UTC.fullmatch(value)
    if not match:
        raise ValueError("timestamp must be UTC ISO 8601 with at most seven fractional digits")
    year, month, day, hour, minute, second = map(int, match.groups()[:6])
    if hour > 23 or minute > 59 or second > 59:
        raise ValueError("invalid timestamp time")
    seconds = date(year, month, day).toordinal() * 86400 + hour * 3600 + minute * 60 + second
    return seconds * TICKS_PER_SECOND + int((match.group(7) or "").ljust(7, "0"))


def _timestamp(value: str) -> str:
    utc_ticks(value)
    return value


Timestamp = Annotated[str, AfterValidator(_timestamp)]
ScenarioId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
ShortText = Annotated[str, Field(max_length=512)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def evidence_id_for(scenario_id: str, record_id: int) -> str:
    return f"{scenario_id}-SEC-{record_id}"


class AuthenticationEvent(Model):
    evidence_id: str
    scenario_id: ScenarioId
    source_type: Literal["windows_security"]
    channel: Literal["Security"]
    source_event_id: Annotated[int, Field(gt=0)]
    record_id: Annotated[int, Field(gt=0)]
    timestamp_utc: Timestamp
    host: ShortText | None = None
    user: ShortText | None = None
    event_data: dict[str, JsonValue] = Field(default_factory=dict)
    raw_reference: Annotated[str, Field(min_length=1, max_length=2048)]

    @model_validator(mode="after")
    def consistent_id(self) -> AuthenticationEvent:
        if self.evidence_id != evidence_id_for(self.scenario_id, self.record_id):
            raise ValueError("provisional evidence_id must be scenario_id + SEC + original record_id")
        return self


class InvestigationRequest(Model):
    scenario_id: ScenarioId
    start_utc: Timestamp
    end_utc: Timestamp

    @model_validator(mode="after")
    def ordered_window(self) -> InvestigationRequest:
        if utc_ticks(self.start_utc) >= utc_ticks(self.end_utc):
            raise ValueError("start_utc must precede end_utc")
        return self


class QueryRequest(InvestigationRequest):
    event_ids: tuple[int, ...] = AUTH_EVENT_IDS
    account: ShortText | None = None
    host: ShortText | None = None
    limit: Annotated[int, Field(gt=0)] = 100

    @model_validator(mode="after")
    def authentication_only(self) -> QueryRequest:
        if not self.event_ids or not set(self.event_ids).issubset(AUTH_EVENT_IDS):
            raise ValueError("only supported authentication Event IDs 4624 and 4625 are permitted")
        return self


class QueryResult(Model):
    events: tuple[AuthenticationEvent, ...]
    truncated: bool


class Entities(Model):
    account: str | None
    reported_account: str | None
    domain: str | None
    host: str | None
    source_address: str | None
    workstation: str | None
    logon_type: str | None


class ObservedEvents(Model):
    description: str
    failed_logons: int
    successful_logons: int
    failures_before_first_success: int
    repeated_failures_followed_by_success: bool


class TimePeriod(Model):
    first_utc: Timestamp
    last_utc: Timestamp


class Finding(Model):
    finding_id: str
    agent_type: Literal["authentication"] = "authentication"
    scenario_id: ScenarioId
    observed_events: ObservedEvents
    interpretation: str | None = None
    timestamps: TimePeriod
    entities: Entities
    evidence_ids: tuple[str, ...]
    uncertainty: tuple[str, ...]


class Annotation(Model):
    observation_id: str
    evidence_ids: tuple[str, ...]
    interpretation: Literal["may_warrant_review", "context_required"] | None


class ToolCall(Model):
    name: Literal["query_authentication_events", "get_authentication_event", "get_account_authentication_history"]
    arguments: dict[str, JsonValue]


class ModelReply(Model):
    action: Literal["tool", "finish"]
    tool: ToolCall | None
    annotations: tuple[Annotation, ...]

    @model_validator(mode="after")
    def valid_action(self) -> ModelReply:
        if (self.action == "tool") != (self.tool is not None):
            raise ValueError("tool action requires exactly one tool; finish requires null")
        if self.action == "tool" and self.annotations:
            raise ValueError("annotations are only allowed on finish")
        return self


class RunMetadata(Model):
    contract_version: str = "m3-provisional-v1"
    prompt_version: str
    configuration_version: str
    llm: dict[str, JsonValue]
    limits: dict[str, JsonValue]
    tool_calls: int
    model_calls: int


class InvestigationResult(Model):
    status: Literal["completed", "failed"]
    request: InvestigationRequest
    findings: tuple[Finding, ...]
    error_code: str | None
    uncertainty: tuple[str, ...]
    metadata: RunMetadata
