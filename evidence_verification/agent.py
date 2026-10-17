"""The independently prompted Verifier Agent: a second opinion that can only lower a verdict.

The deterministic checks decide whether references resolve, whether times, entities and stated event
types agree with the records, and whether the cited records show the activity a claim names. They
cannot read a sentence. The agent does that one thing: it splits the claim into its separate assertions
and, for each, says which retrieved record states it, copying the words. A claim's embellishments (an
intent, a cause, a consequence, an extra detail) are exactly what records fail to state, so they are the
assertions it cannot ground.

The model never decides the verdict. It lists assertions; code decides what that means:

* an assertion is *shown* only if the model cites a retrieved record and quotes words that appear in it;
  naming no record, or quoting words the record does not contain, leaves it *not shown*;
* an assertion the model added that is not about the claim is ignored;
* any not-shown assertion lowers ``confirmed`` to ``partially_supported``; if none is shown, to
  ``unverified``.

Independence is enforced by what the prompt contains. It holds the claim's text, its type label, its
stated span, its entities and its technique IDs, and the recorded events. It never holds the
reconstruction's rationale, its own assessment, its uncertainty notes, detection or finding IDs, links
to other claims, an orchestration trace, agent reasoning or any answer key. A verifier's judgement is
never accepted as its own ground truth.

Authority is one-directional. The agent is consulted only for claims the deterministic checks
confirmed, because it cannot change any other verdict. It can lower, never raise, and never reject:
rejection requires a failed reference or a contradiction that code has verified, not an opinion. If the
model is unavailable or replies invalidly, the deterministic verdict stands and says so.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from authentication_agent.config import Limits
from event_processing.query import EventStore
from event_processing.schema import NormalisedEvent
from incident_reconstruction.claims import Reconstruction
from incident_reconstruction.verification import VerificationDecision

from .verifier import VERIFIER_VERSION, ClaimAssessment, assess

PROMPT_VERSION = "evidence-verifier-prompt-v2"
NONE = "NONE"
MAX_RECORDS = 14
MAX_ASSERTIONS = 6
MAX_RECORD_CHARS = 700
MAX_VALUE_CHARS = 300
RECORD_FIELDS = (
    "TargetUserName", "TargetDomainName", "SubjectUserName", "LogonType", "Status", "SubStatus", "IpAddress",
    "ProcessName", "NewProcessName", "ParentProcessName", "Image", "ParentImage", "CommandLine", "User",
    "SourceImage", "TargetImage", "GrantedAccess", "TargetFilename", "TargetObject", "Details", "ProcessGuid",
    "ParentProcessGuid", "SourceProcessGUID", "ServiceName", "TaskName",
)

SYSTEM_PROMPT = """You are an independent evidence verifier for security incident reconstructions.

You are shown ONE claim and the recorded events retrieved for it. Your job is to find out which parts of the
claim the records actually state.

Step 1. Split the claim text into its separate assertions: who did what, on which host, how many times, in
what order, when, and ANY stated intent, cause, purpose, consequence, outcome or extra detail.
Step 2. For each assertion, find the shown record that states it and copy the exact words from that record
into quote. If no shown record states the assertion, set shown_by to NONE and quote to an empty string.

Rules:
- Absence of contradiction is NOT support. An assertion about intent, cause, purpose, consequence, an
  account's status, or an action that no shown record records is NOT shown, however plausible.
- An assertion about order or count is shown only if the records' own times and event IDs establish it.
- Use only the records shown. Do not use outside knowledge to fill a gap.
- Do not judge whether the activity is malicious. A benign action that the records show is fully shown.
- List every assertion the claim makes, including the unsupported ones. Do not omit an assertion because it is
  unsupported. Do not list record metadata (host, time, account) as separate assertions unless the claim states it.
- quote must be copied from a shown record, never from the claim. At most 6 assertions: merge small related ones."""


class Assertion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    assertion: str = Field(min_length=1, max_length=200)
    shown_by: str
    quote: str = Field(max_length=160)


class Reply(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    assertions: tuple[Assertion, ...] = Field(min_length=1, max_length=MAX_ASSERTIONS)
    reason: str = Field(min_length=1, max_length=300)


def reply_schema(shown_ids: tuple[str, ...]) -> dict:
    item = {"type": "object", "additionalProperties": False, "required": ["assertion", "shown_by", "quote"],
            "properties": {"assertion": {"type": "string", "minLength": 1, "maxLength": 200},
                           "shown_by": {"type": "string", "enum": [*shown_ids, NONE]},
                           "quote": {"type": "string", "maxLength": 160}}}
    return {"type": "object", "additionalProperties": False, "required": ["assertions", "reason"],
            "properties": {"assertions": {"type": "array", "minItems": 1, "maxItems": MAX_ASSERTIONS, "items": item},
                           "reason": {"type": "string", "minLength": 1, "maxLength": 300}}}


# ---------------------------------------------------------------------------------------------
# The prompt and the record text the model's quotes are checked against
# ---------------------------------------------------------------------------------------------

def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit] + "...[clipped]"


def _record(event: NormalisedEvent) -> dict:
    fields = {name: _clip(event.event_data[name], MAX_VALUE_CHARS) for name in RECORD_FIELDS
              if event.event_data.get(name)}
    record = {"evidence_id": event.evidence_id, "source": event.channel.split("/")[0],
              "event_id": event.source_event_id, "time_utc": event.timestamp_utc, "host": event.host,
              "account": event.user, "fields": fields}
    while len(json.dumps(record)) > MAX_RECORD_CHARS and fields:
        fields.pop(next(reversed(fields)))
    return record


def _normalise(text: str) -> str:
    """Formatting-insensitive form: JSON punctuation, doubled backslashes and spacing do not matter."""
    text = text.replace("\\\\", "\\")
    text = re.sub(r"[\"'{}\[\],:;]", " ", text)
    return re.sub(r"\s+", " ", text).casefold().strip()


_TOKEN = re.compile(r"[A-Za-z0-9_.$-]{3,}")


def _tokens(text: str) -> set[str]:
    return {token.casefold() for token in _TOKEN.findall(_normalise(text))}


def _record_tokens(record: dict) -> set[str]:
    parts = [f"event_id {record['event_id']}", f"time_utc {record['time_utc']}", f"host {record['host']}",
             f"account {record['account']}", f"source {record['source']}"]
    for key, value in record["fields"].items():
        parts += [f"{key} {value}", str(value)]
    return _tokens(" ".join(parts))


@dataclass(frozen=True)
class Prompt:
    messages: list[dict[str, str]]
    shown_ids: tuple[str, ...]
    record_tokens: dict[str, set[str]]


def build_prompt(assessment: ClaimAssessment) -> Prompt:
    """The whole prompt. Built only from the claim's assertions and records the verifier retrieved itself."""
    claim, evidence = assessment.claim, assessment.evidence
    cited = evidence.cited_events()
    extra = [e for e in evidence.context_events() if e.evidence_id not in evidence.cited]
    chosen = (cited + extra)[:MAX_RECORDS]
    records = [_record(event) for event in chosen]
    payload = {
        "claim": {
            "claim_type": claim.claim_type,
            "claim_text": claim.claim_text,
            "stated_span_utc": [claim.first_utc, claim.last_utc],
            "accounts": list(claim.entities.accounts), "hosts": list(claim.entities.hosts),
            "processes": list(claim.entities.processes), "files": list(claim.entities.files),
            "techniques": [{"id": m.technique_id, "status": m.status} for m in claim.attack],
            "cited_evidence_ids": list(claim.evidence_ids),
        },
        "records": records,
        "records_shown": len(records),
        "records_available": len(cited) + len(extra),
    }
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}]
    return Prompt(messages, tuple(r["evidence_id"] for r in records), {r["evidence_id"]: _record_tokens(r) for r in records})


def build_messages(assessment: ClaimAssessment) -> list[dict[str, str]]:
    return build_prompt(assessment).messages


# ---------------------------------------------------------------------------------------------
# What the model's reply means. All of it is decided here, in code.
# ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Reading:
    outcome: str  # supported | partially_supported | unsupported
    not_shown: tuple[tuple[str, str], ...]  # (assertion, why)
    reason: str


def _about_the_claim(assertion: str, assessment: ClaimAssessment) -> bool:
    """An assertion counts against a claim only if the claim makes it, not if the model added it."""
    claim = assessment.claim
    source = " ".join([claim.claim_text, *claim.entities.accounts, *claim.entities.hosts, *claim.entities.processes,
                       *claim.entities.files])
    wanted = _tokens(assertion)
    return bool(wanted) and len(wanted & _tokens(source)) / len(wanted) >= 0.6


def read_reply(assessment: ClaimAssessment, reply: Reply, prompt: Prompt) -> Reading:
    considered: list[tuple[str, str | None]] = []
    for item in reply.assertions:
        if item.shown_by == NONE:
            why = "no retrieved record states it"
        elif item.shown_by not in prompt.shown_ids:
            why = "it cites a record that was not shown"
        elif not _tokens(item.quote) & prompt.record_tokens[item.shown_by]:
            why = "its quoted support does not appear in the cited record"
        else:
            considered.append((item.assertion, None))
            continue
        if _about_the_claim(item.assertion, assessment):
            considered.append((item.assertion, why))
    if not considered:
        raise ValueError("the reply names no assertion about the claim")
    failed = tuple((a, why) for a, why in considered if why)
    if not failed:
        return Reading("supported", (), reply.reason)
    if len(failed) == len(considered):
        return Reading("unsupported", failed, reply.reason)
    return Reading("partially_supported", failed, reply.reason)


def apply_reading(assessment: ClaimAssessment, reading: Reading) -> tuple[str, tuple[str, ...], str]:
    """(verdict, extra conflicts, reason suffix). Only ever lowers ``confirmed``; never raises or rejects."""
    if assessment.verdict != "confirmed" or reading.outcome == "supported":
        return assessment.verdict, (), "The verifier agent found every assertion in the claim stated by a retrieved record."
    conflicts = tuple(f"unsupported_assertion: {assertion} ({why})" for assertion, why in reading.not_shown)
    named = "; ".join(assertion for assertion, _ in reading.not_shown[:2])
    verdict = "partially_supported" if reading.outcome == "partially_supported" else "unverified"
    return verdict, conflicts, f"The verifier agent could not ground in any retrieved record: {named}."


def parse_reply(text: str) -> Reply:
    return Reply.model_validate_json(text)


class AgentVerifier:
    """Deterministic checks, then a model second opinion on the claims those checks confirmed."""

    def __init__(self, llm, *, limits: Limits | None = None, llm_metadata: dict | None = None) -> None:
        self._llm = llm
        self._limits = limits or Limits()
        self._llm_metadata = llm_metadata or dict(llm.metadata())
        self._stats: Counter = Counter()
        self._seconds = 0.0

    def metadata(self) -> dict:
        return {"verifier": "evidence-verifier", "version": VERIFIER_VERSION, "mode": "deterministic_and_agent",
                "independent_lookup": True, "model": self._llm_metadata, "prompt_version": PROMPT_VERSION,
                "agent_consulted": self._stats["consulted"], "agent_lowered": self._stats["lowered"],
                "agent_failed": self._stats["failed"], "agent_seconds": round(self._seconds, 3)}

    def verify(self, reconstruction: Reconstruction, store: EventStore) -> Iterable[VerificationDecision]:
        return [self._decide(assessment) for assessment in assess(reconstruction, store)]

    def _decide(self, assessment: ClaimAssessment) -> VerificationDecision:
        if assessment.verdict != "confirmed":
            return assessment.decision()  # the agent cannot change this verdict, so it is not consulted
        self._stats["consulted"] += 1
        started = time.perf_counter()
        try:
            prompt = build_prompt(assessment)
            reading = read_reply(assessment, parse_reply(self._llm.complete(
                prompt.messages, reply_schema(prompt.shown_ids), self._limits)), prompt)
        except Exception as error:  # An unavailable or invalid reply never becomes support or a downgrade.
            self._stats["failed"] += 1
            code = str(error)[:60] if type(error).__name__ == "InvestigationError" else type(error).__name__
            base = assessment.decision()
            return base.model_copy(update={"reason": f"{base.reason} The verifier agent was unavailable "
                                                     f"({code}); the deterministic verdict stands."})
        finally:
            self._seconds += time.perf_counter() - started
        verdict, extra, note = apply_reading(assessment, reading)
        base = assessment.decision()
        if verdict != assessment.verdict:
            self._stats["lowered"] += 1
        return base.model_copy(update={"verdict": verdict, "reason": f"{base.reason} {note}",
                                       "conflicts": (*base.conflicts, *extra)})


class FakeVerifierLLM:
    """Deterministic stand-in: cites the first retrieved record for the claim's own words. Plumbing only."""

    def metadata(self) -> dict:
        return {"runtime": "fake", "model": "deterministic-fake-verifier-v1"}

    def complete(self, messages, schema, limits) -> str:
        payload = json.loads(messages[1]["content"])
        record = payload["records"][0]
        return json.dumps({"assertions": [{"assertion": payload["claim"]["claim_text"][:200],
                                           "shown_by": record["evidence_id"], "quote": str(record["event_id"])}],
                           "reason": "fake verifier: first record cited"})


def make_agent_verifier() -> AgentVerifier:
    """Factory for ``--verifier evidence_verification.agent:make_agent_verifier``.

    ``MAIR_VERIFIER_LLM`` must be ``ollama`` or ``fake``; there is no default, so a scored run can never
    silently use the fake. ``ollama`` uses the team's shared profile (Qwen3 8B by default, context 8192,
    thinking off, temperature 0, seed 0) and checks installed weights before any evidence is sent.
    """
    mode = os.getenv("MAIR_VERIFIER_LLM", "")
    if mode == "fake":
        return AgentVerifier(FakeVerifierLLM())
    if mode != "ollama":
        raise ValueError("set MAIR_VERIFIER_LLM to 'ollama' or 'fake'")
    from authentication_agent.config import OllamaConfig
    from authentication_agent.investigate_corpus import local_model_runtime
    from authentication_agent.llm.ollama_client import OllamaClient

    config = OllamaConfig(model=os.getenv("MAIR_VERIFIER_MODEL", "qwen3:8b"),
                          num_ctx=int(os.getenv("MAIR_VERIFIER_NUM_CTX", "8192")), think=False, temperature=0.0, seed=0)
    runtime = local_model_runtime(config)
    limits = Limits(model_timeout_seconds=int(os.getenv("MAIR_VERIFIER_TIMEOUT", "180")))
    return AgentVerifier(OllamaClient(config), limits=limits, llm_metadata=runtime)
