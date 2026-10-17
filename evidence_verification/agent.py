"""The independently prompted Verifier Agent: a second opinion that can only lower a verdict.

The deterministic checks decide whether references resolve, whether times, entities and stated event
types agree with the records, and whether the cited records show the activity a claim names. They
cannot read a sentence. The agent does that one thing: given a claim and the recorded events the
*verifier itself* retrieved, it says whether those events support what the claim states.

Independence is enforced by what the prompt contains. It holds the claim's text, its type label, its
stated span, its entities and its technique IDs, and the recorded events. It never holds the
reconstruction's rationale, its own assessment, its uncertainty notes, detection or finding IDs, links
to other claims, an orchestration trace, agent reasoning or any answer key. A verifier's judgement is
never accepted as its own ground truth.

Authority is one-directional. The agent is consulted only for claims the deterministic checks
confirmed, because it cannot change any other verdict:

* it may lower ``confirmed`` to ``partially_supported`` or ``unverified``;
* it can never raise a verdict and can never reject, because rejection requires a failed reference
  or a contradiction that code has verified, not an opinion;
* if the model is unavailable or replies invalidly, the deterministic verdict stands and says so.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from authentication_agent.config import Limits
from event_processing.query import EventStore
from event_processing.schema import NormalisedEvent
from incident_reconstruction.claims import Reconstruction
from incident_reconstruction.verification import VerificationDecision

from .verifier import ClaimAssessment, assess, VERIFIER_VERSION

PROMPT_VERSION = "evidence-verifier-prompt-v1"
MAX_RECORDS = 14
MAX_RECORD_CHARS = 700
MAX_VALUE_CHARS = 300
RECORD_FIELDS = (
    "TargetUserName", "TargetDomainName", "SubjectUserName", "LogonType", "Status", "SubStatus", "IpAddress",
    "ProcessName", "NewProcessName", "ParentProcessName", "Image", "ParentImage", "CommandLine", "User",
    "SourceImage", "TargetImage", "GrantedAccess", "TargetFilename", "TargetObject", "Details", "ProcessGuid",
    "ParentProcessGuid", "SourceProcessGUID", "ServiceName", "TaskName",
)

SYSTEM_PROMPT = """You are an independent evidence verifier for security incident reconstructions.

You are shown ONE claim and the recorded events you retrieved for it. Decide only whether the recorded
events support what the claim STATES. Do not judge whether the activity is malicious, risky or normal: a
benign action that the records show is fully supported.

Rules:
- Use only the records shown. Do not use outside knowledge to fill a gap.
- Check every assertion in the claim text: who, what, how many, when, and any technique named.
- An assertion is unsupported when no shown record states it. An assertion the records contradict is also
  unsupported. Name each one, quoting the claim's own words.
- If the records shown are too few to judge an assertion, say cannot_tell rather than guess.
- The claim's type label and stated span are assertions too.

Reply with JSON only. judgement is one of: supported (every assertion is shown), partially_supported (the
core is shown but some assertion is not), unsupported (the records do not show the core of the claim),
cannot_tell (the records shown are insufficient to judge)."""

JUDGEMENTS = ("supported", "partially_supported", "unsupported", "cannot_tell")


class Unsupported(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    assertion: str = Field(min_length=1, max_length=240)
    why: str = Field(min_length=1, max_length=240)


class Judgement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    judgement: str
    unsupported_assertions: tuple[Unsupported, ...] = Field(max_length=5)
    reason: str = Field(min_length=1, max_length=400)


def reply_schema() -> dict:
    item = {"type": "object", "additionalProperties": False, "required": ["assertion", "why"],
            "properties": {"assertion": {"type": "string", "minLength": 1, "maxLength": 240},
                           "why": {"type": "string", "minLength": 1, "maxLength": 240}}}
    return {"type": "object", "additionalProperties": False,
            "required": ["judgement", "unsupported_assertions", "reason"],
            "properties": {"judgement": {"type": "string", "enum": list(JUDGEMENTS)},
                           "unsupported_assertions": {"type": "array", "maxItems": 5, "items": item},
                           "reason": {"type": "string", "minLength": 1, "maxLength": 400}}}


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


def build_messages(assessment: ClaimAssessment) -> list[dict[str, str]]:
    """The whole prompt. Built only from the claim's assertions and records the verifier retrieved itself."""
    claim = assessment.claim
    evidence = assessment.evidence
    cited = evidence.cited_events()
    extra = [e for e in evidence.context_events() if e.evidence_id not in evidence.cited]
    chosen = (cited + extra)[:MAX_RECORDS]
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
        "records": [_record(event) for event in chosen],
        "records_shown": len(chosen),
        "records_available": len(cited) + len(extra),
    }
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}]


_TOKEN = re.compile(r"[A-Za-z0-9_.$\\-]{3,}")


def _attributable(assertion: str, claim) -> bool:
    """An unsupported assertion must be about the claim, not invented by the model."""
    source = " ".join([claim.claim_text, claim.claim_type, *claim.entities.accounts, *claim.entities.hosts,
                       *claim.entities.processes, *claim.entities.files, *(m.technique_id for m in claim.attack)])
    wanted = {token.casefold() for token in _TOKEN.findall(assertion)}
    return bool(wanted & {token.casefold() for token in _TOKEN.findall(source)})


def apply_judgement(assessment: ClaimAssessment, judgement: Judgement) -> tuple[str, tuple[str, ...], str]:
    """(verdict, extra conflicts, reason suffix). Only ever lowers ``confirmed``; never raises or rejects."""
    if assessment.verdict != "confirmed" or judgement.judgement == "supported":
        return assessment.verdict, (), "The verifier agent found the claim supported by the retrieved records."
    grounded = tuple(item for item in judgement.unsupported_assertions if _attributable(item.assertion, assessment.claim))
    conflicts = tuple(f"unsupported_assertion: {item.assertion} ({item.why})" for item in grounded)
    if judgement.judgement == "partially_supported" and grounded:
        verdict = "partially_supported"
    elif judgement.judgement in ("unsupported", "cannot_tell"):
        verdict = "unverified"
    else:
        # partially_supported with nothing attributable to the claim: the model named no real assertion.
        return assessment.verdict, (), ("The verifier agent doubted the claim but named no assertion the claim "
                                        "makes, so the deterministic verdict stands.")
    return verdict, conflicts, f"The verifier agent judged it {judgement.judgement}: {judgement.reason}"


def parse_reply(text: str) -> Judgement:
    judgement = Judgement.model_validate_json(text)
    if judgement.judgement not in JUDGEMENTS:
        raise ValueError("judgement outside the contract")
    return judgement


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
        decisions = []
        for assessment in assess(reconstruction, store):
            decisions.append(self._decide(assessment))
        return decisions

    def _decide(self, assessment: ClaimAssessment) -> VerificationDecision:
        if assessment.verdict != "confirmed":
            return assessment.decision()  # the agent cannot change this verdict, so it is not consulted
        self._stats["consulted"] += 1
        started = time.perf_counter()
        try:
            judgement = parse_reply(self._llm.complete(build_messages(assessment), reply_schema(), self._limits))
        except Exception as error:  # An unavailable or invalid reply never becomes support or a downgrade.
            self._stats["failed"] += 1
            code = str(error)[:60] if type(error).__name__ == "InvestigationError" else type(error).__name__
            base = assessment.decision()
            return base.model_copy(update={"reason": f"{base.reason} The verifier agent was unavailable "
                                                     f"({code}); the deterministic verdict stands."})
        finally:
            self._seconds += time.perf_counter() - started
        verdict, extra, note = apply_judgement(assessment, judgement)
        base = assessment.decision()
        if verdict != assessment.verdict:
            self._stats["lowered"] += 1
        return base.model_copy(update={"verdict": verdict, "reason": f"{base.reason} {note}",
                                       "conflicts": (*base.conflicts, *extra)})


class FakeVerifierLLM:
    """Deterministic stand-in: finds every claim supported. Plumbing only; never a scored run."""

    def metadata(self) -> dict:
        return {"runtime": "fake", "model": "deterministic-fake-verifier-v1"}

    def complete(self, messages, schema, limits) -> str:
        return json.dumps({"judgement": "supported", "unsupported_assertions": [],
                           "reason": "fake verifier: records shown"})


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
