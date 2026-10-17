"""The verifier over the real scenario corpus with deterministic fake models; no answer key is read.

Skips, like the other corpus tests, when the original EVTX exports are not present (CI does not fetch Git LFS).
"""

from __future__ import annotations

import pytest

from authentication_agent.config import Limits
from authentication_agent.llm.fake import FakeLLM as AuthenticationFake
from endpoint_agent.llm.fake import FakeLLM as EndpointFake
from event_processing.corpus import normalise_datasets
from event_processing.detection.engine import DetectionEngine, corpus_manifest_digest
from event_processing.query import EventStore
from event_processing.tests.conftest import real_datasets
from evidence_verification.verifier import assess
from incident_reconstruction import IncidentOrchestrator, corpus_investigators
from incident_reconstruction.narrative import FakeReconstructionLLM
from incident_reconstruction.reconstruction import reconstruct

SCENARIOS = ["S01", "S02", "S03"]


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    output = tmp_path_factory.mktemp("verifier-corpus")
    normalise_datasets(real_datasets(), output)
    store = EventStore.load(output)
    engine = DetectionEngine(store, corpus_manifest_sha256=corpus_manifest_digest(output))
    investigators = corpus_investigators(store, authentication_llm=AuthenticationFake(),
                                         endpoint_llm=EndpointFake(), limits=Limits())
    runs = {sid: IncidentOrchestrator(store, engine, investigators).run(sid) for sid in SCENARIOS}
    reconstructions = {sid: reconstruct(runs[sid], store, FakeReconstructionLLM(), Limits()) for sid in SCENARIOS}
    return store, reconstructions


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_claims_built_from_real_records_are_never_rejected(corpus, scenario):
    store, reconstructions = corpus
    results = assess(reconstructions[scenario], store)
    assert results, "every core scenario yields claims"
    rejected = [(a.claim.claim_id, a.conflicts) for a in results if a.verdict == "rejected"]
    assert not rejected, rejected


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_a_real_claim_with_one_fabricated_reference_is_rejected(corpus, scenario):
    store, reconstructions = corpus
    claim = reconstructions[scenario].claims[0]
    broken = claim.model_copy(update={
        "evidence_ids": (*claim.evidence_ids, f"{scenario}-SEC-999999999"),
        "context_evidence_ids": (*claim.context_evidence_ids, f"{scenario}-SEC-999999999")})
    reconstruction = reconstructions[scenario].model_copy(
        update={"claims": (broken, *reconstructions[scenario].claims[1:])})
    result = assess(reconstruction, store)[0]
    assert result.verdict == "rejected"
    assert any("unresolved_reference" in c for c in result.conflicts)


def _a_real_collision(store):
    """A record number present in both lab scenarios' Security exports as two different events."""
    for event in store.scenario_events("S02"):
        if event.channel != "Security":
            continue
        other = store.lookup(f"S03-SEC-{event.record_id}").event
        if other is not None and other.source_event_id != event.source_event_id:
            return event, other
    raise AssertionError("the lab scenarios no longer share a record number for different events")


def test_the_real_record_number_collision_is_caught(corpus):
    """The same record number is a different event in S02 and S03. An S02 claim citing S03's record must not resolve."""
    store, reconstructions = corpus
    mine, theirs = _a_real_collision(store)
    claim = reconstructions["S02"].claims[0]
    swapped = claim.model_copy(update={"evidence_ids": (theirs.evidence_id,),
                                       "context_evidence_ids": (theirs.evidence_id,)})
    reconstruction = reconstructions["S02"].model_copy(update={"claims": (swapped,)})
    result = assess(reconstruction, store)[0]
    assert result.verdict == "rejected"
    assert any(c.startswith("scenario_mismatch") for c in result.conflicts)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_verdicts_are_stable_across_runs(corpus, scenario):
    store, reconstructions = corpus
    first = [a.decision() for a in assess(reconstructions[scenario], store)]
    second = [a.decision() for a in assess(reconstructions[scenario], store)]
    assert first == second
