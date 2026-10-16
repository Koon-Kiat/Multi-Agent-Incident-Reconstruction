"""The orchestrator over the actual scenario corpus with deterministic fake models; no answer keys."""

import pytest

from authentication_agent.config import Limits
from authentication_agent.llm.fake import FakeLLM as AuthenticationFake
from endpoint_agent.llm.fake import FakeLLM as EndpointFake
from event_processing.corpus import normalise_datasets
from event_processing.detection.engine import DetectionEngine, corpus_manifest_digest
from event_processing.query import EventStore
from event_processing.tests.conftest import real_datasets
from incident_reconstruction import IncidentOrchestrator, OrchestrationRun, corpus_investigators
from incident_reconstruction.claims import Reconstruction
from incident_reconstruction.narrative import FakeReconstructionLLM
from incident_reconstruction.pipeline import MODES, Pipeline
from incident_reconstruction.reconstruction import reconstruct
from incident_reconstruction.single_agent import FakeSingleAgentLLM, SingleAgentInvestigator
from incident_reconstruction.verification import PendingVerifier


@pytest.fixture(scope="session")
def orchestrator(tmp_path_factory):
    output = tmp_path_factory.mktemp("orchestration-corpus")
    normalise_datasets(real_datasets(), output)
    store = EventStore.load(output)
    engine = DetectionEngine(store, corpus_manifest_sha256=corpus_manifest_digest(output))
    investigators = corpus_investigators(store, authentication_llm=AuthenticationFake(),
                                         endpoint_llm=EndpointFake(), limits=Limits())
    return store, IncidentOrchestrator(store, engine, investigators)


@pytest.mark.parametrize("scenario", ["S01", "S02", "S03"])
def test_every_detection_reaches_a_completed_investigation(orchestrator, scenario):
    store, orchestration = orchestrator
    result = orchestration.run(scenario)
    assert result.detections, "the conventional baseline fires on every core scenario"
    assert result.uninvestigated_detection_ids() == ()
    assert OrchestrationRun.model_validate_json(result.model_dump_json()) == result
    for finding in result.findings():
        assert finding.scenario_id == scenario
        assert all(store.lookup(eid).event is not None for eid in finding.evidence_ids)

    reconstruction = reconstruct(result, store, FakeReconstructionLLM())
    assert reconstruction.claims
    assert Reconstruction.model_validate_json(reconstruction.model_dump_json()) == reconstruction
    covered = {d for claim in reconstruction.claims for d in claim.detection_ids}
    assert covered == {d.detection_id for d in result.detections}, "every detection lands in a stage"
    assert sum(len(claim.detection_ids) for claim in reconstruction.claims) == len(result.detections)
    for claim in reconstruction.claims:
        assert claim.verification_status == "not_verified"
        assert all(store.lookup(eid).event is not None for eid in claim.context_evidence_ids)
        assert all(m.evidence_ids for m in claim.attack)
    # Each finding is a small fraction of the run: reconstruction narrows, it does not restate.
    linked = {f for claim in reconstruction.claims for f in claim.supporting_finding_ids}
    assert len(linked) < len(result.findings())


def test_every_run_mode_completes_on_the_same_triggers(orchestrator):
    store, orchestration = orchestrator
    engine = orchestration._engine
    pipeline = Pipeline(store, engine, orchestrator=orchestration, reconstruction_llm=FakeReconstructionLLM(),
                        single_agent=SingleAgentInvestigator(store, FakeSingleAgentLLM()), verifier=PendingVerifier())
    outputs = {mode: pipeline.run(mode, "S02") for mode in MODES}
    assert len({output.summary.detections for output in outputs.values()}) == 1
    assert {output.reconstruction.mode for output in outputs.values()} == set(MODES)
    for output in outputs.values():
        for claim in output.reconstruction.claims:
            assert all(store.lookup(eid).event is not None for eid in claim.evidence_ids)
    assert outputs["full"].summary.verdicts == {"unverified": outputs["full"].summary.claims}


def test_cross_source_stages_are_linked_in_the_failed_logon_scenario(orchestrator):
    store, orchestration = orchestrator
    reconstruction = reconstruct(orchestration.run("S02"), store, FakeReconstructionLLM())
    by_type = {claim.claim_type: claim for claim in reconstruction.claims}
    logons, discovery = by_type["failed_logons_then_success"], by_type["discovery_commands"]
    # The account behind the failed-then-successful logons also ran the discovery commands.
    assert any(link.claim_id == discovery.claim_id for link in logons.related_claims)
