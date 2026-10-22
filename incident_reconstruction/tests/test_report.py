import re

import pytest

from event_processing.query import EventStore
from incident_reconstruction import IncidentOrchestrator
from incident_reconstruction.narrative import FakeReconstructionLLM
from incident_reconstruction.pipeline import Pipeline
from incident_reconstruction.report import render_scenario, write_reports
from incident_reconstruction.single_agent import FakeSingleAgentLLM, SingleAgentInvestigator
from incident_reconstruction.verification import PendingVerifier, VerificationDecision

from .conftest import SCENARIO, sysmon
from .test_run_modes import FixedVerifier

HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)>'


@pytest.fixture
def hostile_store(events):
    # An attacker controls command lines; the report must render them as text.
    poisoned = sysmon(21, 5, ProcessGuid=events["process_child"].event_data["ProcessGuid"], ProcessId="200",
                      User="LAB-A\\analyst", Image="C:\\Windows\\System32\\cmd.exe", CommandLine=HOSTILE,
                      ParentProcessGuid=events["process_child"].event_data["ParentProcessGuid"])
    return EventStore([*(e for k, e in events.items() if k != "process_child"), poisoned])


def pipeline_for(store, engine, investigators_factory, verifier):
    return Pipeline(store, engine, orchestrator=IncidentOrchestrator(store, engine, investigators_factory(store)),
                    reconstruction_llm=FakeReconstructionLLM(),
                    single_agent=SingleAgentInvestigator(store, FakeSingleAgentLLM()), verifier=verifier)


@pytest.fixture
def factory():
    from authentication_agent.config import Limits
    from authentication_agent.llm.fake import FakeLLM as AuthenticationFake
    from endpoint_agent.llm.fake import FakeLLM as EndpointFake
    from incident_reconstruction.orchestrator import corpus_investigators
    return lambda store: corpus_investigators(store, authentication_llm=AuthenticationFake(),
                                              endpoint_llm=EndpointFake(), limits=Limits())


def test_event_content_is_escaped_and_pages_are_self_contained(hostile_store, engine, factory):
    output = pipeline_for(hostile_store, engine, factory, PendingVerifier()).run("full", SCENARIO)
    page = render_scenario(store=hostile_store, reconstruction=output.reconstruction, summary=output.summary,
                           orchestration=output.orchestration, verification=output.verification)
    assert "<script" not in page and "<img" not in page
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in page
    # No external resources of any kind: everything a reviewer sees is in the file.
    assert not re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", page)
    assert "@import" not in page and "<link" not in page


def test_verdicts_are_shown_as_returned(store, engine, factory):
    def decide(reconstruction):
        first = reconstruction.claims[0].claim_id
        return [VerificationDecision(claim_id=first, verdict="rejected", reason="timestamps disagree",
                                     conflicts=("evidence after claim end",))]

    output = pipeline_for(store, engine, factory, FixedVerifier(decide)).run("full", SCENARIO)
    page = render_scenario(store=store, reconstruction=output.reconstruction, summary=output.summary,
                           orchestration=output.orchestration, verification=output.verification)
    assert "verifier: rejected" in page and "timestamps disagree" in page and "evidence after claim end" in page
    # Claims the verifier skipped are shown with the pipeline's integrity reason, not as supported.
    assert page.count("no_decision_returned") == len(output.reconstruction.claims) - 1
    assert "verifier: confirmed" not in page


def test_unverified_modes_say_so_and_pending_verification_is_flagged(store, engine, factory):
    pipeline = pipeline_for(store, engine, factory, PendingVerifier())
    multi = pipeline.run("multi-agent", SCENARIO)
    page = render_scenario(store=store, reconstruction=multi.reconstruction, summary=multi.summary)
    assert "Not verified." in page and "verifier:" not in page
    full = pipeline.run("full", SCENARIO)
    page = render_scenario(store=store, reconstruction=full.reconstruction, summary=full.summary,
                           verification=full.verification)
    assert "Verification pending." in page
    assert page.count("verifier: unverified") == len(full.reconstruction.claims)
    assert "deterministic fake model" in page


def test_missing_evidence_is_flagged_not_hidden(store, engine, factory, events):
    output = pipeline_for(store, engine, factory, PendingVerifier()).run("multi-agent", SCENARIO)
    smaller = EventStore([e for k, e in events.items() if k != "fail1"])
    page = render_scenario(store=smaller, reconstruction=output.reconstruction)
    assert f"{events['fail1'].evidence_id}</td><td colspan=4 class=bad>not found in this corpus" in page


def test_reports_and_index_cover_every_saved_run(store, engine, factory, tmp_path):
    pipeline = pipeline_for(store, engine, factory, PendingVerifier())
    for mode in ("single-agent", "multi-agent", "full"):
        pipeline.run(mode, SCENARIO).write(tmp_path)
    written = write_reports(tmp_path, store)
    assert sorted(p.relative_to(tmp_path).as_posix() for p in written) == [
        f"full/{SCENARIO}.report.html", "index.html",
        f"multi-agent/{SCENARIO}.report.html", f"single-agent/{SCENARIO}.report.html"]
    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    from incident_reconstruction.terminology import MODE_LABELS
    for mode in ("single-agent", "multi-agent", "full"):
        assert f'href="{mode}/{SCENARIO}.report.html"' in index
        assert MODE_LABELS[mode] in index
        page = (tmp_path / mode / f"{SCENARIO}.report.html").read_text(encoding="utf-8")
        assert MODE_LABELS[mode] in page
    claim_ids = re.findall(r'<li class=claim id="([^"]+)"', (tmp_path / "full" / f"{SCENARIO}.report.html").read_text(encoding="utf-8"))
    assert claim_ids == [f"{SCENARIO}-CLM-0{i}" for i in range(1, len(claim_ids) + 1)]


def test_an_empty_runs_directory_still_gets_an_index(store, tmp_path):
    (index,) = write_reports(tmp_path, store)
    assert "No saved runs found." in index.read_text(encoding="utf-8")
