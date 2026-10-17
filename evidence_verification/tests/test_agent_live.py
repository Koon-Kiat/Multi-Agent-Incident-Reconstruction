"""Opt-in: the model layer against the real local model, on synthetic claims only.

    $env:MAIR_TEST_VERIFIER_OLLAMA = "1"; python -m pytest evidence_verification/tests/test_agent_live.py -q

Every benchmark case passes the deterministic checks, so only the model layer can catch an embellishment.
The thresholds are floors, not targets: they guard against the layer silently losing sensitivity.
"""

from __future__ import annotations

import os

import pytest

from event_processing.query import EventStore
from evidence_verification import agent as A
from evidence_verification.tests.benchmark_cases import EMBELLISHED, FAITHFUL
from evidence_verification.tests.conftest import corpus_events, make_reconstruction

pytestmark = pytest.mark.ollama


@pytest.fixture(scope="module")
def verdicts():
    if os.getenv("MAIR_TEST_VERIFIER_OLLAMA") != "1":
        pytest.skip("set MAIR_TEST_VERIFIER_OLLAMA=1 with the shared model installed locally")
    os.environ["MAIR_VERIFIER_LLM"] = "ollama"
    verifier = A.make_agent_verifier()
    store = EventStore(corpus_events())
    result = {name: verifier.verify(make_reconstruction(claim), store)[0].verdict
              for group in (FAITHFUL, EMBELLISHED) for name, claim in group.items()}
    result["_failed"] = verifier.metadata()["agent_failed"]
    return result


def test_the_model_layer_catches_embellished_claims(verdicts):
    caught = [name for name in EMBELLISHED if verdicts[name] != "confirmed"]
    assert len(caught) >= 7, f"caught {len(caught)}/{len(EMBELLISHED)}: {sorted(set(EMBELLISHED) - set(caught))} slipped through"


def test_the_model_layer_does_not_cry_wolf_on_faithful_claims(verdicts):
    flagged = [name for name in FAITHFUL if verdicts[name] != "confirmed"]
    assert len(flagged) <= 1, f"flagged faithful claims: {flagged}"


def test_the_model_layer_never_failed_or_rejected(verdicts):
    assert verdicts["_failed"] == 0
    assert "rejected" not in verdicts.values()
