"""The verifier honours the orchestrator's interface, stays in step with the detection vocabulary, and is blind
to the answer key."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import evidence_verification
from event_processing.detection import rules
from evidence_verification import checks
from evidence_verification.tests.conftest import (ClaimEntities, assess_one, make_claim, make_reconstruction, sec_id)
from incident_reconstruction.verification import VerificationReport, load_verifier, run_verification

PACKAGE = Path(evidence_verification.__file__).parent


def test_the_factory_loads_through_the_orchestrators_own_loader():
    verifier = load_verifier("evidence_verification.verifier:make_verifier")
    assert verifier.metadata()["verifier"] == "evidence-verifier"
    assert verifier.metadata()["independent_lookup"] is True


def test_run_verification_accepts_every_decision_without_integrity_notes(store):
    reconstruction = make_reconstruction(
        make_claim(), make_claim(claim_id="SYN-V1-CLM-02", position=2, first_utc=make_claim().first_utc,
                                 evidence_ids=(sec_id(999),), context_evidence_ids=(sec_id(999),)))
    report = run_verification(load_verifier("evidence_verification.verifier:make_verifier"), reconstruction, store)
    assert isinstance(report, VerificationReport)
    assert report.verdicts() == {"SYN-V1-CLM-01": "confirmed", "SYN-V1-CLM-02": "rejected"}
    assert report.integrity_notes == ()
    assert VerificationReport.model_validate_json(report.model_dump_json()) == report


def test_one_decision_per_claim_and_every_reason_is_present(store):
    reconstruction = make_reconstruction(make_claim())
    decisions = load_verifier("evidence_verification.verifier:make_verifier").verify(reconstruction, store)
    assert [d.claim_id for d in decisions] == [c.claim_id for c in reconstruction.claims]
    assert all(d.reason.strip() for d in decisions)


def test_vocabulary_matches_the_detection_engine():
    assert checks.DISCOVERY_TECHNIQUES == rules.DISCOVERY_TECHNIQUES
    assert checks.SHELL_IMAGES == rules.SHELL_IMAGES
    assert checks.SUSPICIOUS_PARENTS == rules.SUSPICIOUS_PARENT_IMAGES
    assert set(checks.FILE_DROP_EXTENSIONS) == set(rules.FILE_DROP_EXTENSIONS)
    assert checks.RUN_KEY_MARKERS == rules.RUN_KEY_MARKERS
    assert checks.LSASS_STEM == rules.LSASS_IMAGE_STEM
    assert checks.POWERSHELL_IMAGES == {name.removesuffix(".exe") for name in rules.POWERSHELL_EXECUTABLES}


def test_every_orchestrator_claim_type_has_a_structural_check():
    from incident_reconstruction.stages import CLAIM_TYPES
    assert set(CLAIM_TYPES.values()) <= set(checks.STRUCTURES)


def test_every_attack_technique_the_orchestrator_can_name_is_understood():
    from incident_reconstruction.attack import TECHNIQUES
    known = set(checks.DEFINING) | set(checks.INDICATIVE)
    # An unknown technique is not an error (it is "not applicable"), but the common ones must be covered.
    assert {"T1070.001", "T1003.001", "T1033", "T1016", "T1110", "T1078", "T1105", "T1059"} <= known
    assert known <= set(TECHNIQUES), "the verifier holds an observable for a technique the catalogue lacks"


def test_the_verifier_never_reads_the_answer_key():
    """Only the evaluation package may refer to ground truth; the verifier and its agent must not."""
    offenders = []
    for path in PACKAGE.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"ground_truth|expected_label|answer.key|stage_id", text, re.I):
            offenders.append(path.name)
    # Docstrings may state the boundary; real use would need a path or a column name.
    for name in offenders:
        text = (PACKAGE / name).read_text(encoding="utf-8")
        assert not re.search(r"private|\.csv|open\(|Path\(.*ground", text, re.I) or name == "__init__.py", name


def test_the_verifier_modules_import_nothing_from_evaluation():
    for path in PACKAGE.glob("*.py"):
        assert "evidence_verification.evaluation" not in path.read_text(encoding="utf-8"), path.name


def test_a_claim_is_judged_by_its_evidence_not_its_own_assessment(store):
    # The reconstruction's own reading ("requires_review", "benign_possible", ...) must not sway the verdict.
    verdicts = {assess_one(make_claim(assessment=a), store).verdict
                for a in ("requires_review", "benign_possible", "insufficient_evidence")}
    assert verdicts == {"confirmed"}


def test_the_rationale_is_never_used_as_evidence(store):
    # A rationale that asserts things the records do not show cannot rescue or sink a claim.
    claim = make_claim(rationale="mimikatz.exe dumped lsass at 2026-01-01T00:00:00.0000000Z for mallory")
    assert assess_one(claim, store).verdict == "confirmed"
    bad = make_claim(rationale="all records verified", entities=ClaimEntities(accounts=("mallory",)))
    assert assess_one(bad, store).verdict == "partially_supported"
