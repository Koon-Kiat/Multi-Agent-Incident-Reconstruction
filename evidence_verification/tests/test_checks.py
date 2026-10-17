"""Each test breaks one thing in an otherwise supported claim and asserts the verdict and the check that caught it.

A verifier that confirms everything would pass a suite of positive cases. These exist to show that
every kind of unsupported claim is caught, by the right check, with the right severity.
"""

from __future__ import annotations

import pytest

from evidence_verification.checks import SPAN_TOLERANCE_SECONDS
from evidence_verification.verifier import assess
from evidence_verification.tests.conftest import (HOST, OTHER, AttackMapping, ClaimEntities, ClaimLink, assess_one,
                                                   failed_names, iso, make_claim, make_reconstruction, sec_id,
                                                   sys_id)


# ---------------------------------------------------------------- the baseline claim is supported

def test_a_fully_supported_claim_is_confirmed(store):
    result = assess_one(make_claim(), store)
    assert result.verdict == "confirmed"
    assert result.failed == ()
    assert result.conflicts == ()


def test_confirmed_means_supported_as_stated_not_malicious(store):
    # A benign-looking claim over real, matching records is just as supported as an alarming one.
    claim = make_claim(assessment="benign_possible", claim_text="Two failed logons, then a successful logon.")
    assert assess_one(claim, store).verdict == "confirmed"


# ---------------------------------------------------------------- references: reject-grade

def test_a_fabricated_reference_is_rejected(store):
    claim = make_claim(evidence_ids=(sec_id(10), sec_id(999)),
                       context_evidence_ids=(sec_id(10), sec_id(999)))
    result = assess_one(claim, store)
    assert result.verdict == "rejected"
    assert "reference_resolves" in failed_names(result)
    assert any(c.startswith("unresolved_reference") and sec_id(999) in c for c in result.conflicts)


def test_a_malformed_reference_is_rejected_not_coerced(store):
    for bad in ("SYN-V1-SEC-010", "syn-v1-sec-10", "SYN-V1-10", "SYN-V1-SEC-10 ", ""):
        claim = make_claim(evidence_ids=(bad,), context_evidence_ids=(bad,))
        result = assess_one(claim, store)
        assert result.verdict == "rejected", bad
        assert any(c.startswith("invalid_reference") for c in result.conflicts), bad


def test_the_record_number_collision_is_caught(store):
    # Record 10 exists in BOTH scenarios. Citing the other scenario's record 10 must not resolve.
    claim = make_claim(evidence_ids=(sec_id(10, OTHER), sec_id(11), sec_id(12)),
                       context_evidence_ids=(sec_id(10, OTHER), sec_id(11), sec_id(12)))
    result = assess_one(claim, store)
    assert result.verdict == "rejected"
    assert any(c.startswith("scenario_mismatch") for c in result.conflicts)
    assert "repeat across scenarios" in result.conflicts[0]


def test_a_failed_reference_is_reported_once_however_often_it_is_cited(store):
    claim = make_claim(evidence_ids=(sec_id(999), sec_id(10)),
                       context_evidence_ids=(sec_id(999), sec_id(10)))
    result = assess_one(claim, store)
    assert sum(sec_id(999) in c for c in result.conflicts) == 1


def test_context_only_unresolved_reference_also_rejects(store):
    claim = make_claim(context_evidence_ids=(sec_id(10), sec_id(11), sec_id(12), sec_id(777)))
    assert assess_one(claim, store).verdict == "rejected"


# ---------------------------------------------------------------- activity: unverified

def test_cited_records_that_do_not_show_the_claimed_activity_are_unverified(store):
    # Real records, wrong activity: a claim of failed logons that cites process and file events.
    claim = make_claim(evidence_ids=(sys_id(20), sys_id(21)), context_evidence_ids=(sys_id(20), sys_id(21)),
                       claim_text="Two failed logons were followed by a successful logon.",
                       first_utc=iso(5), last_utc=iso(6))
    result = assess_one(claim, store)
    assert result.verdict == "unverified"
    assert "claim_type_structure" in failed_names(result)


def test_failures_without_a_later_success_do_not_support_failed_then_success(store):
    claim = make_claim(evidence_ids=(sec_id(10), sec_id(11)), context_evidence_ids=(sec_id(10), sec_id(11)),
                       last_utc=iso(1))
    assert assess_one(claim, store).verdict == "unverified"


def test_activity_shown_only_by_context_is_partial_not_unverified(store):
    claim = make_claim(evidence_ids=(sec_id(10), sec_id(11)))
    result = assess_one(claim, store)
    assert result.verdict == "partially_supported"
    assert result.failed[0].name == "claim_type_structure"


# ---------------------------------------------------------------- entities, host, time: partial or reject

def test_an_unrecorded_entity_is_partial(store):
    claim = make_claim(entities=ClaimEntities(accounts=("analyst", "mallory"), hosts=(HOST,)))
    result = assess_one(claim, store)
    assert result.verdict == "partially_supported"
    assert "entities_recorded" in failed_names(result)
    assert "mallory" in result.conflicts[0]


def test_a_domain_qualified_account_matches_its_recorded_name(store):
    claim = make_claim(entities=ClaimEntities(accounts=("LAB-A\\analyst",), hosts=(HOST,)))
    assert assess_one(claim, store).verdict == "confirmed"


def test_a_host_the_evidence_contradicts_is_rejected(store):
    claim = make_claim(entities=ClaimEntities(accounts=("analyst",), hosts=("OTHER-HOST",)))
    result = assess_one(claim, store)
    assert result.verdict == "rejected"
    assert any(c.startswith("contradicted_by_evidence") for c in result.conflicts)


def test_a_span_that_ends_before_it_starts_is_rejected(store):
    claim = make_claim(first_utc=iso(2), last_utc=iso(0))
    assert assess_one(claim, store).verdict == "rejected"


def test_a_span_edge_no_record_attests_is_partial(store):
    claim = make_claim(first_utc=iso(0.5))
    result = assess_one(claim, store)
    assert result.verdict == "partially_supported"
    assert "span_endpoints_recorded" in failed_names(result)


def test_cited_records_far_outside_the_span_are_partial(store):
    far = SPAN_TOLERANCE_SECONDS + 60
    claim = make_claim(first_utc=iso(far), last_utc=iso(far + 1))
    result = assess_one(claim, store)
    assert "cited_events_inside_span" in failed_names(result)
    assert result.verdict in {"partially_supported", "rejected"}


def test_records_just_outside_the_span_are_tolerated(store):
    # The orchestrator spans a stage by its triggers and cites related records slightly beyond it.
    claim = make_claim(first_utc=iso(0), last_utc=iso(1), evidence_ids=(sec_id(10), sec_id(11), sec_id(12)))
    result = assess_one(claim, store)
    assert "cited_events_inside_span" not in failed_names(result)


# ---------------------------------------------------------------- what the claim text asserts

def test_a_named_event_type_no_record_has_is_partial(store):
    claim = make_claim(claim_text="Two failed logons (Security 4625), then a success (Sysmon 11).")
    result = assess_one(claim, store)
    assert result.verdict == "partially_supported"
    assert "text_event_types_recorded" in failed_names(result)
    assert "Sysmon 11" in result.conflicts[0]


def test_an_overstated_failed_logon_count_is_partial(store):
    claim = make_claim(claim_text="Five failed logons were followed by a successful logon.")
    result = assess_one(claim, store)
    assert result.verdict == "partially_supported"
    assert "text_failed_logon_count" in failed_names(result)


def test_a_correct_failed_logon_count_passes(store):
    claim = make_claim(claim_text="Two failed logons were followed by a successful logon.")
    assert "text_failed_logon_count" not in failed_names(assess_one(claim, store))


def test_a_file_the_text_names_but_no_record_contains_is_partial(store):
    claim = make_claim(claim_text="Two failed logons, then a success; mimikatz.exe was then launched.")
    result = assess_one(claim, store)
    assert "text_files_recorded" in failed_names(result)
    assert "mimikatz.exe" in " ".join(result.conflicts)


def test_a_timestamp_in_the_text_no_record_carries_is_partial(store):
    claim = make_claim(claim_text="Two failed logons then a success, ending at 2026-09-21T04:00:00.0000000Z.")
    assert "text_times_recorded" in failed_names(assess_one(claim, store))


# ---------------------------------------------------------------- claim types

def _claim_over(record_ids, claim_type, *, scenario=None, second=(5, 5), **overrides):
    ids = tuple(record_ids)
    return make_claim(claim_type=claim_type, claim_text=f"{claim_type} observed.", evidence_ids=ids,
                      context_evidence_ids=ids, first_utc=iso(second[0]), last_utc=iso(second[1]),
                      entities=ClaimEntities(), **overrides)


@pytest.mark.parametrize("claim_type,ids,second", [
    ("explicit_credential_logon", (sec_id(13),), (3, 3)),
    ("audit_log_cleared", (sec_id(14),), (4, 4)),
    ("discovery_commands", (sys_id(20),), (5, 5)),
    ("payload_written", (sys_id(21),), (6, 6)),
    ("lsass_access", (sys_id(22),), (7, 7)),
    ("unusual_parent_shell", (sys_id(23),), (8, 8)),
    ("run_key_set", (sys_id(24),), (9, 9)),
    ("repeated_failed_logons", (sec_id(10), sec_id(11)), (0, 1)),
])
def test_each_claim_type_is_confirmed_by_its_own_activity(store, claim_type, ids, second):
    assert assess_one(_claim_over(ids, claim_type, second=second), store).verdict == "confirmed"


@pytest.mark.parametrize("claim_type", [
    "explicit_credential_logon", "audit_log_cleared", "discovery_commands", "payload_written",
    "lsass_access", "unusual_parent_shell", "run_key_set", "suspicious_powershell", "service_installed",
    "scheduled_task_created",
])
def test_each_claim_type_is_unverified_when_the_records_show_something_else(store, claim_type):
    # Record 10 is a failed logon; none of these types is a failed logon.
    claim = _claim_over((sec_id(10),), claim_type, second=(0, 0))
    result = assess_one(claim, store)
    assert result.verdict == "unverified", claim_type
    assert "claim_type_structure" in failed_names(result)


def test_an_unknown_claim_type_gets_only_the_generic_checks(store):
    claim = _claim_over((sec_id(13),), "free_form_label_from_a_single_agent", second=(3, 3))
    result = assess_one(claim, store)
    assert result.verdict == "confirmed"
    assert any(c.name == "claim_type_structure" and c.status == "not_applicable" for c in result.checks)


def test_an_unknown_claim_type_with_a_fabricated_reference_is_still_rejected(store):
    claim = _claim_over((sec_id(555),), "free_form_label_from_a_single_agent", second=(3, 3))
    assert assess_one(claim, store).verdict == "rejected"


# ---------------------------------------------------------------- ATT&CK

def _attack(technique, status, ids):
    return AttackMapping(technique_id=technique, name="x", tactics=(), status=status, justification="j",
                         evidence_ids=tuple(ids))


def test_a_supported_technique_without_its_defining_observable_is_partial(store):
    claim = _claim_over((sec_id(13),), "explicit_credential_logon", second=(3, 3),
                        attack=(_attack("T1070.001", "supported", (sec_id(13),)),))
    result = assess_one(claim, store)
    assert result.verdict == "partially_supported"
    assert "attack_T1070.001" in failed_names(result)


def test_a_supported_technique_with_its_defining_observable_passes(store):
    claim = _claim_over((sec_id(14),), "audit_log_cleared", second=(4, 4),
                        attack=(_attack("T1070.001", "supported", (sec_id(14),)),))
    assert assess_one(claim, store).verdict == "confirmed"


def test_marking_an_indicative_only_technique_supported_is_an_overclaim(store):
    claim = make_claim(attack=(_attack("T1110", "supported", (sec_id(10), sec_id(11))),))
    result = assess_one(claim, store)
    assert "attack_T1110" in failed_names(result)
    assert "at most tentative" in result.conflicts[0]


def test_a_tentative_technique_needs_a_consistent_observable(store):
    ok = make_claim(attack=(_attack("T1110", "tentative", (sec_id(10), sec_id(11))),))
    assert assess_one(ok, store).verdict == "confirmed"
    bad = _claim_over((sec_id(14),), "audit_log_cleared", second=(4, 4),
                      attack=(_attack("T1110", "tentative", (sec_id(14),)),))
    assert "attack_T1110" in failed_names(assess_one(bad, store))


def test_an_uncertain_technique_asserts_nothing(store):
    claim = make_claim(attack=(_attack("T1003.001", "uncertain", (sec_id(10),)),))
    result = assess_one(claim, store)
    assert result.verdict == "confirmed"


# ---------------------------------------------------------------- relationships and order

def _two_claims(link_reason, second_user="LAB-A\\analyst"):
    first = make_claim(related_claims=(ClaimLink(claim_id=f"{OTHER_ID}-CLM-02", reason=link_reason),))
    second = make_claim(
        claim_id=f"{OTHER_ID}-CLM-02", position=2, claim_type="discovery_commands", claim_text="whoami ran.",
        evidence_ids=(sys_id(20),), context_evidence_ids=(sys_id(20),), first_utc=iso(5), last_utc=iso(5),
        entities=ClaimEntities(), related_claims=(ClaimLink(claim_id=f"{OTHER_ID}-CLM-01", reason=link_reason),))
    return first, second


OTHER_ID = "SYN-V1"


def test_a_shared_account_link_is_confirmed_when_both_claims_name_the_account(store):
    first, second = _two_claims("shared account analyst")
    assert [a.verdict for a in assess(make_reconstruction(first, second), store)] == ["confirmed", "confirmed"]


def test_a_shared_account_link_the_records_do_not_show_is_partial(store):
    first, second = _two_claims("shared account mallory")
    verdicts = assess(make_reconstruction(first, second), store)
    assert all(a.verdict == "partially_supported" for a in verdicts)
    assert all("link_unsupported" in a.conflicts[0] for a in verdicts)


def test_a_process_lineage_link_is_checked_against_process_guids(store):
    first, second = _two_claims("a process in the later stage was started by a process in the earlier stage")
    # The only process in claim 2 has ParentProcessGuid GUID_PARENT, which no record in claim 1 carries.
    assert all("link_unsupported" in a.conflicts[0] for a in assess(make_reconstruction(first, second), store))


def test_claims_out_of_chronological_order_are_flagged(store):
    first = make_claim(claim_id=f"{OTHER_ID}-CLM-01", position=1, claim_type="discovery_commands",
                       claim_text="whoami ran.", evidence_ids=(sys_id(20),), context_evidence_ids=(sys_id(20),),
                       first_utc=iso(5), last_utc=iso(5), entities=ClaimEntities())
    second = make_claim(claim_id=f"{OTHER_ID}-CLM-02", position=2)  # starts at second 0, before claim 1
    results = assess(make_reconstruction(first, second), store)
    assert results[0].verdict == "confirmed"
    assert results[1].verdict == "partially_supported"
    assert "timeline_order" in failed_names(results[1])


# ---------------------------------------------------------------- verdict invariants

def test_the_verdict_always_agrees_with_the_failed_checks(store):
    claims = [
        make_claim(),
        make_claim(evidence_ids=(sec_id(999),), context_evidence_ids=(sec_id(999),)),
        make_claim(entities=ClaimEntities(accounts=("mallory",))),
        _claim_over((sec_id(10),), "audit_log_cleared", second=(0, 0)),
        make_claim(claim_text="Five failed logons then a success."),
    ]
    rank = {"reject": 0, "insufficient": 1, "partial": 2}
    for claim in claims:
        result = assess_one(claim, store)
        if not result.failed:
            assert result.verdict == "confirmed"
        else:
            worst = result.failed[0].grade
            assert result.verdict == {"reject": "rejected", "insufficient": "unverified",
                                      "partial": "partially_supported"}[worst]
            assert rank[worst] == min(rank[c.grade] for c in result.failed)


def test_a_rejection_always_cites_what_failed(store):
    for claim in (make_claim(evidence_ids=(sec_id(999),), context_evidence_ids=(sec_id(999),)),
                  make_claim(entities=ClaimEntities(hosts=("OTHER-HOST",))),
                  make_claim(first_utc=iso(2), last_utc=iso(0))):
        result = assess_one(claim, store)
        assert result.verdict == "rejected"
        assert result.conflicts and result.reason.startswith("Rejected:")


def test_decisions_are_deterministic(store):
    claim = make_claim(entities=ClaimEntities(accounts=("analyst", "mallory")))
    first, second = assess_one(claim, store).decision(), assess_one(claim, store).decision()
    assert first == second


def test_checked_evidence_ids_cover_every_reference(store):
    claim = make_claim(context_evidence_ids=(sec_id(10), sec_id(11), sec_id(12), sec_id(13)))
    result = assess_one(claim, store)
    assert set(result.checked_evidence_ids) == {sec_id(i) for i in (10, 11, 12, 13)}
