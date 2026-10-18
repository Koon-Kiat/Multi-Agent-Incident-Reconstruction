"""The scoring harness, over a made-up key and synthetic events. The real answer key never appears in a test."""

from __future__ import annotations

import json

import pytest

from event_processing.metrics import load_labels
from event_processing.query import EventStore
from event_processing.tests.synthetic import SECURITY, make_event
from evidence_verification.evaluation import alignment as AL
from evidence_verification.evaluation import detection as DE
from evidence_verification.evaluation import groundtruth as GT
from evidence_verification.evaluation import scoring as SC
from evidence_verification.evaluation.report import render
from evidence_verification.tests.conftest import (HOST, SCENARIO, USER, at, corpus_events, iso, make_claim, sec_id,
                                                   sys_id)

HEADER = ("scenario_id,stage_id,stage_order,time_utc,actual_activity,actor,host,expected_label,"
          "security_record_ids,sysmon_record_ids,mitre_technique,notes")


def key_text(*rows: str, bom: bool = True) -> str:
    return ("\ufeff" if bom else "") + "\n".join([HEADER, *rows]) + "\n"


STAGE_ROWS = (
    f'{SCENARIO},ST01,1,2026-09-21T02:05:00Z,a,x,h,malicious,"10;11;12",,T1110,n',
    f'{SCENARIO},ST02,2,2026-09-21T02:05:05Z,b,x,h,malicious,,20,T1033,n',
    f'{SCENARIO},ST03,3,2026-09-21T02:05:03Z,c,x,h,benign,13,,,n',
)


@pytest.fixture
def key_dir(tmp_path):
    (tmp_path / f"{SCENARIO}_ground_truth.csv").write_text(key_text(*STAGE_ROWS), encoding="utf-8")
    return tmp_path


@pytest.fixture
def stages(key_dir):
    return GT.load_ground_truth(key_dir)[SCENARIO]


@pytest.fixture
def store_with_scaffolding():
    events = corpus_events()
    events.append(make_event(scenario_id=SCENARIO, channel=SECURITY, record_id=30, event_id=4688,
                             timestamp_ticks=at(500), host=HOST, user=USER, in_scenario_window=False,
                             event_data={"NewProcessName": "C:\\Windows\\System32\\cmd.exe"}))
    events.append(make_event(scenario_id=SCENARIO, channel=SECURITY, record_id=31, event_id=4624,
                             timestamp_ticks=at(3), host=HOST, user="Font Driver Host\\UMFD-2",
                             event_data={"TargetUserName": "UMFD-2", "LogonType": "2"}))
    return EventStore(events)


# ---------------------------------------------------------------- loading the key

def test_the_key_loads_with_scoped_evidence_ids_and_a_bom(stages):
    assert [s.stage_id for s in stages] == ["ST01", "ST02", "ST03"]
    assert stages[0].evidence_ids == (sec_id(10), sec_id(11), sec_id(12))
    assert stages[1].evidence_ids == (sys_id(20),)
    assert stages[1].techniques == ("T1033",) and stages[2].techniques == ()


def test_a_record_cited_on_two_channels_stays_distinct(tmp_path):
    (tmp_path / "SYN-X_ground_truth.csv").write_text(key_text(
        'SYN-X,S1,1,2026-01-01T00:00:00Z,a,x,h,malicious,"5",5,,n'), encoding="utf-8")
    assert GT.load_ground_truth(tmp_path)["SYN-X"][0].evidence_ids == ("SYN-X-SEC-5", "SYN-X-SYS-5")


@pytest.mark.parametrize("rows,message", [
    ((f'{SCENARIO},S1,1,t,a,x,h,suspicious,"1",,,n',), "label"),
    ((f'{SCENARIO},S1,1,t,a,x,h,malicious,,,,n',), "cites no records"),
    ((f'{SCENARIO},S1,1,t,a,x,h,malicious,"1",,,n', f'{SCENARIO},S2,3,t,a,x,h,malicious,"2",,,n'), "contiguous"),
])
def test_a_malformed_key_is_refused(tmp_path, rows, message):
    (tmp_path / f"{SCENARIO}_ground_truth.csv").write_text(key_text(*rows), encoding="utf-8")
    with pytest.raises(GT.GroundTruthError, match=message):
        GT.load_ground_truth(tmp_path)


def test_a_key_missing_a_column_is_refused(tmp_path):
    (tmp_path / f"{SCENARIO}_ground_truth.csv").write_text("scenario_id,stage_id\nSYN,S1\n", encoding="utf-8")
    with pytest.raises(GT.GroundTruthError, match="missing column"):
        GT.load_ground_truth(tmp_path)


def test_no_key_for_a_scenario_is_an_error_not_a_silent_skip(key_dir):
    with pytest.raises(GT.GroundTruthError, match="no ground truth"):
        GT.load_ground_truth(key_dir, (SCENARIO, "S99"))


def test_neutral_records_load_from_the_exclusions_file(tmp_path):
    (tmp_path / GT.EXCLUSIONS_FILE).write_text(json.dumps(
        {"schema_version": GT.EXCLUSIONS_SCHEMA, "neutral_evidence_ids": {SCENARIO: [sec_id(14)]}}), encoding="utf-8")
    assert GT.load_neutral_evidence(tmp_path) == {SCENARIO: frozenset({sec_id(14)})}
    assert GT.load_neutral_evidence(tmp_path / "absent") == {}


# ---------------------------------------------------------------- alignment

def test_a_claim_citing_a_stage_record_is_aligned(stages, store_with_scaffolding):
    claim = make_claim(evidence_ids=(sec_id(10),))
    result = AL.align_claim(claim, stages, frozenset(), store_with_scaffolding)
    assert (result.alignment, result.stage_ids) == ("aligned", ("ST01",))


def _claim_citing(*ids, **kw):
    return make_claim(evidence_ids=tuple(ids), context_evidence_ids=tuple(ids), **kw)


def test_a_claim_on_out_of_window_records_is_neutral(stages, store_with_scaffolding):
    result = AL.align_claim(_claim_citing(sec_id(30)), stages, frozenset(), store_with_scaffolding)
    assert result.alignment == "neutral" and "outside the declared scenario window" in result.reason


def test_a_claim_on_non_person_session_records_is_neutral(stages, store_with_scaffolding):
    result = AL.align_claim(_claim_citing(sec_id(31)), stages, frozenset(), store_with_scaffolding)
    assert result.alignment == "neutral" and "non-person" in result.reason


def test_designated_contextual_records_are_neutral(stages, store_with_scaffolding):
    result = AL.align_claim(_claim_citing(sys_id(22)), stages, frozenset({sys_id(22)}), store_with_scaffolding)
    assert result.alignment == "neutral" and "designated contextual" in result.reason


def test_an_in_window_claim_the_key_does_not_cover_is_unaligned(stages, store_with_scaffolding):
    result = AL.align_claim(_claim_citing(sys_id(21)), stages, frozenset(), store_with_scaffolding)
    assert result.alignment == "unaligned"


def test_a_mixed_claim_is_not_excused_by_its_out_of_scope_half(stages, store_with_scaffolding):
    result = AL.align_claim(_claim_citing(sec_id(30), sys_id(21)), stages, frozenset(), store_with_scaffolding)
    assert result.alignment == "unaligned"


def test_a_fabricated_reference_can_never_be_neutral(stages, store_with_scaffolding):
    result = AL.align_claim(_claim_citing(sec_id(999)), stages, frozenset(), store_with_scaffolding)
    assert result.alignment == "unaligned" and "does not resolve" in result.reason


# ---------------------------------------------------------------- reconstruction scoring

def _score(claims, stages, store, neutral=frozenset()):
    alignments = {c.claim_id: AL.align_claim(c, stages, neutral, store) for c in claims}
    return SC.score_reconstruction(SCENARIO, "D_full_mair", tuple(claims), stages, alignments)


def _claims():
    c1 = make_claim(claim_id="C1", position=1, evidence_ids=(sec_id(10), sec_id(12)), assessment="requires_review")
    c2 = make_claim(claim_id="C2", position=2, evidence_ids=(sys_id(20),), context_evidence_ids=(sys_id(20),),
                    assessment="requires_review", first_utc=iso(5), last_utc=iso(5), claim_type="discovery_commands")
    c3 = make_claim(claim_id="C3", position=3, evidence_ids=(sys_id(21),), context_evidence_ids=(sys_id(21),),
                    first_utc=iso(6), last_utc=iso(6))
    c4 = make_claim(claim_id="C4", position=4, evidence_ids=(sec_id(30),), context_evidence_ids=(sec_id(30),),
                    first_utc=iso(500), last_utc=iso(500))
    return c1, c2, c3, c4


def test_stage_recall_precision_and_coverage_are_counted_with_denominators(stages, store_with_scaffolding):
    score = _score(_claims(), stages, store_with_scaffolding)
    assert (score.stages_matched, score.stages_total, score.stage_recall) == (2, 3, 0.6667)
    assert score.missed_stages == ["ST03"]
    assert (score.claims_aligned, score.claims_neutral, score.claims_unaligned) == (2, 1, 1)
    assert score.claim_precision == 0.6667, "neutral claims leave the denominator"
    assert score.mean_stage_coverage == pytest.approx((2 / 3 + 1) / 2, abs=1e-4)
    assert score.matched_stages == {"ST01": ["C1"], "ST02": ["C2"]}


def test_order_is_scored_separately_from_recall(stages, store_with_scaffolding):
    in_order = _score(_claims(), stages, store_with_scaffolding)
    assert (in_order.order_concordant, in_order.order_discordant, in_order.order_accuracy) == (1, 0, 1.0)
    c1, c2, c3, c4 = _claims()
    swapped = [c1.model_copy(update={"position": 2}), c2.model_copy(update={"position": 1}), c3, c4]
    out_of_order = _score(swapped, stages, store_with_scaffolding)
    assert out_of_order.stages_matched == 2, "recall is unchanged"
    assert (out_of_order.order_concordant, out_of_order.order_discordant, out_of_order.order_accuracy) == (0, 1, 0.0)


def test_one_claim_matching_two_stages_is_a_tie_not_an_order_error(stages, store_with_scaffolding):
    both = make_claim(claim_id="C1", position=1, evidence_ids=(sec_id(10), sys_id(20)),
                      context_evidence_ids=(sec_id(10), sys_id(20)))
    score = _score([both], stages, store_with_scaffolding)
    assert (score.order_ties, score.order_accuracy) == (1, None), "undefined, not zero"


def test_assessment_agreement_separates_attack_from_lookalike(stages, store_with_scaffolding):
    c1 = make_claim(claim_id="C1", position=1, evidence_ids=(sec_id(10),), assessment="benign_possible")
    c3 = make_claim(claim_id="C3", position=2, evidence_ids=(sec_id(13),), context_evidence_ids=(sec_id(13),),
                    assessment="requires_review", first_utc=iso(3), last_utc=iso(3))
    score = _score([c1, c3], stages, store_with_scaffolding)
    assert score.assessment == {"true_flag": 0, "under_call": 1, "over_call": 1, "true_benign": 0}


def test_an_empty_reconstruction_has_undefined_rates_not_zeros(stages, store_with_scaffolding):
    score = _score([], stages, store_with_scaffolding)
    assert (score.stages_matched, score.claim_precision, score.order_accuracy, score.mean_stage_coverage) == (0, None, None, None)
    assert score.missed_stages == ["ST01", "ST02", "ST03"]


def test_attack_agreement_is_reported_at_exact_and_parent_level(stages, store_with_scaffolding):
    from incident_reconstruction.claims import AttackMapping
    mapping = AttackMapping(technique_id="T1033", name="x", tactics=(), status="tentative", justification="j",
                            evidence_ids=(sys_id(20),))
    c2 = _claims()[1].model_copy(update={"attack": (mapping,)})
    score = _score([_claims()[0], c2], stages, store_with_scaffolding)
    assert score.attack == {"stages_with_technique": 2, "technique_exact": 1, "technique_parent": 1}


# ---------------------------------------------------------------- evidence-support summary

def test_support_counts_verdicts_and_crosstabs_them_against_the_key(stages, store_with_scaffolding):
    claims = _claims()
    alignments = {c.claim_id: AL.align_claim(c, stages, frozenset(), store_with_scaffolding) for c in claims}
    verdicts = {"C1": "confirmed", "C2": "partially_supported", "C3": "confirmed", "C4": "rejected"}
    conflicts = {"C4": ("unresolved_reference: SYN-V1-SEC-9 does not exist",)}
    s = SC.summarise_support(SCENARIO, "D_full_mair", "pipeline", verdicts, conflicts, alignments)
    assert s.verdicts == {"confirmed": 2, "partially_supported": 1, "unverified": 0, "rejected": 1}
    assert s.fabricated_reference_claims == 1 and s.confirmed_rate == 0.5
    assert s.by_alignment["unaligned"]["confirmed"] == 1, "a well-grounded claim the key does not cover"
    assert s.by_alignment["aligned"] == {"confirmed": 1, "partially_supported": 1, "unverified": 0, "rejected": 0}


# ---------------------------------------------------------------- detection labels (Configuration A)

def test_label_files_load_in_the_engines_own_loader_and_follow_the_two_views(tmp_path, stages, store_with_scaffolding):
    primary = tmp_path / "primary.csv"
    counts = DE.write_labels(primary, {SCENARIO: stages}, {SCENARIO: frozenset({sec_id(14)})},
                             store_with_scaffolding, exclude_scaffolding=True)
    rows = {r.evidence_id: r.label for r in load_labels(primary)}
    assert rows[sec_id(10)] == "positive" and rows[sys_id(20)] == "positive"
    assert rows[sec_id(13)] == "negative", "a benign stage's record is explicitly negative"
    assert rows[sec_id(30)] == "excluded" and rows[sec_id(14)] == "excluded"
    assert counts["positive"] == 4 and counts["excluded"] == 2

    strict = tmp_path / "strict.csv"
    DE.write_labels(strict, {SCENARIO: stages}, {SCENARIO: frozenset({sec_id(14)})}, store_with_scaffolding,
                    exclude_scaffolding=False)
    assert {r.label for r in load_labels(strict)} == {"positive", "negative"}


def test_a_record_in_both_a_malicious_and_a_benign_stage_is_positive(tmp_path, store_with_scaffolding):
    both = (GT.Stage(SCENARIO, "A", 1, "malicious", "t", (sec_id(10),), ()),
            GT.Stage(SCENARIO, "B", 2, "benign", "t", (sec_id(10),), ()))
    path = tmp_path / "l.csv"
    DE.write_labels(path, {SCENARIO: both}, {}, store_with_scaffolding, exclude_scaffolding=True)
    assert {r.evidence_id: r.label for r in load_labels(path)}[sec_id(10)] == "positive"


# ---------------------------------------------------------------- report

def test_the_report_labels_plumbing_runs_and_never_headlines_a_percentage():
    results = {"plumbing_only": True, "scored": False,
               "inputs": {"corpus_manifest_sha256": "abc"},
               "provenance": {"git_commit": "c", "verifier_code_clean": True, "verifier": {
                   "version": "1", "prompt_version": "p", "span_tolerance_seconds": 120},
                   "protocol_public_sha256": "x", "protocol_private_sha256": None,
                   "hardware": {"platform": "p", "logical_cpus": 1, "note": ""}},
               "runs": [], "totals": {}}
    text = render(results)
    assert "PLUMBING ONLY" in text and "must not be reported as results" in text
    assert "%" not in text


# ---------------------------------------------------------------- post-hoc re-verification must never touch the scored run

def test_reverify_refuses_to_overwrite_or_nest_inside_the_scored_run(tmp_path):
    from evidence_verification.evaluation.reverify import reverify
    scored = tmp_path / "scored"
    (scored / "full").mkdir(parents=True)
    marker = scored / "full" / "S99.verification.json"
    marker.write_text("original", encoding="utf-8")
    for destination in (scored, scored / "inside", tmp_path):            # same, inside, and containing the scored run
        with pytest.raises((FileExistsError, ValueError)):
            reverify(corpus=tmp_path, source=scored, destination=destination, verifier_spec="x:y")
    existing = tmp_path / "already-there"
    existing.mkdir()
    with pytest.raises(FileExistsError):
        reverify(corpus=tmp_path, source=scored, destination=existing, verifier_spec="x:y")
    assert marker.read_text(encoding="utf-8") == "original", "the scored run was modified"


def test_a_labelled_report_says_it_is_post_hoc_and_must_sit_beside_the_original():
    results = {"plumbing_only": False, "scored": True, "label": "POST-HOC re-run", "inputs": {"corpus_manifest_sha256": "a"},
               "provenance": {"git_commit": "c", "verifier_code_clean": True, "verifier": {
                   "version": "1", "prompt_version": "p", "span_tolerance_seconds": 120},
                   "protocol_public_sha256": "x", "protocol_private_sha256": None,
                   "hardware": {"platform": "p", "logical_cpus": 1, "note": ""}}, "runs": [], "totals": {}}
    text = render(results)
    assert "POST-HOC re-run" in text and "never in place of it" in text
