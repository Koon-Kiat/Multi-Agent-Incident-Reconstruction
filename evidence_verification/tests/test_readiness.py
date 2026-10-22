"""The final-score readiness report lists every missing input and only says ready when the scorer agrees."""

from evidence_verification.evaluation.readiness import check, main
from evidence_verification.tests.conftest import SCENARIO
from evidence_verification.tests.test_comparison_validation import experiment  # noqa: F401 (fixture)


def statuses(gates):
    return {g["gate"]: g["status"] for g in gates}


def run_check(experiment, **overrides):
    runbooks = experiment["corpus"].parent/"runbooks"
    runbooks.mkdir(exist_ok=True)
    (runbooks/"S.md").write_text("synthetic runbook", encoding="utf8")
    options = dict(ground_truth=experiment["ground_truth"], runbooks=runbooks,
                   claim_reviews=experiment["claim_reviews"], scoring_contract=experiment["scoring_contract"])
    options.update(overrides)
    return check(experiment["corpus"].parent, **options)


def test_complete_inputs_are_ready_only_through_the_real_scorer(experiment):
    gates = run_check(experiment)
    assert set(statuses(gates).values()) == {"ready"}
    assert gates[-1] == {"gate": "final score gate", "status": "ready", "detail": "the scorer accepts every input",
                         "owner": ""}


def test_an_empty_folder_reports_every_gap_with_its_owner(tmp_path, capsys):
    assert main(["--root", str(tmp_path), "--ground-truth", str(tmp_path/"key"),
                 "--runbooks", str(tmp_path/"books")]) == 1
    printed = capsys.readouterr().out
    assert "MISSING  corpus" in printed and "BLOCKED  final score gate" in printed
    assert "[Dataset & Ground Truth Management]" in printed


def test_a_missing_answer_key_blocks_the_review_and_contract(experiment, tmp_path):
    found = statuses(run_check(experiment, ground_truth=tmp_path/"absent"))
    assert found["answer key"] == "missing"
    assert found["claim reviews"] == found["scoring contract"] == found["final score gate"] == "blocked"
    assert found["Generalist and specialist reconstruction runs"] == "ready"


def test_a_missing_configuration_is_named(experiment):
    (experiment["runs"]/"full"/f"{SCENARIO}.reconstruction.json").unlink()
    gate = next(g for g in run_check(experiment) if g["gate"] == "Generalist and specialist reconstruction runs")
    assert gate["status"] == "invalid" and f"full/{SCENARIO} not run" in gate["detail"]


def test_missing_runbooks_and_unapproved_contract_are_reported(experiment, tmp_path):
    contract = experiment["scoring_contract"]
    contract.write_text(contract.read_text().replace('"negative_population_reviewed": true',
                                                     '"negative_population_reviewed": false'), encoding="utf8")
    found = statuses(run_check(experiment, runbooks=tmp_path/"none"))
    assert found["runbooks"] == "missing" and found["scoring contract"] == "invalid"
    assert found["final score gate"] == "blocked"
