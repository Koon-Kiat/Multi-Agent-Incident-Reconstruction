"""Report every prerequisite of the final A/B/C/D score at once; never score, never invent an input.

The scorer stops at the first missing input. This lists them all, so each owner can see what is still
theirs to supply. It reuses the scorer's own validators, and when every gate passes it runs the scorer
itself into a throwaway directory: "ready" means the real gate accepted the inputs, not a separate check.

    python -m evidence_verification.evaluation.readiness --root out/final-01

``--root`` is the folder ``scripts/run-evaluation.ps1 -Out`` writes: corpus/, detections/, runs/ and
review/. Exit codes: 0 ready to score; 1 something is missing or invalid; 2 invalid arguments.
"""

import argparse
import json
import tempfile
from pathlib import Path

from event_processing.detection.engine import corpus_manifest_digest
from event_processing.metrics import load_detection_runs
from event_processing.provenance import json_digest
from event_processing.query import EventStore
from .groundtruth import load_ground_truth, load_neutral_evidence
from .independent import load_reviews, validate_contract
from .runner import MODES, evaluate
from .validation import validate_run

OWNERS = {
    "answer key": "Dataset & Ground Truth Management",
    "runbooks": "Dataset & Ground Truth Management",
    "configuration A": "whoever runs the comparison",
    "runs B/C/D": "whoever runs the comparison",
    "claim reviews": "the independent reviewer",
    "scoring contract": "the dataset, detection and evaluation owners",
}


def _problem(error):
    return str(error) or type(error).__name__


def check(root, *, ground_truth=Path("ground_truth/private"), runbooks=Path("runbooks/private"),
          claim_reviews=None, scoring_contract=None):
    root = Path(root)
    corpus, detections, runs = root/"corpus", root/"detections", root/"runs"
    claim_reviews = Path(claim_reviews or root/"review"/"claim_reviews.json")
    scoring_contract = Path(scoring_contract or root/"review"/"scoring_contract.json")
    gates = []

    def gate(name, status, detail):
        gates.append({"gate": name, "status": status, "detail": detail, "owner": OWNERS.get(name, "")})

    store = digest = None
    try:
        store, digest = EventStore.load(corpus), corpus_manifest_digest(corpus)
        gate("corpus", "ready", f"{len(store.scenario_ids)} scenarios, manifest {digest[:12]}")
    except (ValueError, OSError) as error:
        gate("corpus", "missing", f"{corpus}: {_problem(error)}")

    key_ok = False
    if store is None:
        gate("answer key", "blocked", "needs the corpus")
    else:
        try:
            stages = load_ground_truth(ground_truth, store.scenario_ids)
            neutral = load_neutral_evidence(ground_truth)
            cited = {i for s in stages.values() for stage in s for i in stage.evidence_ids} | {
                i for ids in neutral.values() for i in ids}
            if not cited <= set(store.evidence_ids) or set(neutral) - set(store.scenario_ids):
                raise ValueError("ground truth or exclusions reference records or scenarios absent from this corpus")
            key_ok = True
            gate("answer key", "ready", ", ".join(f"{s}: {len(st)} stages" for s, st in stages.items())
                 + ("; owner exclusions present" if neutral else "; no owner exclusions file"))
        except (ValueError, OSError) as error:
            gate("answer key", "missing", f"{ground_truth}: {_problem(error)}")

    books = [p for p in Path(runbooks).glob("*") if p.is_file() and not p.name.startswith(".")] \
        if Path(runbooks).is_dir() else []
    gate("runbooks", "ready" if books else "missing",
         f"{len(books)} file(s) in {runbooks}" if books else f"no runbook files in {runbooks}")

    triggers = {}
    if store is None:
        gate("configuration A", "blocked", "needs the corpus")
    else:
        try:
            found = load_detection_runs(detections)
            if {r.scenario_id for r in found} != set(store.scenario_ids) or any(
                    r.corpus_manifest_sha256 != digest for r in found):
                raise ValueError("detections cover different scenarios or a different corpus revision")
            triggers = {r.scenario_id: json_digest([d.model_dump(mode="json") for d in r.detections]) for r in found}
            gate("configuration A", "ready", f"{sum(len(r.detections) for r in found)} detections")
        except (ValueError, OSError) as error:
            gate("configuration A", "missing", f"{detections}: {_problem(error)}")

    if store is None:
        gate("runs B/C/D", "blocked", "needs the corpus")
    else:
        problems, profile, valid = [], None, 0
        for mode in MODES:
            for scenario in store.scenario_ids:
                base = runs/mode/scenario
                if not Path(f"{base}.reconstruction.json").is_file():
                    problems.append(f"{mode}/{scenario} not run")
                    continue
                try:
                    _, pipeline, _, _, profile = validate_run(base, mode, scenario, digest, expected_profile=profile)
                    if scenario in triggers and pipeline["detection_sha256"] != triggers[scenario]:
                        raise ValueError(f"{mode}/{scenario}: detection triggers differ from configuration A")
                    valid += 1
                except (ValueError, OSError) as error:
                    problems.append(_problem(error))
        total = len(MODES) * len(store.scenario_ids)
        gate("runs B/C/D", "ready" if not problems else "missing" if valid == 0 else "invalid",
             f"{valid}/{total} valid, one shared model profile" if not problems
             else f"{valid}/{total} valid; " + "; ".join(problems))

    for name, path, loader in (("claim reviews", claim_reviews, load_reviews),
                               ("scoring contract", scoring_contract, validate_contract)):
        if not path.is_file():
            gate(name, "missing", f"{path} does not exist; `-Only review` generates the unanswered form")
        elif not key_ok:
            gate(name, "blocked", "needs the answer key, whose exact bytes it must bind")
        else:
            try:
                loaded = loader(path, digest, ground_truth)
                if name == "claim reviews":
                    expected = {(m, s) for m in MODES for s in store.scenario_ids}
                    unlabelled = sum(c.get("support") is None for run in loaded.values()
                                     for c in run.get("claims", []) if isinstance(c, dict))
                    if set(loaded) != expected or unlabelled:
                        raise ValueError(f"{len(set(loaded) & expected)}/{len(expected)} runs reviewed, "
                                         f"{unlabelled} claim(s) unlabelled")
                gate(name, "ready", f"{path} validated")
            except (ValueError, OSError) as error:
                gate(name, "invalid", f"{path}: {_problem(error)}")

    if all(g["status"] == "ready" for g in gates):
        with tempfile.TemporaryDirectory() as scratch:
            try:
                results = evaluate(corpus=corpus, runs=runs, ground_truth=ground_truth, detections=detections,
                                   out=Path(scratch)/"evaluation", claim_reviews=claim_reviews,
                                   scoring_contract=scoring_contract)
                ready = results.get("scored") is True
                gate("final score gate", "ready" if ready else "invalid",
                     "the scorer accepts every input" if ready else "the scorer ran but would not mark this scored")
            except (ValueError, OSError) as error:
                gate("final score gate", "invalid", _problem(error))
    else:
        gate("final score gate", "blocked", "needs every gate above")
    return gates


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, required=True, help="the run-evaluation.ps1 -Out folder")
    parser.add_argument("--ground-truth", type=Path, default=Path("ground_truth/private"))
    parser.add_argument("--runbooks", type=Path, default=Path("runbooks/private"))
    parser.add_argument("--claim-reviews", type=Path, help="default: <root>/review/claim_reviews.json")
    parser.add_argument("--scoring-contract", type=Path, help="default: <root>/review/scoring_contract.json")
    parser.add_argument("--json", action="store_true", help="print the gates as JSON")
    a = parser.parse_args(argv)
    gates = check(a.root, ground_truth=a.ground_truth, runbooks=a.runbooks,
                  claim_reviews=a.claim_reviews, scoring_contract=a.scoring_contract)
    if a.json:
        print(json.dumps(gates, indent=2))
    else:
        for g in gates:
            owner = f" [{g['owner']}]" if g["owner"] and g["status"] != "ready" else ""
            print(f"{g['status'].upper():8} {g['gate']}{owner}: {g['detail']}")
    return 0 if gates[-1]["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
