"""Prepare unanswered independent-review forms; never invent ground truth or approvals."""

import argparse
import json
from pathlib import Path

from event_processing.query import EventStore
from event_processing.detection.engine import corpus_manifest_digest
from event_processing.provenance import json_digest
from .groundtruth import load_ground_truth
from .independent import REVIEW_SCHEMA,CONTRACT_SCHEMA,key_digests
from .validation import EvaluationError,validate_run


def prepare(corpus,runs,ground_truth,out,*,allow_fake=False):
    if out.exists():
        raise EvaluationError("review output exists; choose a new directory")
    store=EventStore.load(corpus)
    digest=corpus_manifest_digest(corpus)
    load_ground_truth(ground_truth,store.scenario_ids)
    forms=[]
    expected=None
    for mode in ("single-agent","multi-agent","full"):
        for scenario in store.scenario_ids:
            rec,_,_,_,expected=validate_run(Path(runs)/mode/scenario,mode,scenario,digest,
                                            allow_fake=allow_fake,expected_profile=expected)
            forms.append({"mode":mode,"scenario_id":scenario,
                "reconstruction_sha256":json_digest(rec.model_dump(mode="json")),
                "claims":[{"claim_id":c.claim_id,"claim_sha256":json_digest(c.model_dump(mode="json")),
                    "claim_text":c.claim_text,"evidence_ids":list(c.evidence_ids),
                    "support":None,"correct_stage_ids":[],"notes":""} for c in rec.claims]})
    common={"corpus_manifest_sha256":digest,"ground_truth_sha256":key_digests(ground_truth)}
    review={"schema_version":REVIEW_SCHEMA,**common,"reviewer":"","method":"independent_human_review",
            "independent_of_verifier":False,"runs":forms}
    contract={"schema_version":CONTRACT_SCHEMA,**common,"unit":"evidence_id",
        "positive_policy":"malicious-stage-evidence-v1","exclusions":"out-of-window-and-owner-contextual-v1",
        "negative_population_reviewed":False,"f1_convention":"zero-when-precision-and-recall-defined-zero-v2",
        "approved_by":{"dataset":"","detection":"","evaluation":""}}
    out.mkdir(parents=True)
    for name,value in (("claim_reviews.json",review),("scoring_contract.json",contract)):
        (out/name).write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding="utf8")
    return out


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("corpus","runs","ground-truth","out"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--allow-fake",action="store_true")
    a=p.parse_args(argv)
    try:
        prepare(a.corpus,a.runs,a.ground_truth,a.out,allow_fake=a.allow_fake)
    except (ValueError,OSError) as error:
        p.exit(2,f"error: {error}\n")
    print(f"Unanswered review templates -> {a.out}; independent human review and owner approvals are required.")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
