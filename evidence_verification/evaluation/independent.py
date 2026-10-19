"""Independent annotations, never inferred from the system's own verdicts.

Templates contain no answers. Reviewers read the lab key and original records,
then label each immutable claim. A verifier cannot supply its own answer key.
"""

import hashlib
import json
from pathlib import Path
from itertools import combinations

from event_processing.provenance import json_digest
from .validation import EvaluationError
from .scoring import rate

REVIEW_SCHEMA = "independent-claim-review-v1"
CONTRACT_SCHEMA = "detection-scoring-contract-v1"
SUPPORT = ("supported","partially_supported","unsupported","uncertain")


def key_digests(directory):
    directory=Path(directory)
    paths=list(directory.glob("*_ground_truth.csv"))
    exclusions=directory/"scoring_exclusions.json"
    if exclusions.is_file():
        paths.append(exclusions)
    return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def read_document(path):
    try:
        result = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if not isinstance(result,dict):
            raise ValueError("expected object")
        return result
    except (OSError,ValueError) as error:
        raise EvaluationError(f"invalid independent review/contract {Path(path).name}") from error


def load_reviews(path, digest, ground_truth):
    if path is None:
        return None
    doc = read_document(path)
    if (doc.get("schema_version") != REVIEW_SCHEMA or doc.get("corpus_manifest_sha256") != digest
            or doc.get("ground_truth_sha256") != key_digests(ground_truth)
            or doc.get("method") != "independent_human_review"
            or doc.get("independent_of_verifier") is not True
            or not isinstance(doc.get("reviewer"),str) or not doc["reviewer"].strip()
            or not isinstance(doc.get("runs"),list)):
        raise EvaluationError("independent claim reviews are incomplete, stale or not independently adjudicated")
    indexed = {}
    for run in doc["runs"]:
        if (not isinstance(run,dict) or run.get("mode") not in ("single-agent","multi-agent","full")
                or not isinstance(run.get("scenario_id"),str)):
            raise EvaluationError("invalid independent review run identity")
        key = (run.get("mode"),run.get("scenario_id"))
        if key in indexed:
            raise EvaluationError("duplicate run in independent claim reviews")
        indexed[key] = run
    return indexed


def semantic_score(review, reconstruction, stages, verdicts, incomplete_ids=()):
    if review is None:
        return {"status":"not_independently_reviewed","stages_correct":None,"correct_stage_recall":None}
    if review.get("reconstruction_sha256") != json_digest(reconstruction.model_dump(mode="json")):
        raise EvaluationError("independent review belongs to different reconstruction content")
    items = review.get("claims")
    if not isinstance(items,list):
        raise EvaluationError("independent review claims must be a list")
    if any(not isinstance(item,dict) or not isinstance(item.get("claim_id"),str) for item in items):
        raise EvaluationError("independent review claims require string claim IDs")
    by_id = {item["claim_id"]:item for item in items}
    if len(by_id) != len(items) or set(by_id) != {c.claim_id for c in reconstruction.claims}:
        raise EvaluationError("independent review must cover every claim exactly once")
    stage_by_id = {s.stage_id:s for s in stages}
    first = {}
    counts = {s:0 for s in SUPPORT}
    tp=fp=fn=tn=0
    abstentions={"supported":0,"unsupported":0}
    incomplete_ids=set(incomplete_ids)
    for claim in reconstruction.claims:
        item = by_id[claim.claim_id]
        if (item.get("claim_sha256") != json_digest(claim.model_dump(mode="json"))
                or item.get("support") not in SUPPORT or not isinstance(item.get("notes"),str)
                or not item["notes"].strip() or not isinstance(item.get("correct_stage_ids"),list)):
            raise EvaluationError(f"claim {claim.claim_id}: incomplete or stale independent annotation")
        support = item["support"]
        counts[support] += 1
        correct = item["correct_stage_ids"]
        if any(not isinstance(sid,str) for sid in correct) or len(correct) != len(set(correct)) or set(correct)-set(stage_by_id):
            raise EvaluationError("independent annotation names duplicate or unknown stages")
        if correct and support != "supported":
            raise EvaluationError("a stage match must be independently supported as stated")
        for sid in correct:
            if not set(claim.evidence_ids)&set(stage_by_id[sid].evidence_ids):
                raise EvaluationError("a correct stage requires its own cited source evidence")
            first[sid] = min(first.get(sid,claim.position),claim.position)
        # Fully supported/unsupported cases form a labelled detection audit.
        # Partial/uncertain labels stay separate rather than becoming truth.
        if support in ("supported","unsupported"):
            if claim.claim_id in incomplete_ids:
                # Failure to complete verification is not a content judgment.
                # An unsupported claim missed through failure still reduces
                # recall; a supported claim is an abstention, not a false alarm.
                abstentions[support]+=1
                fn+=support=="unsupported"
                continue
            predicted = verdicts[claim.claim_id] != "confirmed"
            actual = support == "unsupported"
            tp += predicted and actual; fp += predicted and not actual
            fn += not predicted and actual; tn += not predicted and not actual
    concordant=discordant=ties=0
    for a,b in combinations(sorted(first,key=lambda sid:stage_by_id[sid].order),2):
        concordant += first[a]<first[b]; discordant += first[a]>first[b]; ties += first[a]==first[b]
    return {"status":"independently_reviewed","claims":len(items),"support_labels":counts,
        "stages_correct":len(first),"stages_total":len(stages),"correct_stage_recall":rate(len(first),len(stages)),
        "order_concordant":concordant,"order_discordant":discordant,"order_ties":ties,
        "order_accuracy":rate(concordant,concordant+discordant),
        "unsupported_claim_detection":{"tp":tp,"fp":fp,"fn":fn,"tn":tn,
            "operational_abstentions":abstentions,
            "decision_coverage":rate(tp+fp+tn+fn-abstentions["unsupported"],counts["supported"]+counts["unsupported"]),
            "precision":rate(tp,tp+fp),"recall":rate(tp,tp+fn)}}


def validate_contract(path,digest,ground_truth):
    if path is None:
        return None
    doc = read_document(path)
    owners = doc.get("approved_by",{})
    if not isinstance(owners,dict):
        raise EvaluationError("approved_by must identify all three owners")
    if (doc.get("schema_version") != CONTRACT_SCHEMA or doc.get("corpus_manifest_sha256") != digest
            or doc.get("ground_truth_sha256") != key_digests(ground_truth)
            or doc.get("unit") != "evidence_id" or doc.get("positive_policy") != "malicious-stage-evidence-v1"
            or doc.get("exclusions") != "out-of-window-and-owner-contextual-v1"
            or doc.get("negative_population_reviewed") is not True
            or doc.get("f1_convention") != "zero-when-precision-and-recall-defined-zero-v2"
            or any(not isinstance(owners.get(role),str) or not owners[role].strip()
                   for role in ("dataset","detection","evaluation"))):
        raise EvaluationError("detection scoring contract is stale, unapproved or incomplete")
    return doc
