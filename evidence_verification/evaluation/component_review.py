"""Blind human review of a component run's claims against their cited records.

``prepare`` shuffles every claim of the given reconstructions under a neutral code (R01, R02, ...) and
writes a reading packet, an unanswered label form and a sealed code-to-claim mapping. The packet shows
the claim text and the recorded fields of the records the verifier was given. It never shows a claim
ID, a verifier verdict, a deterministic check result, the orchestrator's rationale or any answer key.

``score`` runs only after a named reviewer has completed every label. It checks that the claims, the
corpus and the packet are unchanged, unblinds the codes and joins each label to the verifier verdict
recorded for that claim. The outcome rules are fixed below and printed in the packet before anyone
labels, so they cannot be chosen after the verdicts are seen. Labels are never inferred.

    python -m evidence_verification.evaluation.component_review prepare \\
        --corpus out/c/corpus --runs out/c/runs --out out/semantic-review
    python -m evidence_verification.evaluation.component_review score \\
        --packet out/semantic-review --corpus out/c/corpus --runs out/c/runs \\
        --verdicts docs/validation/correctness-2026-10-20.json --out out/semantic-review-result
"""

import argparse
import hashlib
import json
import random
import re
from pathlib import Path

from event_processing.detection.engine import corpus_manifest_digest
from event_processing.provenance import implementation_digest, json_digest
from event_processing.query import EventStore
from incident_reconstruction.claims import Reconstruction
from .independent import SUPPORT
from .scoring import rate
from .validation import EvaluationError, load

LABELS_SCHEMA = "blind-claim-review-labels-v1"
MAPPING_SCHEMA = "blind-claim-review-mapping-v1"
RESULT_SCHEMA = "blind-claim-review-result-v1"
METHOD = "blind_human_review"
ASSERTION_SUPPORT = ("supported", "unsupported", "uncertain")
# (verifier lowered the claim, reviewer's overall label) -> outcome. "Not fully supported" means
# partially_supported or unsupported: either justifies a lowered verdict.
OUTCOMES = {
    (True, "supported"): "false_alarm", (True, "partially_supported"): "justified",
    (True, "unsupported"): "justified", (True, "uncertain"): "unresolved",
    (False, "supported"): "correct", (False, "partially_supported"): "missed",
    (False, "unsupported"): "missed", (False, "uncertain"): "unresolved",
}
_TEMPLATE = re.compile(r"^(?P<behaviour>.+) observed from (?P<start>\S+) to (?P<end>\S+)\.$")
_SOURCES = {"Security": "Security", "Microsoft-Windows-Sysmon/Operational": "Sysmon"}


def assertions(claim_text):
    """The claim's checkable parts. The fake narrator's template splits in two; anything else stays whole."""
    match = _TEMPLATE.match(claim_text)
    if not match:
        return [claim_text]
    return [f"The recorded activity is: {match['behaviour']}",
            f"It was observed from {match['start']} to {match['end']}"]


def _reconstructions(corpus, runs, mode):
    store = EventStore.load(corpus)
    digest = corpus_manifest_digest(corpus)
    recs = []
    for scenario in store.scenario_ids:
        rec = load(Path(runs)/mode/f"{scenario}.reconstruction.json", Reconstruction)
        if rec.scenario_id != scenario or rec.corpus_manifest_sha256 != digest:
            raise EvaluationError(f"{scenario}: reconstruction belongs to a different scenario or corpus")
        recs.append(rec)
    return store, digest, recs


def _code(value):
    """A value shown verbatim: a table-safe code span, so paths, underscores and backticks stay literal."""
    text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    if not text:
        return "(empty)"
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text[0] == "`" or text[-1] == "`" else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _record_table(store, evidence_ids):
    events = []
    for eid in evidence_ids:
        found = store.lookup(eid)
        if found.event is None:
            raise EvaluationError(f"cited record {eid} is not in the corpus")
        events.append(found.event)
    rows = ["| Time (UTC) | Evidence ID | Source | Host | User | Recorded fields |", "|---|---|---|---|---|---|"]
    for e in sorted(events, key=lambda e: (e.timestamp_ticks, e.evidence_id)):
        fields = "<br>".join(f"{_code(k)} = {_code(v)}" for k, v in e.event_data.items()) or "(none)"
        rows.append(f"| {e.timestamp_utc} | {e.evidence_id} | {_SOURCES.get(e.channel, e.channel)} {e.source_event_id} "
                    f"| {_code(e.host or '')} | {_code(e.user or '')} | {fields} |")
    return "\n".join(rows)


def _packet(entries, store, corpus):
    lines = ["# Blind claim review packet", "",
        f"{len(entries)} claims, shuffled under neutral codes. For each claim, decide from the records below",
        "whether every assertion it makes is stated by, or follows directly from, those records (counts, time",
        "spans and paths may be worked out from the records). Do not consult verifier output, reports,",
        "ground truth or runbooks, and do not open `sealed/`.", "",
        "Label each assertion `supported`, `unsupported` or `uncertain`, then the claim as a whole",
        "`supported`, `partially_supported`, `unsupported` or `uncertain`, with a note saying why. A claim is",
        "`supported` only if every assertion is. Record labels in `labels.json`, together with your name, the",
        "date and `independent_of_verifier: true` once you have labelled without seeing verifier output. Use",
        "`disclosures` for anything you already knew about the claims or verdicts before labelling.", "",
        "Cited records are what the claim cites. Context records are linked to the same stage and were also",
        "shown to the verifier; they are background, not automatically part of what the claim asserts.",
        f"To see a record's original XML: `python -m event_processing lookup --corpus {corpus} <evidence-id>`.", "",
        "## Outcome rules, fixed before labelling", "",
        "After every claim is labelled, each code is unblinded and compared with the verifier's verdict:", "",
        "| Verifier | Your overall label | Outcome |", "|---|---|---|"]
    for (lowered, support), outcome in OUTCOMES.items():
        lines.append(f"| {'lowered' if lowered else 'confirmed'} | {support} | {outcome} |")
    for code, claim in entries:
        lines += ["", f"## {code}", "", f"> {_code(claim.claim_text)}", "", "Assertions:", ""]
        lines += [f"{n}. A{n}: {text}" for n, text in enumerate(assertions(claim.claim_text), 1)]
        context = [eid for eid in claim.context_evidence_ids if eid not in claim.evidence_ids]
        lines += ["", f"### Cited records ({len(claim.evidence_ids)})", "", _record_table(store, claim.evidence_ids)]
        if context:
            lines += ["", f"### Context records ({len(context)})", "", _record_table(store, context)]
    return "\n".join(lines) + "\n"


def prepare(corpus, runs, out, *, mode="multi-agent", rng=None):
    out = Path(out)
    if out.exists():
        raise EvaluationError("review output exists; choose a new directory")
    store, digest, recs = _reconstructions(corpus, runs, mode)
    claims = [(rec, claim) for rec in recs for claim in rec.claims]
    if not claims:
        raise EvaluationError("no claims to review")
    (rng or random.SystemRandom()).shuffle(claims)
    entries = [(f"R{n:02d}", claim) for n, (_, claim) in enumerate(claims, 1)]
    packet = _packet(entries, store, corpus)
    packet_sha = hashlib.sha256(packet.encode("utf-8")).hexdigest()
    labels = {"schema_version": LABELS_SCHEMA, "packet_sha256": packet_sha, "reviewer": "", "review_date": "",
        "method": METHOD, "independent_of_verifier": False, "disclosures": "",
        "claims": [{"code": code, "claim_text": claim.claim_text,
            "assertions": [{"id": f"A{n}", "text": text, "support": None, "note": ""}
                           for n, text in enumerate(assertions(claim.claim_text), 1)],
            "support": None, "notes": ""} for code, claim in entries]}
    mapping = {"schema_version": MAPPING_SCHEMA, "corpus_manifest_sha256": digest, "mode": mode,
        "implementation_sha256": implementation_digest(), "packet_sha256": packet_sha,
        "claims": {code: {"scenario_id": rec.scenario_id, "claim_id": claim.claim_id,
            "claim_sha256": json_digest(claim.model_dump(mode="json"))}
            for code, (rec, claim) in zip((c for c, _ in entries), claims)}}
    (out/"sealed").mkdir(parents=True)
    (out/"packet.md").write_text(packet, encoding="utf-8", newline="\n")
    for path, doc in ((out/"labels.json", labels), (out/"sealed"/"mapping.json", mapping)):
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return out


def _read(path):
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as error:
        raise EvaluationError(f"unreadable {Path(path).name}") from error
    if not isinstance(doc, dict):
        raise EvaluationError(f"{Path(path).name} must be an object")
    return doc


def _checked_labels(labels, codes):
    if (labels.get("schema_version") != LABELS_SCHEMA or labels.get("method") != METHOD
            or labels.get("independent_of_verifier") is not True
            or any(not isinstance(labels.get(k), str) or not labels[k].strip() for k in ("reviewer", "review_date"))
            or not isinstance(labels.get("disclosures"), str) or not isinstance(labels.get("claims"), list)):
        raise EvaluationError("labels need a named reviewer, a date and an attested blind, independent review")
    by_code = {}
    for item in labels["claims"]:
        code = item.get("code") if isinstance(item, dict) else None
        if code in by_code:
            raise EvaluationError(f"{code}: labelled twice")
        by_code[code] = item
    if set(by_code) != set(codes):
        raise EvaluationError("labels must cover every packet code exactly once")
    for code, item in by_code.items():
        parts = item.get("assertions")
        if (item.get("support") not in SUPPORT or not isinstance(item.get("notes"), str) or not item["notes"].strip()
                or not isinstance(parts, list) or not parts
                or any(not isinstance(p, dict) or p.get("support") not in ASSERTION_SUPPORT for p in parts)):
            raise EvaluationError(f"{code}: incomplete label")
        support = {p["support"] for p in parts}
        if (item["support"] == "supported") != (support == {"supported"}):
            raise EvaluationError(f"{code}: a claim is supported exactly when every assertion is")
        if "unsupported" in support and item["support"] not in ("partially_supported", "unsupported"):
            raise EvaluationError(f"{code}: an unsupported assertion makes the claim partially supported or unsupported")
    return by_code


def _verifier_verdicts(audit, claim_ids):
    component = audit.get("real_corpus_component")
    if not isinstance(component, dict) or not isinstance(component.get("lowered_claims"), list):
        raise EvaluationError("verdict file has no real_corpus_component.lowered_claims")
    lowered = {c.get("claim_id"): c.get("verdict") for c in component["lowered_claims"] if isinstance(c, dict)}
    counts = component.get("verdicts", {})
    if (len(lowered) != len(component["lowered_claims"]) or set(lowered) - set(claim_ids)
            or "confirmed" in lowered.values() or component.get("cases") != len(claim_ids)
            or counts.get("confirmed") != len(claim_ids) - len(lowered)):
        raise EvaluationError("verdict file does not describe exactly these claims")
    return {cid: lowered.get(cid, "confirmed") for cid in claim_ids}


def score(packet, corpus, runs, verdicts, out):
    packet, out = Path(packet), Path(out)
    if out.exists():
        raise EvaluationError("result output exists; choose a new directory")
    mapping = _read(packet/"sealed"/"mapping.json")
    labels_path = packet/"labels.json"
    labels = _read(labels_path)
    packet_sha = hashlib.sha256((packet/"packet.md").read_bytes()).hexdigest()
    if mapping.get("schema_version") != MAPPING_SCHEMA or not isinstance(mapping.get("claims"), dict):
        raise EvaluationError("invalid sealed mapping")
    if not (packet_sha == mapping.get("packet_sha256") == labels.get("packet_sha256")):
        raise EvaluationError("packet, labels and sealed mapping do not belong together")
    by_code = _checked_labels(labels, mapping["claims"])
    _, digest, recs = _reconstructions(corpus, runs, mapping.get("mode"))
    if digest != mapping.get("corpus_manifest_sha256"):
        raise EvaluationError("corpus changed since the packet was prepared")
    current = {c.claim_id: (rec.scenario_id, c) for rec in recs for c in rec.claims}
    if len(current) != len(mapping["claims"]):
        raise EvaluationError("claim set changed since the packet was prepared")
    verdict_by_id = _verifier_verdicts(_read(verdicts), list(current))
    rows = []
    for code in sorted(mapping["claims"]):
        sealed, label = mapping["claims"][code], by_code[code]
        scenario, claim = current.get(sealed.get("claim_id"), (None, None))
        if claim is None or json_digest(claim.model_dump(mode="json")) != sealed.get("claim_sha256"):
            raise EvaluationError(f"{code}: claim changed since the packet was prepared")
        verdict = verdict_by_id[claim.claim_id]
        rows.append({"code": code, "scenario_id": scenario, "claim_id": claim.claim_id,
            "claim_sha256": sealed["claim_sha256"], "claim_text": claim.claim_text,
            "assertions": label["assertions"], "support": label["support"], "notes": label["notes"],
            "verifier_verdict": verdict, "outcome": OUTCOMES[(verdict != "confirmed", label["support"])]})
    tally = {o: sum(r["outcome"] == o for r in rows) for o in sorted(set(OUTCOMES.values()))}
    tp, fp, fn, tn = tally["justified"], tally["false_alarm"], tally["missed"], tally["correct"]
    result = {"schema_version": RESULT_SCHEMA, "method": METHOD, "reviewer": labels["reviewer"],
        "review_date": labels["review_date"], "independent_of_verifier": True, "disclosures": labels["disclosures"],
        "corpus_manifest_sha256": digest, "mode": mapping["mode"],
        "claims_implementation_sha256": mapping.get("implementation_sha256"), "packet_sha256": packet_sha,
        "labels_sha256": hashlib.sha256(labels_path.read_bytes()).hexdigest(),
        "verdict_source": {"file": Path(verdicts).name, "sha256": hashlib.sha256(Path(verdicts).read_bytes()).hexdigest()},
        "claims": rows, "outcomes": tally,
        "lowered_claim_review": {"lowered": sum(r["verifier_verdict"] != "confirmed" for r in rows),
            "justified": tp, "false_alarm": fp, "unresolved": sum(r["outcome"] == "unresolved"
                                                                  and r["verifier_verdict"] != "confirmed" for r in rows)},
        # Positive = the reviewer found the claim not fully supported; unresolved labels are left out.
        "not_fully_supported_detection": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": rate(tp, tp + fp), "recall": rate(tp, tp + fn)}}
    out.mkdir(parents=True)
    (out/"result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare", help="write an unanswered blind review packet")
    for name in ("corpus", "runs", "out"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--mode", default="multi-agent", choices=("single-agent", "multi-agent", "full"))
    s = commands.add_parser("score", help="unblind completed labels and compare them with verifier verdicts")
    for name in ("packet", "corpus", "runs", "verdicts", "out"):
        s.add_argument("--" + name, type=Path, required=True)
    a = parser.parse_args(argv)
    try:
        if a.command == "prepare":
            prepare(a.corpus, a.runs, a.out, mode=a.mode)
            print(f"Unanswered blind review packet -> {a.out}; do not open {a.out / 'sealed'} before labelling.")
        else:
            result = score(a.packet, a.corpus, a.runs, a.verdicts, a.out)
            print(json.dumps({"outcomes": result["outcomes"], "lowered_claim_review": result["lowered_claim_review"]}))
    except (ValueError, OSError) as error:
        parser.exit(2, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
