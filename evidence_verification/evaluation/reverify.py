"""Post-hoc re-verification: re-judge SAVED claims with a different verifier, into a separate directory.

The scored run is the primary result and is never modified. This copies it to ``--to`` and replaces only the
full-mode verification files there, leaving every claim, investigation and timing of the other phases exactly as
scored. Because the claims do not change, any difference in the evaluation is the verifier's alone. The output is
meant to be evaluated with ``--label`` so every table says it is post-hoc.

    python -m evidence_verification.evaluation.reverify --corpus out/corpus --source out/scored/runs `
        --to out/posthoc/runs --verifier evidence_verification.agent:make_agent_verifier

Refuses a destination that exists, and a destination inside the source, so the scored result cannot be overwritten.
"""

from __future__ import annotations

import argparse
import json
import hashlib
import shutil
import sys
from tempfile import TemporaryDirectory
from pathlib import Path

from event_processing.query import EventStore
from event_processing.detection.engine import corpus_manifest_digest
from incident_reconstruction.claims import Reconstruction
from incident_reconstruction.verification import load_verifier, run_verification


def reverify(*, corpus: Path, source: Path, destination: Path, verifier_spec: str) -> dict:
    source, destination = source.resolve(), destination.resolve()
    if destination.exists():
        raise FileExistsError(f"{destination} already exists; choose a new directory (the scored run is never overwritten)")
    if destination == source or source in destination.parents or destination in source.parents:
        raise ValueError("the destination may not be, contain or sit inside the scored run")
    store = EventStore.load(corpus)
    digest = corpus_manifest_digest(corpus)
    paths = sorted((source/"full").glob("*.reconstruction.json"))
    if not paths:
        raise ValueError("source has no saved full-mode reconstructions")
    for path in paths:
        rec=Reconstruction.model_validate_json(path.read_text(encoding="utf-8"))
        pipeline=json.loads(path.with_name(f"{rec.scenario_id}.pipeline.json").read_text(encoding="utf-8"))
        if (rec.mode != "full" or rec.corpus_manifest_sha256 != digest
                or pipeline.get("corpus_manifest_sha256") != digest or pipeline.get("scenario_id") != rec.scenario_id):
            raise ValueError("source reconstruction/pipeline belongs to a different corpus or scenario")
    destination.parent.mkdir(parents=True,exist_ok=True)
    with TemporaryDirectory(prefix=".reverify-",dir=destination.parent) as temporary:
        staged=Path(temporary)/"runs"
        summary=_rewrite(store,source,staged,verifier_spec)
        staged.rename(destination)
    return summary


def _rewrite(store, source, destination, verifier_spec):
    shutil.copytree(source, destination)
    summary = {}
    for reconstruction_path in sorted((destination / "full").glob("*.reconstruction.json")):
        scenario = reconstruction_path.name.split(".")[0]
        reconstruction = Reconstruction.model_validate_json(reconstruction_path.read_text(encoding="utf-8"))
        report = run_verification(load_verifier(verifier_spec), reconstruction, store)
        (destination / "full" / f"{scenario}.verification.json").write_text(
            report.model_dump_json(indent=2), encoding="utf-8")
        pipeline_path = destination / "full" / f"{scenario}.pipeline.json"
        pipeline = json.loads(pipeline_path.read_text(encoding="utf-8"))
        original_seconds = next(p["seconds"] for p in pipeline["phases"] if p["phase"] == "verification")
        for phase in pipeline["phases"]:
            if phase["phase"] == "verification":
                phase["seconds"] = report.latency_seconds
        pipeline["latency_seconds"] = round(sum(p["seconds"] for p in pipeline["phases"]), 3)
        old_calls=pipeline.get("verification_model_calls",0)
        new_calls=report.verifier.get("agent_model_calls",0)
        if type(old_calls) is not int or type(new_calls) is not int or min(old_calls,new_calls)<0:
            raise ValueError("invalid verification call accounting")
        pipeline["model_calls"]=pipeline["model_calls"]-old_calls+new_calls
        pipeline["verification_model_calls"]=new_calls
        pipeline["verdicts"] = report.verdicts() and {v: list(report.verdicts().values()).count(v)
                                                      for v in sorted(set(report.verdicts().values()))}
        pipeline["post_hoc"] = {"note": "verification re-run on the saved claims; every other phase is as scored",
                                "verification_seconds_as_scored": original_seconds, "verifier": verifier_spec}
        verification_path = destination/"full"/f"{scenario}.verification.json"
        pipeline.setdefault("artifact_sha256",{})[verification_path.name] = hashlib.sha256(verification_path.read_bytes()).hexdigest()
        pipeline_path.write_text(json.dumps(pipeline, indent=2), encoding="utf-8")
        summary[scenario] = {"verdicts": pipeline["verdicts"], "integrity_notes": list(report.integrity_notes),
                             "verifier": report.verifier}
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True, help="the scored runs directory (never modified)")
    parser.add_argument("--to", type=Path, required=True, dest="destination", help="a new directory")
    parser.add_argument("--verifier", required=True, help="package.module:factory, as for the orchestrator")
    args = parser.parse_args(argv)
    try:
        summary = reverify(corpus=args.corpus, source=args.source, destination=args.destination,
                           verifier_spec=args.verifier)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for scenario, item in summary.items():
        meta = item["verifier"]
        print(f"{scenario}: verdicts {item['verdicts']}; prompt {meta.get('prompt_version')}; "
              f"consulted {meta.get('agent_consulted')}, lowered {meta.get('agent_lowered')}, failed {meta.get('agent_failed')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
