"""``python -m evidence_verification.evaluation``: score written runs against the private key.

    python -m evidence_verification.evaluation --corpus out/corpus --runs out/runs \\
        --detections out/detections --out out/evaluation

Exit codes: 0 scored; 2 invalid input (missing key, stale or fake runs); 1 anything else.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .groundtruth import GroundTruthError
from .runner import EvaluationError, evaluate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--runs", type=Path, required=True, help="root holding single-agent/, multi-agent/ and full/")
    parser.add_argument("--detections", type=Path, help="output of `python -m event_processing detect` (rules-only detection baseline)")
    parser.add_argument("--ground-truth", type=Path, default=Path("ground_truth/private"))
    parser.add_argument("--out", type=Path, default=Path("out/evaluation"))
    parser.add_argument("--allow-fake", action="store_true", help="inspect plumbing runs; results are labelled")
    parser.add_argument("--allow-partial",action="store_true",help="inspect an incomplete comparison; never a final score")
    parser.add_argument("--claim-reviews",type=Path,help="independent claim/stage correctness annotations")
    parser.add_argument("--scoring-contract",type=Path,help="approved event-label scoring agreement")
    parser.add_argument("--label", help="e.g. 'POST-HOC re-run'; printed as a banner on every table")
    parser.add_argument("--hardware-note", default="", help="free text recorded with the results, e.g. GPU and RAM")
    args = parser.parse_args(argv)
    try:
        results = evaluate(corpus=args.corpus, runs=args.runs, ground_truth=args.ground_truth, out=args.out,
                           detections=args.detections, allow_fake=args.allow_fake, hardware_note=args.hardware_note,
                           label=args.label,allow_partial=args.allow_partial,
                           claim_reviews=args.claim_reviews,scoring_contract=args.scoring_contract)
    except (ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    scored = sum(1 for r in results["runs"] if r["status"] == "scored")
    qualification = "FINAL SCORE" if results["scored"] else ("PLUMBING ONLY" if results["plumbing_only"] else "DIAGNOSTIC ONLY")
    print(f"{scored} run(s) analysed ({qualification}) -> {args.out}")
    for configuration, totals in results["totals"].items():
        print(f"  {configuration}: stages {totals['stages_matched']}/{totals['stages_total']}, "
              f"claims aligned/neutral/unaligned {totals['claims_aligned']}/{totals['claims_neutral']}/"
              f"{totals['claims_unaligned']}, verdicts {totals['support_scoring_pass']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
