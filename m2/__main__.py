"""Command line interface for M2.

``normalise`` writes the corpus under ``--out`` (gitignored); no command writes into
``datasets/``. Every other handler still reports that it is not implemented yet and exits
with status 2, so an unimplemented command can never look like a successful run. A command
that fails for a real reason exits 1 and explains itself on stderr.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from m2.corpus import CORPUS_MANIFEST_FILENAME, normalise_datasets

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_NOT_IMPLEMENTED = 2

_CORPUS_DEFAULT = "out/corpus"


def _not_implemented(command: str) -> int:
    print(f"m2 {command}: not implemented yet (phase 0 command surface)")
    return EXIT_NOT_IMPLEMENTED


def _normalise(args: argparse.Namespace) -> int:
    try:
        manifest = normalise_datasets(Path(args.datasets), Path(args.out))
    except (ValueError, OSError) as error:
        print(f"m2 normalise: {error}", file=sys.stderr)
        return EXIT_FAILED
    total = 0
    for scenario in manifest.scenarios:
        total += scenario.jsonl.line_count
        print(f"{scenario.scenario_id}: {scenario.jsonl.line_count} events -> {scenario.jsonl.filename}")
    print(f"total: {total} events; manifest -> {Path(args.out) / CORPUS_MANIFEST_FILENAME}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """Return the M2 argument parser, including every documented subcommand."""
    parser = argparse.ArgumentParser(prog="m2", description="Normalise, query and detect over the MAIR EVTX corpus")
    subcommands = parser.add_subparsers(dest="command", required=True)

    normalise = subcommands.add_parser("normalise", help="parse datasets/S0*/raw/*.evtx into a normalised corpus")
    normalise.add_argument("--datasets", default="datasets")
    normalise.add_argument("--out", default=_CORPUS_DEFAULT)

    lookup = subcommands.add_parser("lookup", help="resolve one evidence_id against a corpus")
    lookup.add_argument("evidence_id")
    lookup.add_argument("--corpus", default=_CORPUS_DEFAULT)

    query = subcommands.add_parser("query", help="query one scenario over a UTC [start, end) window")
    query.add_argument("scenario_id")
    query.add_argument("--start", required=True, help="inclusive UTC ISO 8601 timestamp")
    query.add_argument("--end", required=True, help="exclusive UTC ISO 8601 timestamp")
    query.add_argument("--corpus", default=_CORPUS_DEFAULT)
    query.add_argument("--channel", action="append", dest="channels", help="repeatable exact channel filter")
    query.add_argument("--event-id", action="append", dest="event_ids", type=int, help="repeatable exact Event ID filter")
    query.add_argument("--host")
    query.add_argument("--user")
    query.add_argument("--limit", type=int, default=100)

    detect = subcommands.add_parser("detect", help="run the conventional detection baseline over a corpus")
    detect.add_argument("--corpus", default=_CORPUS_DEFAULT)
    detect.add_argument("--out", default="out/detections")

    score = subcommands.add_parser("score", help="score detection output against an agreed label file")
    score.add_argument("--detections", default="out/detections")
    score.add_argument("--labels", required=True)
    score.add_argument("--out", default="out/scores")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "normalise":
        return _normalise(args)
    return _not_implemented(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
