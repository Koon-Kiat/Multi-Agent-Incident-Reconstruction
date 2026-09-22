"""Command line interface for M2.

``normalise`` writes the corpus under ``--out`` (gitignored); no command writes into
``datasets/``. ``lookup`` and ``query`` read a written corpus back through
:class:`m2.query.EventStore`, so they verify the corpus digests before answering. ``detect``
runs the conventional rule catalogue over a verified corpus and writes one run file per
scenario plus ``summary.json``. ``score`` reads those run files, a label file and the corpus the
labels name (``--corpus`` is required, and every labelled ID must exist in it), and writes
``score_report.json``; it never looks for a label file itself and it invents no labels. A command
that fails for a real reason exits 1 and explains itself on stderr; invalid input (a malformed ID,
an unusable window, an unreadable label row) exits 2.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from m2.corpus import CORPUS_MANIFEST_FILENAME, CorpusOutputError, normalise_datasets
from m2.detection.engine import (
    SUMMARY_FILENAME,
    DetectionError,
    DetectionOutputError,
    corpus_manifest_digest,
    write_detections,
)
from m2.metrics import (
    ScoreCounts,
    ScoreError,
    load_detection_runs,
    load_labels,
    score,
    validate_corpus_manifest,
    write_report,
)
from m2.protected_paths import ProtectedOutputError, refuse_protected_output
from m2.query import EventStore, QueryError
from m2.schema import event_to_json

EXIT_OK = 0
EXIT_FAILED = 1
# Both mean "no result was produced": m3 uses 2 for invalid CLI input, and phase 0 used 2 for
# a command that is not implemented yet. Neither ever masquerades as success.
EXIT_NOT_IMPLEMENTED = 2
EXIT_INVALID_INPUT = 2

_CORPUS_DEFAULT = "out/corpus"


def _not_implemented(command: str) -> int:
    print(f"m2 {command}: not implemented yet (phase 0 command surface)")
    return EXIT_NOT_IMPLEMENTED


def _normalise(args: argparse.Namespace) -> int:
    try:
        manifest = normalise_datasets(Path(args.datasets), Path(args.out))
    except CorpusOutputError as error:
        # An --out the evidence tree owns is invalid input, not a failed parse: refuse before mkdir.
        print(f"m2 normalise: {error}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    except (ValueError, OSError) as error:
        print(f"m2 normalise: {error}", file=sys.stderr)
        return EXIT_FAILED
    total = 0
    for scenario in manifest.scenarios:
        total += scenario.jsonl.line_count
        print(f"{scenario.scenario_id}: {scenario.jsonl.line_count} events -> {scenario.jsonl.filename}")
    print(f"total: {total} events; manifest -> {Path(args.out) / CORPUS_MANIFEST_FILENAME}")
    return EXIT_OK


def _open_corpus(command: str, corpus: str) -> EventStore | int:
    """Load a verified store, or print why it cannot be used and return an exit code."""
    try:
        return EventStore.load(Path(corpus))
    except (QueryError, OSError) as error:
        print(f"m2 {command}: {error}", file=sys.stderr)
        return EXIT_FAILED


def _lookup(args: argparse.Namespace) -> int:
    store = _open_corpus("lookup", args.corpus)
    if isinstance(store, int):
        return store
    result = store.lookup(args.evidence_id)
    if result.status == "invalid_id":
        print(f"m2 lookup: malformed evidence_id {args.evidence_id!r}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    if result.status == "not_found" or result.event is None:
        print(f"m2 lookup: {args.evidence_id} is not in {args.corpus}", file=sys.stderr)
        return EXIT_FAILED
    print(event_to_json(result.event))
    return EXIT_OK


def _query(args: argparse.Namespace) -> int:
    store = _open_corpus("query", args.corpus)
    if isinstance(store, int):
        return store
    try:
        result = store.query(
            args.scenario_id,
            args.start,
            args.end,
            channels=args.channels,
            event_ids=args.event_ids,
            host=args.host,
            user=args.user,
            limit=args.limit,
        )
    except QueryError as error:
        print(f"m2 query: {error}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    for event in result.events:
        print(event_to_json(event))
    if result.truncated:
        print(f"m2 query: truncated at {len(result.events)} of {result.total_matched} matches", file=sys.stderr)
    return EXIT_OK



def _detect(args: argparse.Namespace) -> int:
    try:
        summary = write_detections(Path(args.corpus), Path(args.out))
    except DetectionOutputError as error:
        # An unusable --out is invalid input, not a failed detection: refuse before reading.
        print(f"m2 detect: {error}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    except (ValueError, OSError) as error:
        print(f"m2 detect: {error}", file=sys.stderr)
        return EXIT_FAILED
    total = 0
    for scenario in summary.scenarios:
        total += scenario.total
        print(f"{scenario.scenario_id}: {scenario.total} detections -> {scenario.scenario_id}.json")
    print(f"total: {total} detections; summary -> {Path(args.out) / SUMMARY_FILENAME}")
    return EXIT_OK


def _metric(value: float | None) -> str:
    """A metric for the console: three decimals, or ``undefined`` when it has no denominator."""
    return "undefined" if value is None else f"{value:.3f}"


def _score_line(label: str, counts: ScoreCounts) -> str:
    return (
        f"{label}: TP={counts.tp} FP={counts.fp} FN={counts.fn} "
        f"precision={_metric(counts.precision)} recall={_metric(counts.recall)} "
        f"f1={_metric(counts.f1)} (flagged={counts.flagged}, positives={counts.positives}, "
        f"excluded={counts.excluded}, flagged_excluded={counts.flagged_excluded}, "
        f"unflagged_excluded={counts.unflagged_excluded})"
    )


def _score(args: argparse.Namespace) -> int:
    detections_dir = Path(args.detections)
    labels_path = Path(args.labels)
    try:
        refuse_protected_output(Path(args.out))
    except ProtectedOutputError as error:
        print(f"m2 score: {error}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    if not labels_path.is_file():
        print(f"m2 score: label file {labels_path} does not exist", file=sys.stderr)
        return EXIT_FAILED
    if not detections_dir.is_dir():
        print(f"m2 score: detections directory {detections_dir} does not exist", file=sys.stderr)
        return EXIT_FAILED
    store = _open_corpus("score", args.corpus)
    if isinstance(store, int):
        return store
    try:
        digest = corpus_manifest_digest(Path(args.corpus))
    except DetectionError as error:
        print(f"m2 score: {error}", file=sys.stderr)
        return EXIT_FAILED
    try:
        runs = load_detection_runs(detections_dir)
        rows = load_labels(labels_path)
    except ScoreError as error:
        print(f"m2 score: {error}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    try:
        # B1: a run computed from another corpus revision is a failed run, not malformed input.
        validate_corpus_manifest(runs, digest)
    except ScoreError as error:
        print(f"m2 score: {error}", file=sys.stderr)
        return EXIT_FAILED
    try:
        report = score(
            runs,
            rows,
            known_evidence_ids=store.evidence_ids,
            corpus_manifest_sha256=digest,
        )
        path = write_report(report, Path(args.out))
    except (ScoreError, ProtectedOutputError) as error:
        print(f"m2 score: {error}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    except OSError as error:
        print(f"m2 score: {error}", file=sys.stderr)
        return EXIT_FAILED
    print(_score_line("overall", report.overall))
    for scenario in report.scenarios:
        print(_score_line(scenario.scenario_id, scenario.counts))
    print(f"report -> {path}")
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
    detect.add_argument(
        "--out",
        default="out/detections",
        help=(
            "a directory detect owns; stale m2 run files left there by an earlier run are removed, "
            "while every other file is left alone; datasets/ and ground_truth/ are refused"
        ),
    )

    score = subcommands.add_parser("score", help="score detection output against an agreed label file")
    score.add_argument("--detections", default="out/detections")
    score.add_argument("--labels", required=True)
    score.add_argument(
        "--corpus",
        required=True,
        help="the corpus the labels name; every labelled evidence_id must exist in it",
    )
    score.add_argument("--out", default="out/scores")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "normalise":
        return _normalise(args)
    if args.command == "lookup":
        return _lookup(args)
    if args.command == "query":
        return _query(args)
    if args.command == "detect":
        return _detect(args)
    if args.command == "score":
        return _score(args)
    return _not_implemented(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
