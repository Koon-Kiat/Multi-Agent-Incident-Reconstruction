"""CLI surface: every command is either implemented and honest, or fails loudly."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from m2.__main__ import (
    EXIT_FAILED,
    EXIT_INVALID_INPUT,
    EXIT_NOT_IMPLEMENTED,
    EXIT_OK,
    _not_implemented,
    build_parser,
    main,
)
from m2.corpus import write_manifest, write_scenario
from m2.evtx_reader import RawRecord
from m2.manifest import load_scenario
from m2.schema import NormalisedEvent
from m2.tests.synthetic import SECURITY, SYSMON, build_scenario_dir, make_event
from m2.timeutil import TICKS_PER_SECOND, iso_to_ticks

SUBCOMMANDS = ("normalise", "lookup", "query", "detect", "score")

WINDOW_START = "2026-09-21T02:05:00.0000000Z"
WINDOW_END = "2026-09-21T02:06:00.0000000Z"


def test_help_lists_every_subcommand(capsys):
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--help"])
    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    for command in SUBCOMMANDS:
        assert command in help_text


def test_every_documented_subcommand_is_dispatched_and_unknown_ones_fail_loudly(capsys):
    # Phase 0 gave `detect` and `score` an explicit "not implemented" exit. By phase 4 both are
    # implemented, so the remaining safety nets are argparse for an unknown subcommand and the
    # fallback in `main` for a subcommand added to the parser but not yet dispatched.
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["frobnicate"])
    assert exit_info.value.code != 0
    assert _not_implemented("frobnicate") == EXIT_NOT_IMPLEMENTED
    assert "frobnicate" in capsys.readouterr().out


def test_missing_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args([])
    assert exit_info.value.code != 0


def test_normalise_reports_missing_datasets_without_a_traceback(tmp_path: Path, capsys):
    code = main(["normalise", "--datasets", str(tmp_path / "absent"), "--out", str(tmp_path / "corpus")])
    assert code == EXIT_FAILED
    assert "does not exist" in capsys.readouterr().err


def test_normalise_writes_a_corpus_and_prints_a_summary(tmp_path: Path, monkeypatch, capsys):
    datasets = tmp_path / "datasets"
    build_scenario_dir(datasets, "lab")
    monkeypatch.setattr("m2.corpus.iter_records", _two_records_per_file)
    out = tmp_path / "corpus"

    assert main(["normalise", "--datasets", str(datasets), "--out", str(out)]) == EXIT_OK

    stdout = capsys.readouterr().out
    assert "SYN-B: 4 events -> SYN-B.jsonl" in stdout
    assert "total: 4 events" in stdout
    assert (out / "SYN-B.jsonl").is_file()
    assert (out / "corpus_manifest.json").is_file()


def _two_records_per_file(path: Path):
    channel = SYSMON if path.name == "Sysmon.evtx" else SECURITY
    for record_id in (1, 2):
        yield RawRecord(
            record_id=record_id,
            event_id=1 if channel == SYSMON else 4688,
            channel=channel,
            computer="MAIR-WIN11-LAB",
            filetime=0,
            event_data={},
            raw_xml="<Event/>",
        )


def _write_corpus(tmp_path: Path, events: list[NormalisedEvent] | None = None) -> Path:
    """A verified corpus, written the way normalise writes it."""
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    out = tmp_path / "corpus"
    if events is None:
        events = [
            make_event(record_id=1, event_id=4624, timestamp_ticks=iso_to_ticks("2026-09-21T02:05:30.0000000Z")),
            make_event(record_id=2, event_id=4625, timestamp_ticks=iso_to_ticks("2026-09-21T02:05:35.0000000Z")),
        ]
    write_manifest(out, [write_scenario(out, info, events)])
    return out


def test_lookup_prints_the_event_as_json(tmp_path: Path, capsys):
    corpus = _write_corpus(tmp_path)
    assert main(["lookup", "SYN-B-SEC-1", "--corpus", str(corpus)]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert (payload["evidence_id"], payload["record_id"], payload["source_event_id"]) == ("SYN-B-SEC-1", 1, 4624)


def test_lookup_separates_absent_from_malformed(tmp_path: Path, capsys):
    corpus = _write_corpus(tmp_path)
    assert main(["lookup", "SYN-B-SEC-9", "--corpus", str(corpus)]) == EXIT_FAILED
    assert "is not in" in capsys.readouterr().err
    assert main(["lookup", "nope", "--corpus", str(corpus)]) == EXIT_INVALID_INPUT
    assert "malformed" in capsys.readouterr().err


def test_lookup_reports_an_unusable_corpus_without_a_traceback(tmp_path: Path, capsys):
    assert main(["lookup", "SYN-B-SEC-1", "--corpus", str(tmp_path / "absent")]) == EXIT_FAILED
    assert "corpus manifest" in capsys.readouterr().err


def test_query_prints_one_event_per_line_and_filters(tmp_path: Path, capsys):
    corpus = _write_corpus(tmp_path)
    argv = [
        "query",
        "SYN-B",
        "--start",
        WINDOW_START,
        "--end",
        WINDOW_END,
        "--corpus",
        str(corpus),
        "--event-id",
        "4624",
    ]
    assert main(argv) == EXIT_OK
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["evidence_id"] for line in lines] == ["SYN-B-SEC-1"]


def test_query_reports_truncation_on_stderr(tmp_path: Path, capsys):
    corpus = _write_corpus(tmp_path)
    argv = ["query", "SYN-B", "--start", WINDOW_START, "--end", WINDOW_END, "--corpus", str(corpus), "--limit", "1"]
    assert main(argv) == EXIT_OK
    assert "truncated at 1 of 2 matches" in capsys.readouterr().err


def test_query_rejects_an_unusable_window(tmp_path: Path, capsys):
    corpus = _write_corpus(tmp_path)
    argv = ["query", "SYN-B", "--start", WINDOW_END, "--end", WINDOW_START, "--corpus", str(corpus)]
    assert main(argv) == EXIT_INVALID_INPUT
    assert "strictly before" in capsys.readouterr().err


def test_detect_writes_one_run_per_scenario_and_prints_a_summary(tmp_path: Path, capsys):
    window = "2026-09-21T02:05:30.0000000Z"
    base = iso_to_ticks(window)
    events = [
        make_event(record_id=record, event_id=4625, timestamp_ticks=base + record * TICKS_PER_SECOND)
        for record in (1, 2, 3)
    ]
    events.append(make_event(record_id=4, event_id=4624, timestamp_ticks=base + 4 * TICKS_PER_SECOND))
    corpus = _write_corpus(tmp_path, events)
    out = tmp_path / "detections"

    assert main(["detect", "--corpus", str(corpus), "--out", str(out)]) == EXIT_OK

    stdout = capsys.readouterr().out
    assert "SYN-B: 1 detections -> SYN-B.json" in stdout
    assert "total: 1 detections" in stdout
    run = json.loads((out / "SYN-B.json").read_text(encoding="utf-8"))
    assert run["scenario_id"] == "SYN-B"
    assert [detection["rule_id"] for detection in run["detections"]] == ["R-AUTH-01"]
    assert json.loads((out / "summary.json").read_text(encoding="utf-8"))["scenarios"][0]["total"] == 1


def test_detect_reports_an_unusable_corpus_without_a_traceback(tmp_path: Path, capsys):
    code = main(["detect", "--corpus", str(tmp_path / "absent"), "--out", str(tmp_path / "out")])
    assert code == EXIT_FAILED
    assert "corpus manifest" in capsys.readouterr().err


def _detect_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """Run `detect` over a 3-failures-then-success corpus; return (corpus, detections)."""
    base = iso_to_ticks("2026-09-21T02:05:30.0000000Z")
    events = [
        make_event(record_id=record, event_id=4625, timestamp_ticks=base + record * TICKS_PER_SECOND)
        for record in (1, 2, 3)
    ]
    events.append(make_event(record_id=4, event_id=4624, timestamp_ticks=base + 4 * TICKS_PER_SECOND))
    corpus = _write_corpus(tmp_path, events)
    out = tmp_path / "detections"
    assert main(["detect", "--corpus", str(corpus), "--out", str(out)]) == EXIT_OK
    return corpus, out


def test_score_writes_a_report_and_prints_the_metrics(tmp_path: Path, capsys):
    corpus, detections = _detect_fixture(tmp_path)
    labels = tmp_path / "labels.csv"
    labels.write_text("evidence_id,label,reason\nSYN-B-SEC-4,positive,the success\nSYN-B-SEC-1,negative,\n", encoding="utf-8")
    out = tmp_path / "scores"

    argv = [
        "score",
        "--detections",
        str(detections),
        "--labels",
        str(labels),
        "--corpus",
        str(corpus),
        "--out",
        str(out),
    ]
    assert main(argv) == EXIT_OK

    stdout = capsys.readouterr().out
    assert "overall: TP=1 FP=3 FN=0 precision=0.250 recall=1.000 f1=0.400" in stdout
    assert "SYN-B: TP=1 FP=3 FN=0" in stdout
    report = json.loads((out / "score_report.json").read_text(encoding="utf-8"))
    assert report["unit"] == "evidence_id"
    assert (report["overall"]["tp"], report["overall"]["fp"], report["overall"]["fn"]) == (1, 3, 0)


def test_score_requires_a_corpus_whenever_it_is_given_labels(tmp_path: Path, capsys):
    # A2: without the corpus a record-number typo in the label file is a silent false negative.
    _, detections = _detect_fixture(tmp_path)
    labels = tmp_path / "labels.csv"
    labels.write_text("evidence_id,label\nSYN-B-SEC-4,positive\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["score", "--detections", str(detections), "--labels", str(labels)])
    assert exit_info.value.code != 0
    assert "--corpus" in capsys.readouterr().err


def test_score_rejects_a_label_naming_an_event_the_corpus_does_not_hold(tmp_path: Path, capsys):
    corpus, detections = _detect_fixture(tmp_path)
    labels = tmp_path / "labels.csv"
    labels.write_text("evidence_id,label\nSYN-B-SEC-99,positive\n", encoding="utf-8")
    argv = ["score", "--detections", str(detections), "--labels", str(labels), "--corpus", str(corpus)]
    assert main(argv) == EXIT_INVALID_INPUT
    assert "not in the corpus being scored" in capsys.readouterr().err


def test_score_reports_a_missing_label_file_without_a_traceback(tmp_path: Path, capsys):
    corpus, detections = _detect_fixture(tmp_path)
    argv = [
        "score",
        "--detections",
        str(detections),
        "--labels",
        str(tmp_path / "absent.csv"),
        "--corpus",
        str(corpus),
    ]
    assert main(argv) == EXIT_FAILED
    assert "does not exist" in capsys.readouterr().err


def test_score_reports_a_missing_detections_directory_without_a_traceback(tmp_path: Path, capsys):
    corpus, _ = _detect_fixture(tmp_path)
    labels = tmp_path / "labels.csv"
    labels.write_text("evidence_id,label\nSYN-B-SEC-1,positive\n", encoding="utf-8")
    argv = ["score", "--detections", str(tmp_path / "absent"), "--labels", str(labels), "--corpus", str(corpus)]
    assert main(argv) == EXIT_FAILED
    assert "does not exist" in capsys.readouterr().err


def test_score_reports_an_unusable_corpus_without_a_traceback(tmp_path: Path, capsys):
    _, detections = _detect_fixture(tmp_path)
    labels = tmp_path / "labels.csv"
    labels.write_text("evidence_id,label\nSYN-B-SEC-1,positive\n", encoding="utf-8")
    argv = ["score", "--detections", str(detections), "--labels", str(labels), "--corpus", str(tmp_path / "absent")]
    assert main(argv) == EXIT_FAILED
    assert "corpus manifest" in capsys.readouterr().err


def test_score_rejects_a_malformed_label_file(tmp_path: Path, capsys):
    corpus, detections = _detect_fixture(tmp_path)
    labels = tmp_path / "labels.csv"
    labels.write_text("evidence_id,label\nSYN-B-SEC-1,maybe\n", encoding="utf-8")
    argv = ["score", "--detections", str(detections), "--labels", str(labels), "--corpus", str(corpus)]
    assert main(argv) == EXIT_INVALID_INPUT
    assert "not a valid label row" in capsys.readouterr().err
