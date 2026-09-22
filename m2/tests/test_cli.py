"""CLI surface: every command is either implemented and honest, or fails loudly."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from m2.__main__ import EXIT_FAILED, EXIT_INVALID_INPUT, EXIT_NOT_IMPLEMENTED, EXIT_OK, build_parser, main
from m2.corpus import write_manifest, write_scenario
from m2.evtx_reader import RawRecord
from m2.manifest import load_scenario
from m2.tests.synthetic import SECURITY, SYSMON, build_scenario_dir, make_event
from m2.timeutil import iso_to_ticks

SUBCOMMANDS = ("normalise", "lookup", "query", "detect", "score")
UNIMPLEMENTED = (["detect"], ["score", "--labels", "labels.csv"])

WINDOW_START = "2026-09-21T02:05:00.0000000Z"
WINDOW_END = "2026-09-21T02:06:00.0000000Z"


def test_help_lists_every_subcommand(capsys):
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--help"])
    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    for command in SUBCOMMANDS:
        assert command in help_text


@pytest.mark.parametrize("argv", UNIMPLEMENTED)
def test_unimplemented_commands_fail_loudly(argv, capsys):
    assert main(argv) == EXIT_NOT_IMPLEMENTED
    assert argv[0] in capsys.readouterr().out


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


def _write_corpus(tmp_path: Path) -> Path:
    """A verified corpus with one 4624 and one 4625, written the way normalise writes it."""
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    out = tmp_path / "corpus"
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
