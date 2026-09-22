"""CLI surface: every command is either implemented and honest, or fails loudly."""

from __future__ import annotations

from pathlib import Path

import pytest

from m2.__main__ import EXIT_FAILED, EXIT_NOT_IMPLEMENTED, EXIT_OK, build_parser, main
from m2.evtx_reader import RawRecord
from m2.tests.synthetic import SECURITY, SYSMON, build_scenario_dir

SUBCOMMANDS = ("normalise", "lookup", "query", "detect", "score")
UNIMPLEMENTED = (
    ["lookup", "S02-SEC-43584"],
    ["query", "S02", "--start", "2026-09-21T02:04:38.9439270Z", "--end", "2026-09-21T02:06:18.3126076Z"],
    ["detect"],
    ["score", "--labels", "labels.csv"],
)


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
