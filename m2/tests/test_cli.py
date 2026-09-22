"""Phase 0 acceptance: the CLI command surface exists and never fakes success."""

from __future__ import annotations

import pytest

from m2.__main__ import EXIT_NOT_IMPLEMENTED, build_parser, main

SUBCOMMANDS = ("normalise", "lookup", "query", "detect", "score")


def test_help_lists_every_subcommand(capsys):
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--help"])
    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    for command in SUBCOMMANDS:
        assert command in help_text


@pytest.mark.parametrize(
    "argv",
    [
        ["normalise"],
        ["lookup", "S02-SEC-43584"],
        ["query", "S02", "--start", "2026-09-21T02:04:38.9439270Z", "--end", "2026-09-21T02:06:18.3126076Z"],
        ["detect"],
        ["score", "--labels", "labels.csv"],
    ],
)
def test_unimplemented_commands_fail_loudly(argv, capsys):
    assert main(argv) == EXIT_NOT_IMPLEMENTED
    assert argv[0] in capsys.readouterr().out


def test_missing_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args([])
    assert exit_info.value.code != 0
