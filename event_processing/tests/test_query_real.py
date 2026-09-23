"""T2.4 real-evidence queries: the collision anchors, window counts and determinism.

Skipped in CI, where the datasets are checked out with ``lfs: false``. The expected values are
public properties of the corpus (AGENTS.md section 3 and the phase-1 handoff), reproducible
with Windows' own parser.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from event_processing.manifest import load_scenario
from event_processing.query import EventStore
from event_processing.tests.conftest import real_datasets
from event_processing.timeutil import ticks_to_iso

SECURITY = "Security"

# AGENTS.md section 3 public anchors: same record number, two different events.
ANCHORS = {
    ("S02", 43584): (4624, "2026-09-21T02:05:30.0430374Z", None),
    ("S03", 43584): (4688, "2026-09-21T02:25:15.6704553Z", "dllhost.exe"),
    ("S02", 43628): (4688, None, "msedgewebview2.exe"),
    ("S03", 43628): (4688, None, "whoami.exe"),
    ("S02", 43571): (4625, None, None),
    ("S03", 43571): (4688, None, "sppsvc.exe"),
}

S02_IN_WINDOW_SECURITY = 171
S02_IN_WINDOW_SYSMON = 620


def test_the_colliding_record_id_resolves_to_two_different_events(real_corpus_dir: Path):
    store = EventStore.load(real_corpus_dir)
    s02 = store.lookup("S02-SEC-43584")
    s03 = store.lookup("S03-SEC-43584")

    assert s02.status == s03.status == "found"
    assert s02.event is not None and s03.event is not None
    assert s02.event.record_id == s03.event.record_id == 43584
    assert (s02.event.source_event_id, s02.event.timestamp_utc) == (4624, "2026-09-21T02:05:30.0430374Z")
    assert (s03.event.source_event_id, s03.event.timestamp_utc) == (4688, "2026-09-21T02:25:15.6704553Z")
    assert s02.event.scenario_id != s03.event.scenario_id


def test_every_public_anchor_resolves_through_the_query_api(real_corpus_dir: Path):
    store = EventStore.load(real_corpus_dir)
    for (scenario, record_id), (event_id, timestamp, image) in ANCHORS.items():
        found = store.lookup(f"{scenario}-SEC-{record_id}")
        assert found.status == "found", f"{scenario}-SEC-{record_id}"
        assert found.event.source_event_id == event_id
        if timestamp is not None:
            assert found.event.timestamp_utc == timestamp
        if image is not None:
            command = found.event.event_data.get("NewProcessName") or found.event.event_data.get("Image") or ""
            assert command.rsplit("\\", 1)[-1].lower() == image


def test_the_documented_s01_example_id_resolves(real_corpus_dir: Path):
    assert EventStore.load(real_corpus_dir).lookup("S01-SEC-31213331").status == "found"


def test_the_s02_window_query_reproduces_the_public_in_window_counts(real_corpus_dir: Path):
    store = EventStore.load(real_corpus_dir)
    info = load_scenario(real_datasets() / "S02")
    # One tick past the declared end: `in_scenario_window` is inclusive at both ends, a query
    # window is [start, end), so this asks for exactly the flagged set.
    result = store.query(
        "S02",
        ticks_to_iso(info.window_start_ticks),
        ticks_to_iso(info.window_end_ticks + 1),
        limit=1000,
    )
    flagged = [event for event in store.scenario_events("S02") if event.in_scenario_window]

    assert [event.evidence_id for event in result.events] == [event.evidence_id for event in flagged]
    assert result.truncated is False
    assert result.total_matched == len(flagged) == S02_IN_WINDOW_SECURITY + S02_IN_WINDOW_SYSMON
    by_channel = Counter(event.channel for event in result.events)
    assert by_channel[SECURITY] == S02_IN_WINDOW_SECURITY


def test_a_real_query_is_ordered_repeatable_and_honest_about_truncation(real_corpus_dir: Path):
    store = EventStore.load(real_corpus_dir)
    window = ("2026-09-21T02:05:00Z", "2026-09-21T02:05:30Z")

    first = store.query("S02", *window, limit=1000)
    keys = [(event.timestamp_ticks, event.evidence_id) for event in first.events]
    assert keys == sorted(keys)
    assert first.truncated is False
    assert store.query("S02", *window, limit=1000) == first

    truncated = store.query("S02", *window, limit=5)
    assert len(truncated.events) == 5
    assert truncated.truncated is True
    assert truncated.total_matched == first.total_matched > 5
    assert [event.evidence_id for event in truncated.events] == [
        event.evidence_id for event in first.events[:5]
    ]
