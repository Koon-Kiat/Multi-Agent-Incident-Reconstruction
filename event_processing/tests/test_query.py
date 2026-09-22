"""T2.1/T2.2/T2.4: lookup and query semantics over a synthetic corpus.

Everything here runs in CI: the corpus is written from hand-made events, and no EVTX file is
opened. The real collision case (S02/S03 record 43584) lives in ``test_query_real.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from event_processing.corpus import write_manifest, write_scenario
from event_processing.manifest import load_scenario
from event_processing.query import EventStore, QueryError, QueryLimits
from event_processing.schema import NormalisedEvent
from event_processing.tests.synthetic import SECURITY, SYSMON, build_scenario_dir, make_event
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks, ticks_to_iso

BASE = iso_to_ticks("2026-09-21T02:05:30.0000000Z")


def at(seconds: int) -> str:
    """The canonical UTC string ``BASE + seconds``, for readable window bounds."""
    return ticks_to_iso(BASE + seconds * TICKS_PER_SECOND)


def synthetic_events() -> tuple[NormalisedEvent, ...]:
    """Five events: a boundary pair, an all-empty Security event, and a Sysmon GUID pair."""
    return (
        make_event(
            record_id=1,
            timestamp_ticks=BASE,
            event_id=4624,
            user="alice",
            host="LAB-A",
            event_data={"TargetUserName": "alice", "LogonType": "10"},
        ),
        make_event(
            record_id=2,
            timestamp_ticks=BASE + 5 * TICKS_PER_SECOND,
            event_id=4625,
            user="bob",
            host="LAB-A",
            event_data={"TargetUserName": "bob"},
        ),
        # Present but empty values, which is a different fact from an absent field.
        make_event(
            record_id=3,
            timestamp_ticks=BASE + 10 * TICKS_PER_SECOND,
            event_id=4688,
            user="",
            host="",
            event_data={"SubjectUserName": ""},
        ),
        # Records 4 and 5 share ticks; the canonical order is by evidence_id, not insertion.
        make_event(
            record_id=5,
            channel=SYSMON,
            event_id=1,
            timestamp_ticks=BASE + 15 * TICKS_PER_SECOND,
            user="alice",
            host="LAB-A",
            event_data={"User": "alice", "ProcessGuid": "{B}", "ParentProcessGuid": "{A}"},
        ),
        make_event(
            record_id=4,
            channel=SYSMON,
            event_id=1,
            timestamp_ticks=BASE + 15 * TICKS_PER_SECOND,
            user="alice",
            host="LAB-A",
            event_data={"User": "alice", "ProcessGuid": "{A}", "ParentProcessGuid": "{ROOT}"},
        ),
    )


@pytest.fixture
def corpus_dir(tmp_path: Path) -> Path:
    """A written corpus directory, exactly as ``python -m event_processing normalise`` would leave it."""
    info = load_scenario(build_scenario_dir(tmp_path / "datasets", "lab"))
    out = tmp_path / "corpus"
    write_manifest(out, [write_scenario(out, info, synthetic_events())])
    return out


@pytest.fixture
def store(corpus_dir: Path) -> EventStore:
    return EventStore.load(corpus_dir)


# --- T2.1 lookup ------------------------------------------------------------------


def test_load_reads_the_written_events_with_full_precision(store: EventStore):
    result = store.lookup("SYN-B-SEC-1")
    assert result.status == "found"
    assert result.event is not None
    assert result.event.timestamp_utc == at(0)
    assert result.event.timestamp_ticks == BASE
    assert store.scenario_ids == ("SYN-B",)


def test_lookup_distinguishes_not_found_from_invalid_id(store: EventStore):
    absent = store.lookup("SYN-B-SEC-99")
    assert (absent.status, absent.event) == ("not_found", None)
    assert (absent.evidence_id, absent.event) == ("SYN-B-SEC-99", None)
    for malformed in ("syn-b-sec-1", "SYN-B-XYZ-1", "SYN-B-SEC-01", "SYN-B-SEC-0", "SYN-B-43584", "", "SYN-B-SEC-1 "):
        assert store.lookup(malformed).status == "invalid_id", malformed


def test_lookup_never_returns_a_nearby_event(store: EventStore):
    # S02-SEC-43585 must never answer for S02-SEC-43584, here or elsewhere.
    assert store.lookup("SYN-B-SEC-6").status == "not_found"
    assert store.lookup("SYN-B-SEC-6").event is None
    assert store.lookup("SYN-B-SEC-1").event.record_id == 1


def test_lookup_many_preserves_input_order(store: EventStore):
    ids = ["SYN-B-SEC-2", "SYN-B-SEC-99", "oops", "SYN-B-SEC-1"]
    results = store.lookup_many(ids)
    assert [result.status for result in results] == ["found", "not_found", "invalid_id", "found"]
    assert [result.evidence_id for result in results] == ids


def test_lookup_rejects_a_non_string_id(store: EventStore):
    with pytest.raises(QueryError, match="must be a str"):
        store.lookup(1)  # type: ignore[arg-type]


def test_a_found_event_with_empty_fields_is_not_a_not_found(store: EventStore):
    result = store.lookup("SYN-B-SEC-3")
    assert result.status == "found"
    assert result.event is not None
    assert (result.event.user, result.event.host) == ("", "")


def test_the_stores_evidence_ids_are_every_id_it_can_resolve(store: EventStore):
    # The corpus's citable universe, which is what validates a whole label file in bulk.
    ids = store.evidence_ids
    assert ids == tuple(sorted(ids))
    assert set(ids) == {event.evidence_id for event in synthetic_events()}
    for evidence_id in ids:
        assert store.lookup(evidence_id).status == "found"
    assert "SYN-B-SEC-99" not in ids


# --- T2.2 filters -----------------------------------------------------------------


def test_start_is_inclusive_and_end_is_exclusive(store: EventStore):
    result = store.query("SYN-B", at(5), at(15))
    assert [event.evidence_id for event in result.events] == ["SYN-B-SEC-2", "SYN-B-SEC-3"]
    assert (result.truncated, result.total_matched) == (False, 2)


def test_equal_ticks_are_ordered_by_evidence_id_and_queries_repeat(store: EventStore):
    first = store.query("SYN-B", at(14), at(16))
    assert [event.evidence_id for event in first.events] == ["SYN-B-SYS-4", "SYN-B-SYS-5"]
    assert store.query("SYN-B", at(14), at(16)) == first


def test_filters_are_exact_and_case_sensitive(store: EventStore):
    window = (at(0), at(20))
    assert [e.evidence_id for e in store.query("SYN-B", *window, channels=(SECURITY,)).events] == [
        "SYN-B-SEC-1",
        "SYN-B-SEC-2",
        "SYN-B-SEC-3",
    ]
    assert store.query("SYN-B", *window, channels=("security",)).total_matched == 0
    assert [e.evidence_id for e in store.query("SYN-B", *window, event_ids=(4625,)).events] == ["SYN-B-SEC-2"]
    assert [e.evidence_id for e in store.query("SYN-B", *window, user="").events] == ["SYN-B-SEC-3"]
    assert [e.evidence_id for e in store.query("SYN-B", *window, host="lab-a").events] == []
    assert [e.evidence_id for e in store.query("SYN-B", *window, host="LAB-A").events] == [
        "SYN-B-SEC-1",
        "SYN-B-SEC-2",
        "SYN-B-SYS-4",
        "SYN-B-SYS-5",
    ]


def test_none_means_no_filter_and_an_empty_collection_matches_nothing(store: EventStore):
    window = (at(0), at(20))
    assert store.query("SYN-B", *window).total_matched == 5
    assert store.query("SYN-B", *window, channels=None, event_ids=None, host=None, user=None).total_matched == 5
    assert store.query("SYN-B", *window, channels=()).total_matched == 0
    assert store.query("SYN-B", *window, event_ids=()).total_matched == 0


def test_a_filter_that_could_only_match_nothing_by_mistake_is_rejected(store: EventStore):
    # frozenset("Security") is a set of characters, so this would answer 0 to a Security query.
    with pytest.raises(QueryError, match="not a single str"):
        store.query("SYN-B", at(0), at(20), channels=SECURITY)  # type: ignore[arg-type]
    with pytest.raises(QueryError, match="not a single str"):
        store.query("SYN-B", at(0), at(20), event_ids="4625")  # type: ignore[arg-type]
    with pytest.raises(QueryError, match="not a single bytes"):
        store.query("SYN-B", at(0), at(20), channels=b"Security")  # type: ignore[arg-type]
    with pytest.raises(QueryError, match="is not a str"):
        store.query("SYN-B", at(0), at(20), channels=(SECURITY, 1))  # type: ignore[arg-type]
    with pytest.raises(QueryError, match="is not an int"):
        store.query("SYN-B", at(0), at(20), event_ids=("4625",))  # type: ignore[arg-type]
    # bool is an int subclass but can never be a Windows Event ID.
    with pytest.raises(QueryError, match="is not an int"):
        store.query("SYN-B", at(0), at(20), event_ids=(True,))  # type: ignore[arg-type]
    # The well-typed filters still answer normally.
    assert store.query("SYN-B", at(0), at(20), channels=(SECURITY,)).total_matched == 3
    assert store.query("SYN-B", at(0), at(20), event_ids=(4625,)).total_matched == 1


def test_truncation_is_reported_with_the_true_total(store: EventStore):
    result = store.query("SYN-B", at(0), at(20), limit=2)
    assert [event.evidence_id for event in result.events] == ["SYN-B-SEC-1", "SYN-B-SEC-2"]
    assert (result.truncated, result.total_matched) == (True, 5)


def test_an_unknown_scenario_or_an_empty_window_is_an_empty_result(store: EventStore):
    assert store.query("SYN-Z", at(0), at(20)).events == ()
    assert store.query("SYN-Z", at(0), at(20)).total_matched == 0
    assert store.query("SYN-B", at(100), at(200)).events == ()


def test_start_at_or_after_end_raises(store: EventStore):
    with pytest.raises(QueryError, match="strictly before"):
        store.query("SYN-B", at(5), at(5))
    with pytest.raises(QueryError, match="strictly before"):
        store.query("SYN-B", at(6), at(5))


def test_a_malformed_timestamp_raises_a_query_error(store: EventStore):
    with pytest.raises(QueryError, match="UTC ISO 8601"):
        store.query("SYN-B", "2026-09-21 02:05:30", at(20))


def test_an_oversized_window_is_rejected_not_clamped(store: EventStore):
    with pytest.raises(QueryError, match="max_window_seconds"):
        store.query("SYN-B", at(0), at(3601))
    assert store.query("SYN-B", at(0), at(3600)).total_matched == 5


def test_an_oversized_or_invalid_limit_is_rejected_not_clamped(store: EventStore):
    window = (at(0), at(20))
    with pytest.raises(QueryError, match="max_limit"):
        store.query("SYN-B", *window, limit=1001)
    with pytest.raises(QueryError, match="positive int"):
        store.query("SYN-B", *window, limit=0)
    assert store.query("SYN-B", *window, limit=1000).truncated is False


def test_the_configured_limits_are_the_ones_enforced(corpus_dir: Path):
    store = EventStore.load(corpus_dir, limits=QueryLimits(max_window_seconds=10, max_limit=2))
    assert store.limits == QueryLimits(max_window_seconds=10, max_limit=2)
    with pytest.raises(QueryError, match="max_window_seconds"):
        store.query("SYN-B", at(0), at(11))
    with pytest.raises(QueryError, match="max_limit"):
        store.query("SYN-B", at(0), at(10), limit=3)
    assert store.query("SYN-B", at(0), at(10), limit=2).truncated is False
    assert store.query("SYN-B", at(0), at(10), limit=1).truncated is True


# --- read-only --------------------------------------------------------------------


def test_a_returned_event_cannot_be_mutated(store: EventStore):
    result = store.lookup("SYN-B-SEC-1")
    assert result.event is not None
    with pytest.raises(ValidationError):
        result.event.user = "mallory"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        result.event.record_id = 11  # type: ignore[misc]


def test_mutating_a_returned_event_data_does_not_reach_the_store(store: EventStore):
    first = store.lookup("SYN-B-SEC-1").event
    assert first is not None
    first.event_data["TargetUserName"] = "mallory"
    assert store.lookup("SYN-B-SEC-1").event.event_data["TargetUserName"] == "alice"

    queried = store.query("SYN-B", at(0), at(20)).events[0]
    queried.event_data["TargetUserName"] = "mallory"
    assert store.query("SYN-B", at(0), at(20)).events[0].event_data["TargetUserName"] == "alice"


def test_the_store_rejects_a_duplicate_evidence_id():
    event = make_event(record_id=1)
    with pytest.raises(QueryError, match="duplicate evidence_id"):
        EventStore([event, event])


def test_the_same_record_id_in_two_scenarios_is_two_events():
    store = EventStore(
        [
            make_event(scenario_id="S02", record_id=43584, event_id=4624),
            make_event(scenario_id="S03", record_id=43584, event_id=4688),
        ]
    )
    assert store.lookup("S02-SEC-43584").event.source_event_id == 4624
    assert store.lookup("S03-SEC-43584").event.source_event_id == 4688


# --- T2.2 helpers -----------------------------------------------------------------


def test_process_by_guid_and_children_of_are_exact(store: EventStore):
    assert [event.evidence_id for event in store.process_by_guid("SYN-B", "{A}").events] == ["SYN-B-SYS-4"]
    assert [event.evidence_id for event in store.children_of("SYN-B", "{A}").events] == ["SYN-B-SYS-5"]
    assert store.process_by_guid("SYN-B", "{a}").total_matched == 0
    assert store.process_by_guid("SYN-B", "{ROOT}").total_matched == 0
    assert store.children_of("SYN-B", "{missing}").total_matched == 0
    assert store.process_by_guid("SYN-Z", "{A}").total_matched == 0


def test_window_around_includes_the_anchor_and_ends_exclusively(store: EventStore):
    result = store.window_around("SYN-B-SEC-2", 6)
    assert [event.evidence_id for event in result.events] == ["SYN-B-SEC-1", "SYN-B-SEC-2", "SYN-B-SEC-3"]
    assert (result.truncated, result.total_matched) == (False, 3)


def test_window_around_rejects_a_bad_anchor_or_size(store: EventStore):
    with pytest.raises(QueryError, match="not_found"):
        store.window_around("SYN-B-SEC-99", 5)
    with pytest.raises(QueryError, match="invalid_id"):
        store.window_around("nope", 5)
    with pytest.raises(QueryError, match="positive int"):
        store.window_around("SYN-B-SEC-1", 0)
    with pytest.raises(QueryError, match="max_window_seconds"):
        store.window_around("SYN-B-SEC-1", 1801)


# --- T2.1 load verification --------------------------------------------------------


def test_load_rejects_a_tampered_jsonl(corpus_dir: Path):
    path = corpus_dir / "SYN-B.jsonl"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(QueryError, match="sha256"):
        EventStore.load(corpus_dir)


def test_load_rejects_a_file_the_manifest_names_but_that_is_absent(corpus_dir: Path):
    (corpus_dir / "SYN-B.jsonl").unlink()
    with pytest.raises(QueryError, match="missing"):
        EventStore.load(corpus_dir)


def test_load_requires_a_corpus_manifest(tmp_path: Path):
    with pytest.raises(QueryError, match="corpus manifest"):
        EventStore.load(tmp_path)


def test_load_reads_only_the_files_the_manifest_names(corpus_dir: Path):
    """A stale .jsonl from an earlier run is never read, however plausible it looks."""
    (corpus_dir / "STALE.jsonl").write_text("{}\n", encoding="utf-8")
    store = EventStore.load(corpus_dir)
    assert store.scenario_ids == ("SYN-B",)
    assert store.lookup("SYN-B-SEC-1").status == "found"
