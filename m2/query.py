"""Deterministic, read-only query API over a written corpus (AGENTS.md I3).

Contract
--------

* :meth:`EventStore.load` reads **only** the files named by ``corpus_manifest.json`` and
  verifies every ``.jsonl`` digest before trusting a line, so a stale file left in the
  directory by an earlier run is never read and a modified file is never queried.
* :meth:`EventStore.lookup` always returns an explicit :class:`LookupResult` for a string:
  ``found`` carries the event, ``not_found`` is a well-formed ID the corpus does not hold and
  ``invalid_id`` is a malformed one. There is no fuzzy matching, no case folding, no nearest
  neighbour and no "did you mean". A non-string is a programming error, not an ID.
* :meth:`EventStore.query` filters on UTC ``[start_utc, end_utc)``: the start is inclusive and
  the end is exclusive. Ordering is always ``(timestamp_ticks, evidence_id)`` ascending, so
  equal ticks are ordered by ID and never imply precedence.
* Filters are exact, case-sensitive string equality. ``None`` means "no filter"; ``""``
  matches an actual empty value (and only that).
* Windows and limits over :class:`QueryLimits` raise :class:`QueryError` instead of being
  silently clamped, and a result that stopped early reports ``truncated=True`` with the true
  ``total_matched``.
* Read-only: the store never mutates an event after construction, and every event handed to a
  caller is a detached copy, so a consumer cannot reach the stored corpus through it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from m2.corpus import CORPUS_MANIFEST_FILENAME, CorpusManifest, JsonlDigest, event_sort_key
from m2.ids import parse_evidence_id
from m2.manifest import sha256_file
from m2.schema import NormalisedEvent, event_from_json
from m2.timeutil import TICKS_PER_SECOND, iso_to_ticks

SECURITY_CHANNEL = "Security"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Sysmon event IDs this module knows by field name.
SYSMON_PROCESS_CREATE = 1

LookupStatus = Literal["found", "not_found", "invalid_id"]


class QueryError(ValueError):
    """The corpus cannot be trusted, or the query is malformed or unbounded."""


class QueryLimits(BaseModel):
    """Hard bounds a query may not exceed. Nothing is silently clamped to them."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    max_window_seconds: int = Field(default=3600, gt=0)
    max_limit: int = Field(default=1000, gt=0)


class LookupResult(BaseModel):
    """The answer to one exact-ID lookup: never an exception, never an empty event."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: LookupStatus
    evidence_id: str
    event: NormalisedEvent | None = None

    @model_validator(mode="after")
    def event_presence_matches_status(self) -> LookupResult:
        if self.status == "found":
            if self.event is None:
                raise ValueError("status 'found' requires an event")
            if self.event.evidence_id != self.evidence_id:
                raise ValueError("a found result must carry the event that was asked for")
        elif self.event is not None:
            raise ValueError(f"status {self.status!r} must not carry an event")
        return self


class QueryResult(BaseModel):
    """Matching events in canonical order, plus how many matched before the limit."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    events: tuple[NormalisedEvent, ...] = ()
    truncated: bool
    total_matched: int = Field(ge=0)

    @model_validator(mode="after")
    def counts_are_consistent(self) -> QueryResult:
        if self.total_matched < len(self.events):
            raise ValueError("total_matched cannot be smaller than the number of events returned")
        if self.truncated != (self.total_matched > len(self.events)):
            raise ValueError("truncated must be true exactly when more events matched than were returned")
        return self


class EventStore:
    """An immutable snapshot of one written corpus.

    Construction is cheap and total; :meth:`load` adds the manifest and digest verification a
    corpus directory needs before anything in it may be queried.
    """

    def __init__(self, events: Iterable[NormalisedEvent], *, limits: QueryLimits | None = None) -> None:
        self._limits = limits or QueryLimits()
        by_id: dict[str, NormalisedEvent] = {}
        by_scenario: dict[str, list[NormalisedEvent]] = {}
        for event in events:
            if event.evidence_id in by_id:
                raise QueryError(f"duplicate evidence_id in the corpus: {event.evidence_id}")
            by_id[event.evidence_id] = event
            by_scenario.setdefault(event.scenario_id, []).append(event)
        self._by_id = by_id
        # One ordering, fixed at construction, so two identical queries are identical lists.
        self._by_scenario = {
            scenario_id: tuple(sorted(events, key=event_sort_key)) for scenario_id, events in by_scenario.items()
        }

    @classmethod
    def load(cls, corpus_dir: Path | str, *, limits: QueryLimits | None = None) -> EventStore:
        """Read the corpus ``normalise`` wrote under ``corpus_dir``, verifying every digest.

        A missing or altered ``.jsonl`` raises :class:`QueryError` instead of being queried, and
        only the scenario files the manifest names are opened.
        """
        directory = Path(corpus_dir)
        manifest = _read_corpus_manifest(directory)
        events: list[NormalisedEvent] = []
        for scenario in manifest.scenarios:
            path = directory / scenario.jsonl.filename
            _verify_jsonl(path, scenario.jsonl)
            lines = path.read_text(encoding="utf-8-sig").splitlines()
            if len(lines) != scenario.jsonl.line_count:
                raise QueryError(
                    f"corpus file {path} holds {len(lines)} lines, manifest declares {scenario.jsonl.line_count}"
                )
            for line in lines:
                event = event_from_json(line)
                if event.scenario_id != scenario.scenario_id:
                    raise QueryError(f"corpus file {path} holds an event of scenario {event.scenario_id!r}")
                events.append(event)
        return cls(events, limits=limits)

    @property
    def limits(self) -> QueryLimits:
        return self._limits

    @property
    def scenario_ids(self) -> tuple[str, ...]:
        """Every scenario in the store, sorted; a scenario with no events is absent."""
        return tuple(sorted(self._by_scenario))

    def lookup(self, evidence_id: str) -> LookupResult:
        """Resolve one ``evidence_id`` exactly, or explain why it does not resolve."""
        if not isinstance(evidence_id, str):
            raise QueryError(f"evidence_id must be a str, got {type(evidence_id).__name__}")
        try:
            parse_evidence_id(evidence_id)
        except ValueError:
            return LookupResult(status="invalid_id", evidence_id=evidence_id, event=None)
        event = self._by_id.get(evidence_id)
        if event is None:
            return LookupResult(status="not_found", evidence_id=evidence_id, event=None)
        return LookupResult(status="found", evidence_id=evidence_id, event=_detached(event))

    def lookup_many(self, evidence_ids: Iterable[str]) -> tuple[LookupResult, ...]:
        """Look up several IDs, preserving the input order (including its duplicates)."""
        return tuple(self.lookup(evidence_id) for evidence_id in evidence_ids)

    def scenario_events(self, scenario_id: str) -> tuple[NormalisedEvent, ...]:
        """Every event of one scenario in canonical order; empty for an unknown scenario."""
        return tuple(_detached(event) for event in self._scenario_events(scenario_id))

    def query(
        self,
        scenario_id: str,
        start_utc: str,
        end_utc: str,
        *,
        channels: Iterable[str] | None = None,
        event_ids: Iterable[int] | None = None,
        host: str | None = None,
        user: str | None = None,
        limit: int = 100,
    ) -> QueryResult:
        """Return the events of one scenario inside UTC ``[start_utc, end_utc)``.

        ``None`` for a filter means "no filter"; an empty collection matches nothing. An
        unknown scenario yields an empty result rather than an error, exactly like a scenario
        that holds no event in the window.
        """
        start = _ticks(start_utc)
        end = _ticks(end_utc)
        if start >= end:
            raise QueryError(f"start_utc {start_utc!r} must be strictly before end_utc {end_utc!r}")
        window = end - start
        if window > self._limits.max_window_seconds * TICKS_PER_SECOND:
            raise QueryError(
                f"query window of {window} ticks exceeds max_window_seconds={self._limits.max_window_seconds}"
            )
        return self._select(
            scenario_id,
            start,
            end,
            channels=None if channels is None else frozenset(channels),
            event_ids=None if event_ids is None else frozenset(event_ids),
            host=host,
            user=user,
            limit=_checked_limit(limit, self._limits),
        )

    def process_by_guid(self, scenario_id: str, guid: str) -> QueryResult:
        """Sysmon process-creation events whose ``ProcessGuid`` is exactly ``guid``."""
        return self._matching(
            scenario_id,
            lambda event: event.channel == SYSMON_CHANNEL
            and event.source_event_id == SYSMON_PROCESS_CREATE
            and _field(event, "ProcessGuid") == guid,
        )

    def children_of(self, scenario_id: str, parent_guid: str) -> QueryResult:
        """Sysmon process-creation events whose ``ParentProcessGuid`` is exactly ``parent_guid``."""
        return self._matching(
            scenario_id,
            lambda event: event.channel == SYSMON_CHANNEL
            and event.source_event_id == SYSMON_PROCESS_CREATE
            and _field(event, "ParentProcessGuid") == parent_guid,
        )

    def window_around(self, evidence_id: str, seconds: int) -> QueryResult:
        """Events of the anchor's scenario in ``[t - seconds, t + seconds)``, anchor included.

        The anchor must resolve: a window centred on an event that is not in the corpus would
        silently answer a question about a different event.
        """
        found = self.lookup(evidence_id)
        if found.status != "found" or found.event is None:
            raise QueryError(f"cannot centre a window on {evidence_id!r}: lookup status is {found.status!r}")
        if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 1:
            raise QueryError(f"seconds {seconds!r} must be a positive int of seconds")
        if 2 * seconds > self._limits.max_window_seconds:
            raise QueryError(f"window of {2 * seconds}s exceeds max_window_seconds={self._limits.max_window_seconds}")
        half = seconds * TICKS_PER_SECOND
        anchor = found.event
        return self._select(
            anchor.scenario_id,
            anchor.timestamp_ticks - half,
            anchor.timestamp_ticks + half,
            channels=None,
            event_ids=None,
            host=None,
            user=None,
            limit=self._limits.max_limit,
        )

    def _scenario_events(self, scenario_id: str) -> tuple[NormalisedEvent, ...]:
        return self._by_scenario.get(scenario_id, ())

    def _select(
        self,
        scenario_id: str,
        start: int,
        end: int,
        *,
        channels: frozenset[str] | None,
        event_ids: frozenset[int] | None,
        host: str | None,
        user: str | None,
        limit: int,
    ) -> QueryResult:
        matched = [
            event
            for event in self._scenario_events(scenario_id)
            if start <= event.timestamp_ticks < end
            and (channels is None or event.channel in channels)
            and (event_ids is None or event.source_event_id in event_ids)
            and (host is None or event.host == host)
            and (user is None or event.user == user)
        ]
        return self._result(matched, limit)

    def _matching(self, scenario_id: str, predicate: Callable[[NormalisedEvent], bool]) -> QueryResult:
        matched = [event for event in self._scenario_events(scenario_id) if predicate(event)]
        return self._result(matched, self._limits.max_limit)

    def _result(self, matched: list[NormalisedEvent], limit: int) -> QueryResult:
        return QueryResult(
            events=tuple(_detached(event) for event in matched[:limit]),
            truncated=len(matched) > limit,
            total_matched=len(matched),
        )


def _detached(event: NormalisedEvent) -> NormalisedEvent:
    """A copy that shares no mutable state with the store.

    Every other field is a ``str``, ``int``, ``bool`` or ``tuple`` and is therefore already
    immutable, so detaching ``event_data`` — the only dict — is what actually matters.
    """
    return event.model_copy(update={"event_data": dict(event.event_data)})


def _field(event: NormalisedEvent, name: str) -> str | None:
    return event.event_data.get(name)


def _ticks(value: str) -> int:
    """Parse a query bound, reporting a bad timestamp as a query error rather than a bare one."""
    try:
        return iso_to_ticks(value)
    except ValueError as error:
        raise QueryError(str(error)) from error


def _checked_limit(limit: int, limits: QueryLimits) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise QueryError(f"limit {limit!r} must be a positive int")
    if limit > limits.max_limit:
        raise QueryError(f"limit {limit} exceeds max_limit={limits.max_limit}")
    return limit


def _read_corpus_manifest(directory: Path) -> CorpusManifest:
    path = directory / CORPUS_MANIFEST_FILENAME
    if not path.is_file():
        raise QueryError(f"corpus manifest {path} is missing; run 'python -m m2 normalise' first")
    try:
        return CorpusManifest.model_validate_json(path.read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as error:
        raise QueryError(f"{path} is not a readable corpus manifest: {error}") from error


def _verify_jsonl(path: Path, expected: JsonlDigest) -> None:
    """Check the file the manifest names, before any of its lines is parsed."""
    if not path.is_file():
        raise QueryError(f"corpus file {path} named by the manifest is missing")
    actual = sha256_file(path)
    if actual != expected.sha256.lower():
        raise QueryError(f"corpus file {path} has sha256 {actual}, manifest declares {expected.sha256.lower()}")
