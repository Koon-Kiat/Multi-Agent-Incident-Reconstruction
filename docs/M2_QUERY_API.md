# M2 Query API

Owner: M2 (Data Processing & Detection). Status: implemented (`m2/query.py`,
`m2/adapters/m3_provider.py`, `m2/__main__.py`).
Companion document: [`M2_EVENT_SCHEMA.md`](M2_EVENT_SCHEMA.md) for the events this API returns.

The query layer is **deterministic and read-only**: the same call returns the same events in the
same order on every run, and nothing a consumer can reach mutates the corpus.

## Contents

* [`EventStore.load`](#eventstoreload) — open a written corpus, verifying every digest
* [`lookup` and `lookup_many`](#lookup-and-lookup_many) — exact-ID resolution
* [`query`](#query) — bounded `[start, end)` windows with exact filters
* [`process_by_guid`, `children_of`, `window_around`](#helpers) — bounded convenience queries
* [`M2AuthenticationProvider`](#m3-adapter) — M3's `AuthenticationEventProvider`
* [Command line](#command-line)
* [Limits](#limits)

## `EventStore.load`

```python
EventStore.load(corpus_dir: Path | str, *, limits: QueryLimits | None = None) -> EventStore
EventStore(events: Iterable[NormalisedEvent], *, limits: QueryLimits | None = None)
```

`load` reads **only** the files named by `corpus_manifest.json`, and checks each `.jsonl` against
the SHA-256 the manifest declares *before* parsing a line. A missing file, an altered file, an
event of the wrong scenario or a duplicate `evidence_id` raises `QueryError`; a stale `*.jsonl`
left in the directory by an earlier run is never opened, because the manifest does not name it.

```python
from m2.query import EventStore

store = EventStore.load("out/corpus")
store.scenario_ids            # ('S01', 'S02', 'S03')
store.limits                  # QueryLimits(max_window_seconds=3600, max_limit=1000)
```

`EventStore(events)` builds a store straight from events (used by unit tests); it applies the
same duplicate check and the same ordering.

## `lookup` and `lookup_many`

```python
store.lookup(evidence_id: str) -> LookupResult
store.lookup_many(evidence_ids: Iterable[str]) -> tuple[LookupResult, ...]
```

| `status` | Meaning | `event` |
|---|---|---|
| `"found"` | the corpus holds exactly this ID | the event |
| `"not_found"` | well-formed ID, no such event | `None` |
| `"invalid_id"` | malformed ID (case, leading zero, missing code, whitespace, …) | `None` |

There is **no fuzzy matching**, no nearest neighbour, no case-insensitive fallback and no
"did you mean": a lookup for a nonexistent ID fails closed. A `found` result with empty fields
is still `found` — `""` is a value, not an absence. A non-string argument is a programming
error and raises `QueryError`, because it is not an ID at all.

`lookup_many` preserves the input order, including duplicates.

```python
store.lookup("S02-SEC-43584").status            # 'found'
store.lookup("S02-SEC-999999").status           # 'not_found'
store.lookup("s02-sec-43584").status            # 'invalid_id'
store.lookup_many(["S02-SEC-43584", "slack", "S02-SEC-999999"])
# (found, invalid_id, not_found)  — statuses in input order
```

The returned event is a **detached copy**: mutating it (or its `event_data` dict) does not reach
the store, and the model itself is frozen.

## `query`

```python
store.query(
    scenario_id: str,
    start_utc: str,
    end_utc: str,
    *,
    channels: Iterable[str] | None = None,
    event_ids: Iterable[int] | None = None,
    host: str | None = None,
    user: str | None = None,
    limit: int = 100,
) -> QueryResult
```

* **Window**: UTC `[start_utc, end_utc)` — **start inclusive, end exclusive**. Both bounds must
  be UTC ISO 8601 with at most seven fractional digits (`Z` or `+00:00`). `start >= end` raises
  `QueryError`.
* **Ordering**: always `(timestamp_ticks, evidence_id)` ascending. Equal ticks are ordered by
  ID and **do not imply precedence**. Two identical calls return identical tuples.
* **Filters**: exact, case-sensitive string equality. `None` means "no filter"; an empty
  collection matches nothing; `""` matches an actual empty value. No prefix, substring or
  case-insensitive matching exists on this surface.
* **Scenario**: an unknown scenario returns an empty result rather than raising, exactly like a
  scenario with no event in the window.
* **Limits**: a window longer than `max_window_seconds` or a `limit` above `max_limit` (or below
  1) raises `QueryError` — nothing is silently clamped or expanded.
* **Truncation**: `QueryResult.truncated` is true exactly when more events matched than were
  returned, and `total_matched` always reports the true number of matches.

```python
result = store.query(
    "S02",
    "2026-09-21T02:05:10Z",
    "2026-09-21T02:05:20Z",
    event_ids=(4625,),
    limit=2,
)
result.total_matched                      # 3
result.truncated                          # True
[e.evidence_id for e in result.events]    # ['S02-SEC-43571', 'S02-SEC-43573']
```

An event exactly at `start` is included; one exactly at `end` is excluded. The scenario metadata
window is a *different* thing: `in_scenario_window` is inclusive at both ends (see the schema
document).

## Helpers

All three return a `QueryResult`, are bounded by `max_limit`, and are deterministic. All GUID
comparisons are exact and case-sensitive; case-insensitive path or basename matching exists only
inside detection *rules*, never here.

```python
store.process_by_guid(scenario_id, guid)    # Sysmon 1 (process create) with ProcessGuid == guid
store.children_of(scenario_id, parent_guid) # Sysmon 1 with ParentProcessGuid == parent_guid
store.window_around(evidence_id, seconds)   # [t - seconds, t + seconds) in the anchor's scenario
```

`window_around` requires the anchor to resolve (`QueryError` otherwise), requires
`seconds >= 1`, and rejects a window wider than `max_window_seconds`. The anchor itself is
inside the window because the start is inclusive.

```python
anchor = "S02-SYS-25141"                       # EdgeWebView launcher, 02:04:20.1185014Z
store.process_by_guid("S02", "{6708084d-90a4-6ab0-ca00-000000000e00}").total_matched  # 1
store.children_of("S02", "{6708084d-90a4-6ab0-ca00-000000000e00}").total_matched      # 5
store.window_around(anchor, 1).total_matched   # 12
```

## M3 adapter

`m2.adapters.m3_provider.M2AuthenticationProvider` implements
`m3.queries.interface.AuthenticationEventProvider` over a store:

```python
from m2.adapters.m3_provider import M2AuthenticationProvider
from m3 import InvestigationRequest, investigate
from m3.llm.fake import FakeLLM

provider = M2AuthenticationProvider(store, limits)
result = investigate(request, provider, FakeLLM())
```

* `get_event(evidence_id)` returns `m3.models.AuthenticationEvent | None`. `None` covers a
  malformed ID, a well-formed ID the corpus does not hold, Sysmon events and every Security
  event other than `4624`/`4625` — M3's provider contract has one representation for "there is
  no such authentication event".
* `query(QueryRequest)` returns `m3.models.QueryResult`, ordered by M3's `event_order`, with
  `truncated` set when more events matched than `request.limit` allowed.
* The adapter calls M3's own `check_bounds`, `matches` and `event_order`; it does not restate
  M3's semantics. Field mapping is exact: `event_data` values stay verbatim, `raw_reference` and
  `record_id` are preserved for M6, and `evidence_id` already equals
  `m3.models.evidence_id_for`.
* Pass the same `Limits` the investigation runs with, or M3's requests will exceed the
  provider's bound and be rejected rather than clamped.

Verified end to end on real evidence: with `FakeLLM` over S02's own metadata window the
investigation completes and every cited ID resolves through `store.lookup`.

## Command line

```powershell
.\.venv\Scripts\python.exe -m m2 normalise --datasets datasets --out out/corpus
.\.venv\Scripts\python.exe -m m2 lookup S02-SEC-43584 --corpus out/corpus
.\.venv\Scripts\python.exe -m m2 query S02 --start 2026-09-21T02:05:10Z --end 2026-09-21T02:05:20Z --event-id 4625 --corpus out/corpus
```

`lookup` prints the event as one JSON object (sorted keys) and exits `0`; a well-formed ID that
is not in the corpus exits `1`; a malformed ID exits `2`. `query` prints one JSON event per line
and, when the result was truncated, a note on **stderr** so stdout stays pipeable:

```
> python -m m2 query S02 --start 2026-09-21T02:05:10Z --end 2026-09-21T02:05:20Z --event-id 4625 --limit 2 --corpus out/corpus
m2 query: truncated at 2 of 3 matches        (stderr)
{"channel": "Security", "evidence_id": "S02-SEC-43571", …}   (stdout)
{"channel": "Security", "evidence_id": "S02-SEC-43573", …}   (stdout)
```

```
> python -m m2 lookup S02-SEC-999999 --corpus out/corpus
m2 lookup: S02-SEC-999999 is not in out/corpus        (stderr, exit 1)

> python -m m2 lookup nope --corpus out/corpus
m2 lookup: malformed evidence_id 'nope'               (stderr, exit 2)
```

The JSON lines above are elided for readability; the real output carries every field including
`raw_xml`.

## Limits

| Setting | Default | Applies to |
|---|---:|---|
| `max_window_seconds` | 3600 | `query` window length, `window_around` (2 × seconds) |
| `max_limit` | 1000 | events returned by `query`, `process_by_guid`, `children_of`, `window_around` |

A limit over the bound raises; it is never silently clamped, and a truncated result always says
so. `QueryLimits` is frozen: a store's bounds are fixed when it is created.
