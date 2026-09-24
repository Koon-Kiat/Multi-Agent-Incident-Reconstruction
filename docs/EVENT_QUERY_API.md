# Event Processing & Detection Engine Query API

Owner: Event Processing & Detection Engine. Status: implemented (`event_processing/query.py`,
`event_processing/adapters/authentication_provider.py`, `event_processing/__main__.py`).
Companion document: [`EVENT_SCHEMA.md`](EVENT_SCHEMA.md) for the events this API returns.

The query layer is **deterministic and read-only**: the same call returns the same events in the
same order on every run, and nothing a consumer can reach mutates the corpus.

`EventStore.load()` is the tested integration path. Direct constructor callers
must not mutate their input records: a caller-owned `event_data` dictionary is
currently retained. See the [reproducer and proposed fix](AUTHENTICATION_PROVIDER_HANDOFF.md#constructor-snapshot-issue).

## Contents

* [`EventStore.load`](#eventstoreload) — open a written corpus, verifying every digest
* [`lookup` and `lookup_many`](#lookup-and-lookup_many) — exact-ID resolution
* [`query`](#query) — bounded `[start, end)` windows with exact filters
* [`process_by_guid`, `children_of`, `window_around`](#helpers) — bounded convenience queries
* [`CorpusAuthenticationProvider`](#authentication-investigation-agent-adapter) — Authentication Investigation Agent's `AuthenticationEventProvider`
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

A manifest `filename` must be a **plain direct-child name**: an absolute path, a separator, `.` or
`..` is a malformed manifest, and a symlink that resolves outside the corpus directory is refused
rather than read. A line whose digest matched but whose JSON is malformed or invalid becomes a
`QueryError` naming the file and the line number, never a bare parse error. The manifest's
`schema_version` is pinned to `security-corpus-v1`.

```python
from event_processing.query import EventStore

store = EventStore.load("out/corpus")
store.scenario_ids            # ('S01', 'S02', 'S03')
store.limits                  # QueryLimits(max_window_seconds=3600, max_limit=1000)
```

`EventStore(events)` builds a store straight from events (used by unit tests); it applies the
same duplicate check and the same ordering, and **deep-copies every event before indexing it**, so
a caller that keeps its own list cannot change a later answer by mutating an event it handed in.

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
    event_data_filters: Mapping[int, Mapping[str, str]] | None = None,
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

`event_data_filters` is an optional declarative mapping from **source Event ID**
(not unique evidence ID) to required `event_data` field/value pairs. An event
must have a listed type and match **every** field for that type, as well as all
other query filters. Field names/values are exact case-sensitive strings. `None`
disables this filter; `{}` matches nothing; `{1: {}}` admits type 1 without
additional field requirements. An empty string matches a present empty value,
not a missing field. Invalid types and callbacks raise `QueryError`.

For example, the endpoint adapter can express different source-field names
without adding endpoint-specific logic or a callback to the store:

```python
result = store.query(
    "S02", "2026-09-21T02:05:10Z", "2026-09-21T02:05:20Z",
    channels=("Microsoft-Windows-Sysmon/Operational",), limit=2,
    event_data_filters={1: {"ProcessGuid": "{ABC}"},
                        10: {"SourceProcessGUID": "{ABC}"}},
)
```

Filtering happens **before limiting and before detachment**. The store uses
binary search over its already ordered internal snapshot to find the half-open
time window, counts all matches in that window, and retains at most `limit`
record references before deep-copying only the returned records. No full-scenario
copy, window slice, new index or all-matches list is built. Ordering remains
`(timestamp_ticks, evidence_id)`, and returned records retain `raw_xml` and all
other source fields. Mutating returned event data cannot mutate the store.
Caller-supplied predicates never receive internal records: the API accepts data,
not callbacks. Query working memory is bounded by the filters and return limit;
CPU work still depends on the window's event count because `total_matched` is an
exact count, not a `limit + 1` lower bound. Existing callers that omit the new
keyword retain their semantics. `scenario_events()` still returns a detached
whole-scenario snapshot for callers that explicitly request one.

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

## Authentication Investigation Agent adapter

`event_processing.adapters.authentication_provider.CorpusAuthenticationProvider` implements
`authentication_agent.queries.interface.AuthenticationEventProvider` over a store:

```python
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from authentication_agent import InvestigationRequest, investigate
from authentication_agent.llm.fake import FakeLLM

provider = CorpusAuthenticationProvider(store, limits)
result = investigate(request, provider, FakeLLM())
```

* `get_event(evidence_id)` returns `authentication_agent.models.AuthenticationEvent | None`. Exact lookup
  preserves **any** `Security` record, whatever its Event ID, because Authentication Investigation Agent's provider contract
  fixture looks up a Security 4634 and requires it back unchanged; `None` covers a malformed ID,
  a well-formed ID the corpus does not hold, and a Sysmon event (Authentication Investigation Agent's model admits the Security
  channel only).
* `query(QueryRequest)` is the narrower door: it offers only the `Security` events whose Event ID
  the request admits, which for `QueryRequest` is `4624`/`4625` by construction. Agent tools see
  authentication evidence only; exact lookup is the retrieval path that retains everything.
* `query(QueryRequest)` returns `authentication_agent.models.QueryResult`, ordered by Authentication Investigation Agent's `event_order`, with
  `truncated` set when more events matched than `request.limit` allowed.
* The adapter calls Authentication Investigation Agent's own `check_bounds`, `matches` and `event_order`; it does not restate
  Authentication Investigation Agent's semantics. Field mapping is exact: `event_data` values stay verbatim, `raw_reference` and
  `record_id` are preserved for Evidence Verification & Evaluation, and `evidence_id` already equals
  `authentication_agent.models.evidence_id_for`.
* Pass the same `Limits` the investigation runs with, or Authentication Investigation Agent's requests will exceed the
  provider's bound and be rejected rather than clamped.

Verified end to end on real evidence: with `FakeLLM` over S02's own metadata window the
investigation completes and every cited ID resolves through `store.lookup`.

## Command line

The separate endpoint adapter is
`event_processing.adapters.endpoint_provider.CorpusEndpointProvider`. It uses
the public `query()` API with declarative scope/GUID predicates applied before
the result limit and detachment, preserving exact identities and timestamps. See
[endpoint query and handoff semantics](ENDPOINT_PROVIDER_HANDOFF.md). The generic
store methods and authentication adapter contract are unchanged.

```powershell
.\.venv\Scripts\python.exe -m event_processing normalise --datasets datasets --out out/corpus
.\.venv\Scripts\python.exe -m event_processing lookup S02-SEC-43584 --corpus out/corpus
.\.venv\Scripts\python.exe -m event_processing query S02 --start 2026-09-21T02:05:10Z --end 2026-09-21T02:05:20Z --event-id 4625 --corpus out/corpus
```

`lookup` prints the event as one JSON object (sorted keys) and exits `0`; a well-formed ID that
is not in the corpus exits `1`; a malformed ID exits `2`. `query` prints one JSON event per line
and, when the result was truncated, a note on **stderr** so stdout stays pipeable:

```
> python -m event_processing query S02 --start 2026-09-21T02:05:10Z --end 2026-09-21T02:05:20Z --event-id 4625 --limit 2 --corpus out/corpus
event_processing query: truncated at 2 of 3 matches        (stderr)
{"channel": "Security", "evidence_id": "S02-SEC-43571", …}   (stdout)
{"channel": "Security", "evidence_id": "S02-SEC-43573", …}   (stdout)
```

```
> python -m event_processing lookup S02-SEC-999999 --corpus out/corpus
event_processing lookup: S02-SEC-999999 is not in out/corpus        (stderr, exit 1)

> python -m event_processing lookup nope --corpus out/corpus
event_processing lookup: malformed evidence_id 'nope'               (stderr, exit 2)
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
