# M2 → M3 reply

Reply to `docs/M3_TO_M2_HANDOFF.md` (2026-09-22) and the review item B15 in
`.agent/phase6-findings.md`. M2's read-only provider is implemented and M3's own reusable contract
suite runs green against it in M2's test suite. `m3/` was read, never edited.

## Provider location and usage

`m2/adapters/m3_provider.py` holds `M2AuthenticationProvider`, which implements
`m3.queries.interface.AuthenticationEventProvider` (`get_event`, `query`). It is constructed over a
loaded corpus and the same `Limits` the investigation runs with:

```python
from m2.query import EventStore
from m2.adapters.m3_provider import M2AuthenticationProvider
from m3.config import Limits

store = EventStore.load("out/corpus")              # verifies every jsonl digest first
provider = M2AuthenticationProvider(store, Limits())
```

`python -m m2 normalise --datasets datasets --out out/corpus` writes the corpus the provider
reads. The adapter calls M3's own `check_bounds`, `matches` and `event_order`; it does not restate
your semantics, so the two cannot drift.

## Account mapping (confirmed, verbatim)

For `Security` events M2 sets `user` to `EventData/TargetUserName` for **4624, 4625, 4634, 4647 and
4648**, otherwise to `EventData/SubjectUserName`, otherwise `None` (with a `parse_warnings` entry
and no dropped record). Values are never case-folded, domain-stripped or trimmed — for example
Sysmon carries `ATTACKRANGE\Administrator` where Security carries `administrator` for the same
person, and both are preserved exactly. This is the mapping your `queries/semantics.py`
`account_of` fallback assumes, so account filters keep working through the adapter.
Mapping table and real examples: `docs/M2_EVENT_SCHEMA.md`.

## One Security export per scenario — no namespace extension

Each scenario in this corpus has exactly one `Security.evtx`, so
`evidence_id = f"{scenario_id}-SEC-{record_id}"` already equals
`m3.models.evidence_id_for(scenario_id, record_id)`; no namespace extension is needed for the
current data. The record IDs do collide across scenarios (S02/S03 share 335 Security record IDs;
record `43584` is a 4624 in S02 and a 4688 in S03), which is exactly why the scenario is part of
the ID and nothing keys on the record ID alone. If a second Security export were ever added for
one scenario, its normalised `evidence_id`s would collide with the first export's and
`python -m m2 normalise` aborts on the duplicate rather than silently merging the two.

## In-memory store — no provider timeout needed

`EventStore.load` reads and verifies the entire corpus once, and every `get_event`/`query` call is
an in-memory dictionary or list scan afterwards: the provider performs no I/O and no network call
once loaded. There is no blocking backend for the synchronous Protocol to wait on, so M2's adapter
needs no timeout of its own. The corpus revision is pinned by `corpus_manifest.json`; a modified
`.jsonl` is refused at load time rather than queried.

## The contract suite runs in M2's tests

`m2/tests/test_m3_provider_contract.py` subclasses
`m3.testing.provider_contract.AuthenticationProviderContract` and supplies the `provider_factory`
fixture you sketched: it builds an isolated in-memory `EventStore` from exactly the synthetic
events the suite passes in, wrapped in `M2AuthenticationProvider` with the supplied `Limits`, and
never touches the public corpus. **All 12 checks pass** (`python -m pytest -q
m2/tests/test_m3_provider_contract.py`).

One check did reveal an adapter bug, now fixed (B15): M3's fixture looks up a `Security` 4634 and
requires it back unchanged, but the adapter returned `None` for every Event ID other than
4624/4625 under exact lookup. `get_event` now preserves **any** `Security` record; `query` stays
narrow and offers only the Event IDs the request admits (4624/4625 for `QueryRequest`), so the
agent tools still see authentication evidence only. Two details of that boundary are worth stating
because the suite is now part of M2's tests:

* **`get_event` is not authentication-only.** It returns any `Security` record the corpus holds —
  4624, 4625, **and 4634, 4688, 1102, …** — because M3's contract requires an exact lookup to
  return the record that exists and `None` only when it does not. M3 code calling `get_event`
  directly must not assume the result is a 4624/4625, and must not read `logon_type` etc. without
  checking the event ID. `query` is the narrow path, and it preselects 4624/4625.
* **The contract fixture's `event_data` is not M2's type.** M3's synthetic events carry JSON-typed
  `event_data` (an integer `LogonType`, a `null`, a nested object), while M2's
  `NormalisedEvent.event_data` is `dict[str, str]` and rejects those values. The contract test
  therefore builds its `NormalisedEvent`s from M3's own already-validated models through an
  adapter (pydantic `model_construct`), so the suite proves the **mapping**, not M2's validation of
  those values. Every real corpus record is fully validated. If M3 ever needs non-string
  `event_data` end to end, that is a shared-contract change for M2 and M3 to agree, not something
  the test silences.

Also covered:

| Handoff requirement | Where it is implemented | Proving test |
|---|---|---|
| Stable scenario/channel-scoped IDs, original record IDs | `m2/ids.py`, `m2/schema.py` | `m2/tests/test_ids.py`, `test_query_real.py::test_the_colliding_record_id_resolves_to_two_different_events` |
| Seven-digit UTC timestamps, integer 100 ns ticks | `m2/timeutil.py` | `m2/tests/test_timeutil.py` (equality with `m3.models.utc_ticks`) |
| `[start, end)` queries, exact filters, deterministic ordering | `m2/query.py` | `m2/tests/test_query.py` |
| Bounded results with `truncated=True`, no clamping | `m2/query.py`, adapter `check_bounds` | the contract suite's truncation and configured-limits checks |
| `None` for an unknown exact ID, no fuzzy lookup | adapter `get_event` | contract suite `test_unknown_ids_never_fuzzy_match` |
| Returned objects cannot mutate the store | `m2/query.py` deep copies | contract suite `test_input_and_returned_records_cannot_mutate_store` |
| Real S02 window drives a full investigation | adapter + `m3.investigate` | `m2/tests/test_m3_provider.py::test_the_real_s02_window_runs_through_m3` |

## Still open

Nothing blocking. Item 5 of `docs/M6_TO_M2_INTERFACE_NOTE.md` (metric definitions) remains a joint
M2/M1/M6 decision; it does not affect the provider boundary.
