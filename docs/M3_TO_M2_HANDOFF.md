# M3 to M2 integration handoff

Status refreshed on 2026-09-22: M2 is not merged into `origin/main`, and there
is no open delivery PR. The development branch `origin/m2/normaliser` at
`31add71` contains normalisation and deterministic corpus writing, but query
and exact lookup are still unimplemented. This handoff describes the existing
**provisional M3 adapter**, not a new shared normalisation schema. Real-data
integration awaits M2's read-only provider and joint contract agreement.

## Available M2 work

Read-only inspection of `m2/schema.py`, `m2/corpus.py` and `m2/__main__.py`
at `31add71` found scenario/channel/record-scoped evidence IDs, original record
IDs, seven-digit UTC timestamps, integer ticks and raw references. Corpus output
is ordered by ticks then evidence ID. These choices align with M3's boundary.

M2's event includes additional provenance fields (`source_sha256`, `raw_xml`,
`in_scenario_window`, `parse_warnings`) and `timestamp_ticks`. A future adapter
must explicitly select M3's existing fields: passing the entire M2 object into
M3's extra-forbid model would fail validation. Keep raw XML and metadata flags
outside the model context. M2's inclusive metadata-window flag must not replace
M3's explicit `[start,end)` query filtering.

The M2 CLI currently routes `lookup` and `query` to `_not_implemented`, returning
exit code 2. There is no query provider to connect yet. This is static interface
inspection only; M2's tests and real-data pipeline were not run or modified.

## Required boundary

Implement the existing `m3.queries.interface.AuthenticationEventProvider`:

```python
def get_event(self, evidence_id: str) -> AuthenticationEvent | None: ...
def query(self, request: QueryRequest) -> QueryResult: ...
```

The canonical M3 definitions remain in `m3/models.py`; see
[the existing contract documentation](../m3/README.md#integration-with-m2).
Map your final shared event objects into these models at the adapter boundary.
M3's investigation logic must not need to change when replacing the synthetic
provider. The adapter does not ingest EVTX, normalise logs or implement detections.

| Requirement | Current M3 expectation |
| --- | --- |
| Required fields | `evidence_id`, `scenario_id`, `source_type`, `channel`, `source_event_id`, `record_id`, `timestamp_utc`, `raw_reference` |
| Source | `source_type='windows_security'`, `channel='Security'`; initial query Event IDs 4624/4625 |
| Optional fields | Nullable `user` and `host`; JSON `event_data`; preserve missing versus empty values |
| Authentication data | `TargetUserName`, `TargetDomainName`, `IpAddress`, `WorkstationName`, `LogonType`, when available |
| Evidence identity | Existing provisional `scenario-SEC-original_record_id`; retain original Windows Event Record ID |
| Corpus uniqueness | Scenario **and channel** must participate; never use Event ID or record number alone. Other channels need distinct namespaces. Multiple Security exports/hosts with colliding IDs need a jointly agreed extension |
| Raw reference | Preserve a source reference sufficient for later independent resolution; M3 does not dereference it |
| Time | Already-normalised UTC ISO 8601 string, retaining all original seven fractional digits; comparisons use integer 100ns ticks |
| Query scope | Required exact `scenario_id`, bounded `start_utc` and `end_utc`; optional exact account, host and Event ID filters |
| Boundaries | Inclusive start, exclusive end: `[start_utc, end_utc)` |
| Ordering | Ascending full-precision timestamp, then evidence ID lexicographically for ties |
| Limits | Configurable count/window ceilings; reject excessive requests; return `truncated=True` when more matches exist |
| Missing event | Return `None` for an unknown exact ID; no nearest/fuzzy substitution |
| Immutability | Queries cannot change records; returned objects must not expose mutable store references |
| Consistency | Final exact-ID readback must still match retrieved record contents and scenario |

Account filters currently use `user` when non-null, otherwise a string
`event_data.TargetUserName`, with case-sensitive equality. Domain and source values
are kept separately when forming observations. Confirm this mapping rather than
silently stripping domains, folding case or replacing empty values.

Real Qwen3 testing required no additional event fields or backend operations.
The fixes concern M3's structured model reply and runtime configuration. The
model did not reliably follow a requested tool plan, so required retrieval must
remain deterministic; it must never depend on inferred or fuzzy evidence IDs.

## Reusable provider contract tests

`m3/testing/provider_contract.py` contains 12 focused backend-independent checks.
They use existing synthetic fixture records and no evaluation material. Install
the test dependencies and implement a test factory like this:

```python
import pytest
from m3.testing.provider_contract import AuthenticationProviderContract

class TestM2AuthenticationAdapter(AuthenticationProviderContract):
    @pytest.fixture
    def provider_factory(self):
        def build(events, limits):
            # Load ONLY this supplied synthetic corpus into an isolated M2 test
            # store using M2's own test support, then return the read-only adapter.
            return make_m2_test_adapter(events=events, limits=limits)
        return build
```

`make_m2_test_adapter` is a placeholder for M2's implementation, not delivered
functionality. Do not run test-store setup against the public corpus or a live
index. The factory must honor the supplied `Limits`; the fixtures include a
non-authentication Security event to check query filtering. Exact lookup retains
that Security record, while agent tools only allow authentication evidence.

Run the current implementation's conformance checks:

```powershell
python -m pytest -q m3/tests/test_provider_contract.py
```

The suite checks field preservation, exact not-found lookup (including a wrong
channel ID), scenario collisions, authentication/account/host filters, inclusive
and exclusive boundaries 100ns apart, deterministic ties, truncation, configured
limits, deep-copy isolation, and missing/empty fields. Passing this fixture suite
is necessary but does not prove real-data normalisation or corpus completeness.

## Remaining dependencies

M2 must deliver the query/lookup implementation over its normalised Security
corpus and confirm filter/boundary/limit semantics, identity namespace and account
mapping. The normaliser/schema are available on its development branch only.
Then replace the factory/provider, run the contract suite, and exercise public
scenarios through M2's existing API. M3 must not independently parse EVTX to fill
this gap. Provider I/O timeouts also belong to M2's adapter; the synchronous
Protocol cannot cancel an indefinitely blocked provider call.

## Message to send to M2

> M3 is ready for a read-only provider adapter. The normaliser/schema at `31add71`
> align on IDs, precision and raw references; `query` and `lookup` still return
> not implemented. Please deliver that provider and confirm the provisional
> contract in `m3/queries/interface.py` and `m3/models.py`: scenario/channel-scoped
> stable IDs, original record IDs/raw references, seven-digit UTC timestamps,
> `[start,end)` queries, exact filters, deterministic ordering, bounded results
> with truncation, and `None` for unknown IDs without fuzzy lookup. A reusable
> synthetic conformance suite is in `m3/testing/provider_contract.py`. Please send
> your normalised-event/query interface and confirm account mapping and any
> multi-export ID namespaces so we can connect public data without changing M3's
> investigation logic.
