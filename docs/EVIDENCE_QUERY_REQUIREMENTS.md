> Historical handoff/report: numbered role labels and recorded results are preserved.
> See [component names and current architecture](ARCHITECTURE.md) and the
> [current authentication integration report](AUTHENTICATION_CORPUS_INTEGRATION.md) for current status.

# Evidence Verification & Evaluation -> Event Processing & Detection Engine: Corpus Constraints and Query Requirements

From: Evidence Verification & Evaluation - Evidence Verification & Evaluation
To: Event Processing & Detection Engine - Data Processing & Detection
Date: 2026-09-21

## What this is

Not a deliverable handoff - Event Processing & Detection Engine provides to Evidence Verification & Evaluation, not the other way round. This is
the input Event Processing & Detection Engine's handoff section lists as *"field and query requirements from
AUTH-Evidence Verification & Evaluation"*, plus one corpus property found during ground-truth verification that
constrains how `evidence_id` can be defined.

Sent now because Event Processing & Detection Engine's normaliser is not yet written, and item 1 is expensive to
unwind once it is.

Everything here is reproducible from the public datasets. No answer-key content
is included.

---

## 1. BLOCKING - `evidence_id` must be scoped per scenario

**Windows Event Record IDs are not unique across the MAIR corpus.**

S02 and S03 were both recorded after restoring the same VMware snapshot, so
Windows resumed record numbering from the same value in each. The same record
number therefore denotes a **completely different event** in each scenario.

| Record ID | In `S02/raw/Security.evtx` | In `S03/raw/Security.evtx` |
|---|---|---|
| 43584 | EventID 4624, 02:05:30 | EventID 4688 `dllhost.exe`, 02:25:15 |
| 43628 | EventID 4688 `msedgewebview2.exe`, 02:05:33 | EventID 4688 `whoami.exe`, 02:25:50 |
| 43571 | EventID 4625, 02:05:11 | EventID 4688 `sppsvc.exe`, 02:25:14 |

Overlap is not marginal: **335** shared record IDs on Security (range
43483-43817) and **1526** on Sysmon (range 25033-26558). S01 does not overlap
either, being from a different host and year.

### Required

`evidence_id` must be derived from **scenario + channel + record ID**, and must
be stable across re-runs of the normaliser. For example:

```
S02-SEC-43584
S02-SYS-25891
S01-SEC-31213331
```

The exact string format is Event Processing & Detection Engine's call - the requirement is that the tuple is
complete and that the ID round-trips back to exactly one event in exactly one
scenario file.

### Why this matters

An `evidence_id` keyed on the record number alone resolves an S02 authentication
claim to an unrelated S03 process event **with no error raised**. Nothing in the
pipeline would surface it: the lookup succeeds, returns a real event, and the
claim looks supported. This is the exact failure the shared evidence-ID contract
was written to prevent.

Evidence Verification & Evaluation will reject any claim whose evidence reference cannot be resolved to exactly
one event in exactly one scenario.

---

## 2. REQUIRED - preserve sub-millisecond timestamp precision

The normalised-event contract specifies timezone-aware timestamps but says
nothing about precision. Second-level or millisecond-level truncation breaks
evaluation.

S01 contains bursts of causally-related activity inside a single second. Measured
from the public telemetry, one such burst holds five events spanning
**108 milliseconds**, of which the closest pair is **214 microseconds** apart,
and it includes a Security and a Sysmon record describing the same process
launch **1.06 ms** apart.

Verify it yourself:

```powershell
Get-WinEvent -Path datasets/S01/raw/Sysmon.evtx -Oldest |
  Where-Object { $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') -eq '2022-08-31 17:47:04' } |
  ForEach-Object { "{0}  {1}" -f $_.RecordId, $_.TimeCreated.ToUniversalTime().ToString('HH:mm:ss.fffffff') }
```

Consequences:

- Truncating to **seconds** collapses the whole burst into one instant, losing
  the ordering of causally-related events.
- Truncating to **milliseconds** still ties the closest pair.
- Losing cross-source sub-millisecond ordering makes a Security and a Sysmon
  view of the same process launch arbitrarily ordered relative to each other.

### Required

Preserve the full 100-nanosecond tick precision from the EVTX record, and keep
it through normalisation, storage and the query API. If the storage layer cannot
hold it, keep the original value as a string alongside the parsed timestamp.

This is not a cosmetic concern. Reconstruction is scored partly on whether the
timeline is correctly ordered, and Incident Reconstruction Orchestrator's correlation depends on ordering that
only exists below the millisecond.

---

## 3. REQUIRED - query API semantics Evidence Verification & Evaluation depends on

Evidence Verification & Evaluation is a listed consumer of the Query API. Verification behaviour depends on
these semantics being explicit:

**Unknown `evidence_id` returns a defined not-found result.** Not an exception,
not an empty object that is indistinguishable from a real event with empty
fields. Evidence Verification & Evaluation must be able to tell "this reference is fabricated" apart from "this
reference is real but has no data in that field" - that distinction is the
difference between a `rejected` and an `unverified` verdict.

**Never fuzzy-match or return a nearest neighbour.** A lookup for a nonexistent
ID must fail closed. Silently returning the closest record would mask exactly
the fabricated-reference case Evidence Verification & Evaluation exists to catch.

**Deterministic ordering.** The same query must return the same events in the
same order on every run. Scoring has to be reproducible, and the protocol
requires that raw outputs and scoring rules make each reported result
repeatable.

**Read-only.** No call reachable from an agent may mutate the corpus.

**Bounded time-range filters must document inclusive/exclusive boundaries** at
both ends. Several ground-truth stages sit within milliseconds of each other, so
an off-by-one boundary changes which events a window returns.

---

## 4. REQUIRED - fields Evidence Verification & Evaluation needs on the normalised event

Beyond the agreed minimum, Evidence Verification & Evaluation needs these preserved for independent
verification:

- `scenario_id` - so scoping is explicit rather than inferred from file path
- `channel` - `Security` or `Microsoft-Windows-Sysmon/Operational`
- `record_id` - the original EventRecordID, unmodified
- `source_event_id` - the Windows Event ID (4624, 4688, Sysmon 1, 11, ...)
- `raw reference` - enough to re-derive the event from the original EVTX

That last one is not optional. Evidence Verification & Evaluation's verification path uses **independent access
to the source telemetry**, per the role definition, rather than trusting the
normalised copy. If Evidence Verification & Evaluation cannot get back to the original record, the verification
is not independent and the result is not defensible.

---

## 5. TO AGREE JOINTLY - detection metric definitions (Event Processing & Detection Engine + Dataset & Ground Truth Management + Evidence Verification & Evaluation)

The evaluation section requires that we agree, **before the baseline is run**:

- what counts as a positive event label
- the true-positive and false-positive definitions
- the unit being counted

Evidence Verification & Evaluation has drafted the reconstruction-side and claim-side units already. Two corpus
properties Event Processing & Detection Engine should know before proposing detection definitions:

- Roughly **half of each lab export falls outside the declared scenario window**
  (S02: 178 of 349 Security events; S03: 189 of 352). This is the operator's own
  session that verified and exported the logs.
- Each lab export contains **one Security 1102 audit-log-clear**, from the log
  reset at the start of the runbook. A log clear is a textbook T1070.001
  indicator and appears in both lab scenarios, so a naive rule will fire on it
  in both.

Evidence Verification & Evaluation proposes treating operator/scaffolding activity as out of scope and
non-penalised, tallied separately rather than counted in headline precision.
Worth a short call to settle this before either of us writes scoring code.

---

## 6. FYI - manifest schema differs between scenarios

`S01/metadata/manifest.json` uses `schema_version`, `generated_at_utc`,
`file_count`, `relative_path`, `source_channel`. S02 and S03 use
`collection_time_utc`, `collection_host`, `source`, `channel`, and carry no
`schema_version`.

Both satisfy the raw-log-bundle contract, but as written the parser needs two
code paths. Raised with Dataset & Ground Truth Management as a non-blocking cleanup - flagging it here since Event Processing & Detection Engine
is the affected consumer.

---

## 7. Reproducing all of the above

Everything in this note comes from the public datasets:

```bash
powershell -ExecutionPolicy Bypass -File scripts/verify-ground-truth.ps1
```

The record-ID collisions in item 1 are reported as standing warnings by check
6/7. The validator exits 0 - the collisions are a corpus property to design
around, not a dataset defect.

Independent spot check of the collision, no ground truth needed:

```powershell
foreach ($s in 'S02','S03') {
  Get-WinEvent -Path "datasets/$s/raw/Security.evtx" -FilterXPath "*[System[EventRecordID=43584]]" |
    ForEach-Object { "{0} rec=43584 -> EventID {1} at {2}Z" -f $s, $_.Id, $_.TimeCreated.ToUniversalTime().ToString('HH:mm:ss.fffffff') }
}
```

Expected output - same record number, two different events:

```
S02 rec=43584 -> EventID 4624 at 02:05:30.0430374Z
S03 rec=43584 -> EventID 4688 at 02:25:15.6704553Z
```

Note that `TimeCreated` renders in local time by default. All timestamps in this
note are UTC, which is why the command above converts explicitly - another
reason item 2 matters.

---

## Summary of asks

| # | Item | Status | Owner |
|---|---|---|---|
| 1 | Scope `evidence_id` by scenario + channel + record ID | Blocking | Event Processing & Detection Engine |
| 2 | Preserve 100ns timestamp precision end to end | Required | Event Processing & Detection Engine |
| 3 | Not-found semantics, no fuzzy match, deterministic order, read-only | Required | Event Processing & Detection Engine |
| 4 | Preserve `scenario_id`, `channel`, `record_id`, `source_event_id`, raw reference | Required | Event Processing & Detection Engine |
| 5 | Agree detection metric definitions before the baseline runs | Joint | Event Processing & Detection Engine + Dataset & Ground Truth Management + Evidence Verification & Evaluation |
| 6 | Align manifest schema across scenarios | Non-blocking | Dataset & Ground Truth Management |

Items 1-4 only need Event Processing & Detection Engine's agreement, not a meeting. Item 5 needs a short call.
