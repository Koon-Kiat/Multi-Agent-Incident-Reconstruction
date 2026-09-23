# Event Processing & Detection Engine

The engine turns the original EVTX exports in `datasets/S0*/raw/` into a stable, queryable **normalised
event corpus**, exposes a deterministic read-only **query API**, and runs the **conventional
(non-LLM) detection baseline** over it, with precision/recall/F1 scoring code ready for agreed
labels.

Everything here is deterministic, read-only and offline. There is no LLM, no machine learning, no
anomaly model, no automatic response and no verdict logic: a detection is a *finding*, not a
conclusion, and the engine never sees the ground truth. The answer key decides what a detection is worth;
The engine only implements the arithmetic (`docs/DETECTION_METRICS_PROPOSAL.md`).

Delivered in PR #8. The existing package path remains `event_processing/`.

## Contents

* [What is in here](#what-is-in-here)
* [Install](#install)
* [CLI](#cli)
* [Python API](#python-api)
* [Contracts](#contracts)
* [Determinism and read-only guarantees](#determinism-and-read-only-guarantees)
* [Tests](#tests)
* [Known limitations](#known-limitations)

## What is in here

| Module | Contract |
|---|---|
| `event_processing/ids.py` | `evidence_id = <scenario>-<SEC\|SYS>-<record_id>`; parse from the right; malformed IDs raise |
| `event_processing/timeutil.py` | 100 ns tick arithmetic only; `timestamp_utc` is always `YYYY-MM-DDTHH:MM:SS.fffffffZ` |
| `event_processing/manifest.py` | both dataset manifest shapes; SHA-256 verification; Git-LFS pointer detection |
| `event_processing/evtx_reader.py` | the one EVTX parser (raw FILETIME, EventData, raw XML), opened read-only |
| `event_processing/normalise.py` | raw record → `NormalisedEvent`; a missing optional field is a warning, never a dropped record |
| `event_processing/schema.py` | the frozen, strict `NormalisedEvent` contract (schema version `security-event-v1`) |
| `event_processing/corpus.py` | writes `<scenario>.jsonl` (sorted by `(timestamp_ticks, evidence_id)`) + `corpus_manifest.json` |
| `event_processing/query.py` | `EventStore`: verified load, exact `lookup`, `[start, end)` `query`, bounded helpers |
| `event_processing/adapters/authentication_provider.py` | `CorpusAuthenticationProvider`, Authentication Investigation Agent's `AuthenticationEventProvider` over one store |
| `event_processing/detection/` | 12 rules, the engine, and the run/summary artefacts (`detection-run-v1`) |
| `event_processing/metrics.py` | P/R/F1 over agreed labels (`detection-score-v1`); no definitions of its own |
| `event_processing/__main__.py` | the CLI described below |

Documents: [`../docs/EVENT_SCHEMA.md`](../docs/EVENT_SCHEMA.md) (field by field),
[`../docs/EVENT_QUERY_API.md`](../docs/EVENT_QUERY_API.md) (every function and its semantics),
[`../docs/DETECTION_RULES.md`](../docs/DETECTION_RULES.md) (the rules and the baseline run),
[`../docs/DETECTION_METRICS_PROPOSAL.md`](../docs/DETECTION_METRICS_PROPOSAL.md) (DRAFT metric
definitions), [`../docs/PROCESSING_VERIFICATION_HANDOFF.md`](../docs/PROCESSING_VERIFICATION_HANDOFF.md) (the reply to Evidence Verification & Evaluation's
interface note) and [`../docs/PROCESSING_PROVIDER_REPLY.md`](../docs/PROCESSING_PROVIDER_REPLY.md) (the reply to Authentication Investigation Agent's
integration handoff, including the provider contract-suite result).

## Install

CI runs **Python 3.11**; 3.13 is what the project currently develops on. The only runtime
dependency the engine adds is `python-evtx`; `event_processing/adapters/authentication_provider.py` also imports `authentication_agent`.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
```

The EVTX files themselves are Git LFS objects and are **not** fetched by a plain checkout. Without
them the corpus cannot be built; every test that needs real EVTX skips with a reason (see
[Tests](#tests)). Generated output always goes to `out/`, which is gitignored.

## CLI

`python -m event_processing <command>` (or the `mair-events` script). Every command exits `0` on success, `1` when it
failed for a real reason, and `2` on invalid input; failures print one line to stderr, never a
traceback.

```text
usage: event_processing [-h] {normalise,lookup,query,detect,score} ...

Normalise, query and detect over the MAIR EVTX corpus

  normalise   parse datasets/S0*/raw/*.evtx into a normalised corpus
  lookup      resolve one evidence_id against a corpus
  query       query one scenario over a UTC [start, end) window
  detect      run the conventional detection baseline over a corpus
  score       score detection output against an agreed label file
```

### `normalise` — build the corpus

```powershell
.\.venv\Scripts\python.exe -m event_processing normalise --datasets datasets --out out/corpus
```

```text
S01: 2700 events -> S01.jsonl
S02: 1930 events -> S02.jsonl
S03: 2031 events -> S03.jsonl
total: 6661 events; manifest -> out\corpus\corpus_manifest.json
```

Every source file's SHA-256 is verified against its manifest before a record is parsed, and the
command aborts on a mismatch or on a duplicated `evidence_id`. A scenario id may not be `summary`
(reserved for `detect`'s own run summary; case-insensitive). `--out` is checked **before anything
is created**: it must not resolve inside a `datasets/` or `ground_truth/` tree, and it must not be
the `--datasets` root or a directory under it — so a `--out` typo can never overwrite evidence or
mix generated output into the tree the next run parses. Both refusals exit `2`.

### `lookup` — resolve one evidence ID

```powershell
.\.venv\Scripts\python.exe -m event_processing lookup S02-SEC-43584
```

```json
{"channel": "Security", "event_data": {"TargetUserName": "mair_user", ...},
 "evidence_id": "S02-SEC-43584", "record_id": 43584, "scenario_id": "S02",
 "source_event_id": 4624, "timestamp_utc": "2026-09-21T02:05:30.0430374Z", ...}
```

The event is printed as one line of sorted-key JSON (trimmed here; `raw_xml` and the full
`event_data` are included). A well-formed ID the corpus does not hold exits `1` with
`is not in out/corpus`; a malformed ID exits `2` with `malformed evidence_id`. There is no fuzzy
matching and no nearest neighbour.

### `query` — a bounded, exact, ordered window

```powershell
.\.venv\Scripts\python.exe -m event_processing query S02 --start 2026-09-21T02:05:00Z --end 2026-09-21T02:06:00Z `
  --corpus out/corpus --event-id 4624 --limit 1
```

```text
{"channel": "Security", "event_data": {"TargetUserName": "SYSTEM", ...},
 "evidence_id": "S02-SEC-43547", ...}          <- one JSON line per matching event
The engine: query: truncated at 1 of 6 matches          <- stderr; more events matched than were returned
```

The window is UTC **`[start, end)`**: `start` is included, `end` is excluded. Filters
(`--channel`, `--event-id`, `--host`, `--user`) are exact and case-sensitive; repeating
`--channel`/`--event-id` widens the filter. Ordering is always `(timestamp_ticks, evidence_id)`
ascending. A window longer than 3600 s or a limit above 1000 is rejected, never clamped.

### `detect` — the conventional baseline

```powershell
.\.venv\Scripts\python.exe -m event_processing detect --corpus out/corpus --out out/detections
```

```text
S01: 9 detections -> S01.json
S02: 15 detections -> S02.json
S03: 14 detections -> S03.json
total: 38 detections; summary -> out\detections\summary.json
```

`--out` is a directory `detect` owns: stale **the engine run files** there from an earlier corpus revision
are removed, so `event_processing score` never reads a run that no longer describes the corpus. Only a file whose
name is `<scenario_id>.json`/`summary.json` *and* whose contents carry the the engine detection schema
marker (`detection-run-v1`; the summary also carries the `detection-summary` marker) is removed —
anything else in the directory is left exactly as it is. `detect` refuses a `--out` that resolves
inside a `datasets/` or `ground_truth/` tree, or that is the corpus directory, and exits `2`
without writing. Before it writes anything it also refuses a name that is not a regular file (a
directory called `S02.json`) and a symbolic link, and a regular file that is not an Event Processing & Detection Engine detection
artefact — a foreign `S02.json` or `summary.json` — exiting `1` and writing nothing rather than
overwriting the caller's data. Every document is staged under a dotted `.tmp` name and renamed
into place only once all of them exist, so an I/O failure part way through leaves the previous run
intact. A run also sweeps its own staging leftovers (`.<name>.json.tmp`) that a killed process left
in `--out` before it writes — only a regular file matching that pattern is removed, nothing else.
See
[`../docs/DETECTION_RULES.md`](../docs/DETECTION_RULES.md) for all 12 rules, their frozen
thresholds, their benign lookalikes and what is deliberately not covered. The baseline is **not
scored**: there are no agreed labels yet.

> **Upgrade note (pre-phase-5 output).** The `summary.json` written by an Event Processing & Detection Engine build from before the
> phase-5 `detection-summary` marker was added does not carry that marker, so `detect` treats it as
> a foreign file and refuses the whole `--out` directory with exit `1` until the old
> `summary.json` is deleted (or `--out` is pointed at a fresh directory). Nothing is overwritten;
> the refusal is the safety check doing its job.

### `score` — P/R/F1 once the labels are agreed

```powershell
.\.venv\Scripts\python.exe -m event_processing score --detections out/detections --labels <labels.csv> `
  --corpus out/corpus --out out/scores
```

`--labels` and `--corpus` go together: every labelled `evidence_id` is checked against the corpus
being scored, and a label naming an event the corpus does not hold exits `2` instead of becoming a
silent false negative. Every detection run must also name that corpus's manifest digest as its
`corpus_manifest_sha256`; a run computed from a different corpus revision exits `1` rather than
being scored against the wrong events. An unreadable label file or detection run — bad encoding,
broken CSV/JSON, a locked or permission-denied file, or a directory sitting where a
`<scenario>.json` run file is expected — exits `2` with a one-line message, never a traceback.
`--out` is refused inside `datasets/` or `ground_truth/`. The report lists **every rule that ran**,
including a rule that flagged nothing (its false negatives are part of the picture). The output
shape is:

```text
overall: TP=1 FP=2 FN=0 precision=0.333 recall=1.000 f1=0.500 (flagged=4, positives=1, excluded=1, flagged_excluded=1, unflagged_excluded=0)
SYN-B: TP=1 FP=2 FN=0 precision=0.333 recall=1.000 f1=0.500 (...)
report -> out\readme-scores\score_report.json
```

Those numbers come from a **synthetic** three-failures-then-success corpus built for this README,
not from the MAIR scenarios: the real baseline must not be scored until the the engine/Dataset & Ground Truth Management and Evidence Verification & Evaluation call agrees
the definitions, so no real metric appears anywhere in this repository
(`../docs/DETECTION_METRICS_PROPOSAL.md`, and task T4.3 is BLOCKED). An undefined metric (`0/0`)
prints `undefined` and serialises as `null`, never `0`.

## Python API

### The corpus: `EventStore`

```python
from event_processing.query import EventStore

store = EventStore.load("out/corpus")          # verifies the manifest and every .jsonl digest

found = store.lookup("S02-SEC-43584")
found.status          # "found"
found.event.user      # "mair_user"
found.event.timestamp_utc  # "2026-09-21T02:05:30.0430374Z"

store.lookup("S02-SEC-1").status   # "not_found"  (well-formed, not in this corpus)
store.lookup("nope").status        # "invalid_id" (malformed)
store.scenario_ids                 # ("S01", "S02", "S03")
store.evidence_ids                 # every ID the store can resolve, sorted

result = store.query(
    "S02", "2026-09-21T02:05:00.0000000Z", "2026-09-21T02:06:00.0000000Z",
    event_ids=(4624,), limit=5,
)
len(result.events), result.truncated, result.total_matched
```

Helpers: `lookup_many(ids)`, `scenario_events(id)`, `process_by_guid(scenario, guid)`,
`children_of(scenario, parent_guid)`, `window_around(evidence_id, seconds)`. Limits come from a
frozen `QueryLimits(max_window_seconds=3600, max_limit=1000)`. Returned events are frozen models,
so a consumer cannot mutate the store through them.

### The Authentication Investigation Agent boundary: `CorpusAuthenticationProvider`

Implements `authentication_agent.queries.interface.AuthenticationEventProvider`, so an Authentication Investigation Agent investigation can run over
the real corpus instead of its synthetic provider:

```python
from event_processing.adapters.authentication_provider import CorpusAuthenticationProvider
from event_processing.query import EventStore
from authentication_agent.models import QueryRequest

provider = CorpusAuthenticationProvider(EventStore.load("out/corpus"))

request = QueryRequest(
    scenario_id="S02",
    start_utc="2026-09-21T02:05:00.0000000Z",
    end_utc="2026-09-21T02:06:00.0000000Z",
    event_ids=(4624, 4625),
    limit=5,
)
result = provider.query(request)          # authentication_agent.models.QueryResult, authentication ordering and semantics
result.events[0].evidence_id              # "S02-SEC-43547"
provider.get_event("S02-SEC-43584")       # authentication_agent.models.AuthenticationEvent, or None
```

`get_event` preserves **any** `Security` record, whatever its Event ID — Authentication Investigation Agent's own contract fixture
looks up a Security 4634 and requires it back unchanged. `None` covers a malformed ID, an ID the
corpus lacks and a Sysmon event (Authentication Investigation Agent's model admits the `Security` channel only); Event Processing & Detection Engine's own `lookup`
keeps those cases apart when a caller needs them. `query` is the narrower door: it offers only the
`Security` events the request's Event IDs admit, which for `QueryRequest` is 4624/4625 alone.
`event_data` values are passed through verbatim — Event Processing & Detection Engine never case-folds, strips a domain or trims an
identifier.

### The detections: `DetectionEngine`

```python
from event_processing.detection.engine import DetectionEngine, corpus_manifest_digest, write_detections
from event_processing.query import EventStore

store = EventStore.load("out/corpus")
engine = DetectionEngine(store, corpus_manifest_sha256=corpus_manifest_digest("out/corpus"))

engine.triggers_for("S02")   # 15 detections, ordered by (window_start_utc, detection_id)
write_detections("out/corpus", "out/detections")   # the CLI's own write path
```

Each `Detection` carries `detection_id`, `rule_id`/`rule_version`, `scenario_id`,
`trigger_evidence_ids`, the closed `[window_start_utc, window_end_utc]` span of its triggers,
`attack_technique`, `severity` and a one-line `rationale`. `trigger_evidence_ids` are the only
events a detection flags, which is what the metric unit is.

### The corpus writer

```python
from event_processing.corpus import normalise_datasets

manifest = normalise_datasets("datasets", "out/corpus")   # the CLI's implementation
```

## Contracts

The five invariants agreed with the downstream components, and where each is implemented and proved:

| # | Invariant | Where | Test |
|---|---|---|---|
| I1 | `evidence_id` is scoped `scenario + channel + record`, parsed from the right, and equals Authentication Investigation Agent's `evidence_id_for` | `event_processing/ids.py` | `test_ids.py`, `test_query_real.py::test_the_colliding_record_id_resolves_to_two_different_events` |
| I2 | full 100 ns precision, integer arithmetic only, canonical `…fffffffZ` strings | `event_processing/timeutil.py`, `event_processing/schema.py` | `test_timeutil.py`, `test_schema.py` |
| I3 | explicit `found`/`not_found`/`invalid_id`, no fuzzy match, `[start, end)`, `(timestamp_ticks, evidence_id)` order, bounds rejected not clamped, read-only | `event_processing/query.py` | `test_query.py`, `test_query_real.py` |
| I4 | every required field on every event, missing optional data is a warning rather than a dropped record | `event_processing/schema.py`, `event_processing/normalise.py` | `test_schema.py`, `test_normalise.py` |
| I5 | both manifest shapes, SHA-256 verification, LFS-pointer detection | `event_processing/manifest.py` | `test_manifest.py` |

Full detail, including the evidence-ID format and why the scenario prefix is mandatory, is in
[`../docs/EVENT_SCHEMA.md`](../docs/EVENT_SCHEMA.md) and
[`../docs/EVENT_QUERY_API.md`](../docs/EVENT_QUERY_API.md).

## Determinism and read-only guarantees

* Two runs of `normalise` over the same datasets write byte-identical `.jsonl` files and manifest;
  two runs of `detect` write byte-identical run files and summary.
* All generated JSON uses sorted keys, `ensure_ascii=False` and `\n` line endings, and contains no
  "now" timestamp. Run metadata lives in the separate manifest/run headers, which also record the
  source SHA-256 values.
* Nothing under `datasets/` is ever written to; EVTX files are opened read-only.
* `EventStore.load` verifies the manifest and every `.jsonl` digest before trusting a line, so a
  stale or edited corpus file raises instead of being queried.
* Every model is frozen and strict (`extra="forbid"`), and returned events are detached copies:
  no call reachable by a consumer can mutate the corpus, and no `eval`, shell command or network
  call exists anywhere in `event_processing/`. Log contents are treated as untrusted data.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp            # the full suite (authentication_agent + event_processing + contribution checks)
.\.venv\Scripts\python.exe -m pytest -q event_processing/tests --basetemp .test-tmp   # processing tests only
```

Unit tests use small synthetic fixtures in `event_processing/tests/fixtures/` and `event_processing/tests/synthetic.py` and run
everywhere. Tests that need the real EVTX exports go through the `real_evtx` / `real_corpus_dir`
helpers, which **skip with a reason** when a file is missing or is a Git-LFS pointer — so in CI
(`lfs: false`) the the engine suite is green with those tests skipped, and locally every anchor, count and
digest is checked. A test is never weakened to make a change pass.

The datasets root is `<repo>/datasets`. Set **`MAIR_DATASETS_DIR`** to run the whole suite in the
CI shape without touching the real exports — point it at an empty directory and every real-data
test skips with its reason instead of failing:

```powershell
$env:MAIR_DATASETS_DIR = "$env:TEMP/event_processing-no-evtx"
.\.venv\Scripts\python.exe -m pytest -q --basetemp .test-tmp
```

For the real authentication entry point and current integration findings, see
[the integration report](../docs/AUTHENTICATION_CORPUS_INTEGRATION.md).

## Known limitations

* **S01 is not like S02/S03.** It is a different host and year (`win-dc-mhaag-attack-range-602`,
  Windows Server 2016, August 2022, from the public Splunk `attack_data` set), while S02/S03 are
  2026 lab captures on `MAIR-WIN11-LAB`. Its manifest has the other shape, its `scenario_id` and
  timestamps differ, and it shares no record IDs with them.
* **Only two channels exist.** `NormalisedEvent.channel` is `Security` or
  `Microsoft-Windows-Sysmon/Operational`. Nothing else is exported, so no rule can see it.
* **The System-channel 7045 gap.** Service installs are only detectable through Security 4697 here:
  the System channel, which carries 7045, is not part of the export. `R-PERSIST-01` therefore has a
  narrower field of view than a real deployment would.
* **Security and Sysmon spell the same person differently.** Security events carry
  `TargetUserName`/`SubjectUserName` (often `mair_user`), Sysmon events carry `User` (often with a
  domain). The engine normalises neither: no case folding, no domain stripping, values verbatim, so the
  two channels can group the same human under two names. Scoring treats each event as its own unit
  (open question 1 in the metrics proposal).
* **A field the source does not carry is `None` or `""`, not absent.** `host` and `user` can be
  either; a present-but-empty value stays `""` and is distinct from missing. Consumers must not
  coalesce them.
* **`RuleRecord.params` is a plain `dict`** inside the otherwise frozen `DetectionRun`. A consumer
  holding a run can mutate that dictionary in place; treat a run as read-only and copy it before
  storing it. The values are always JSON primitives, so serialisation is unaffected.
* **`detect --out` owns only its own run files, and refuses two locations.** It removes a direct
  child only when the name is `<scenario_id>.json`/`summary.json` *and* the contents carry the the engine
  detection schema marker; every other file in the directory is left alone, so a `manifest.json`,
  a `package.json` or a foreign `S02.json` survives. A target name that is not a regular file (a
  directory called `S02.json`) or is a symbolic link is refused before anything is written. A
  `--out` resolving inside `datasets/` or `ground_truth/` (any path component, case-insensitive),
  or equal to the corpus directory, is refused with exit `2` before anything is read or written.
* **Metrics are arithmetic, not definitions.** `event_processing/metrics.py` reports precision/recall/F1 for
  whatever labels it is given; the unit, the positive label and the excluded category are still
  DRAFT (`../docs/DETECTION_METRICS_PROPOSAL.md`), and the real baseline stays unscored until
  they are agreed.
* **SQLite, dashboards, ML and response actions are out of scope** for the engine by design.
