# M2 Normalised Event Schema

Owner: M2 (Data Processing & Detection). Status: implemented, `SCHEMA_VERSION = "m2-event-v1"`.
Source of truth: `m2/schema.py`, `m2/ids.py`, `m2/timeutil.py`, `m2/normalise.py`.

The normalised event is what M2 hands to every other member. It is a frozen, strict,
extra-forbid pydantic v2 model: a consumer cannot mutate a corpus event, and a typo or a type
slip is an error rather than a silent attribute. The corpus itself is written as one JSON
object per line under `out/corpus/<scenario>.jsonl`, sorted by `(timestamp_ticks, evidence_id)`,
with sorted keys, `ensure_ascii=False` and `\n` line endings.

## 1. `evidence_id`: scenario + channel + record

```
evidence_id = f"{scenario_id}-{CHANNEL_CODE}-{record_id}"

CHANNEL_CODE: "Security"                              -> "SEC"
              "Microsoft-Windows-Sysmon/Operational"  -> "SYS"

examples: S02-SEC-43584   S02-SYS-25891   S01-SEC-31213331
regex:    ^(?P<scenario>[A-Za-z0-9_-]{1,80})-(?P<code>SEC|SYS)-(?P<record>[1-9][0-9]*)$
```

`record_id` is the original `EventRecordID`, unmodified. The ID is parsed **from the right**,
so a scenario ID may itself contain hyphens (`SYN-A-SEC-1` is scenario `SYN-A`, record `1`).

### Why the scenario is in the ID

Windows record numbers are **not unique across the corpus**. S02 and S03 were both recorded
after restoring the same VM snapshot, so Windows resumed numbering from the same value in each.
Record `43584` is a Security `4624` at `02:05:30` in S02 and a Security `4688` (`dllhost.exe`)
at `02:25:15` in S03. The overlap is not marginal: 335 shared Security record IDs
(43483–43817) and 1526 shared Sysmon record IDs (25033–26558).

An ID keyed on the record number alone would resolve an S02 claim to an unrelated S03 process
event **with no error raised**. Nothing downstream could tell: the lookup succeeds and returns
a real event. The scenario is therefore part of the key, and the model's validator rejects any
event whose `evidence_id` does not equal the ID derived from its own `scenario_id`, `channel`
and `record_id`.

`make_evidence_id(scenario, channel, record)` also equals `m3.models.evidence_id_for(scenario, record)`
for Security events, and `m2/tests/test_ids.py` pins that equality.

Malformed IDs are rejected, never coerced: `s02-sec-1` (case), `S02-SEC-01` (leading zero),
`S02-SEC-0`, `S02-43584` (no channel), `S02-XYZ-1` (unknown code) and whitespace are all
invalid, and a lookup for one returns `status="invalid_id"`.

## 2. Timestamps

| field | type | rule |
|---|---|---|
| `timestamp_utc` | `str` | exactly `YYYY-MM-DDTHH:MM:SS.fffffffZ` — always seven fractional digits, always `Z` |
| `timestamp_ticks` | `int` | 100 ns units on M3's `utc_ticks` epoch |

Both come from the **raw 64-bit FILETIME** of the record's `TimeCreated/@SystemTime`, read
through the binary-XML substitution node. Conversion is **integer-only**: ticks are never passed
through `datetime`, `float` or `time`, which would silently truncate to microseconds. For
`S02-SEC-43584` that difference is visible: the record holds `.0430374`, and python-evtx's own
renderer prints `.043036`.

`timestamp_ticks = filetime + 504912096000000000` (the FILETIME↔M3 epoch offset, i.e.
`date(1601, 1, 1).toordinal() * 86400 * 10⁷`), which is also
`.NET TimeCreated.ToUniversalTime().Ticks + 864000000000`. `m2/timeutil.py` equality with
`m3.models.utc_ticks` is tested on several values, including a six-digit S01 source and a
`+00:00` offset. The model's validator rejects any `timestamp_utc` that is not the canonical
rendering of its own `timestamp_ticks`.

## 3. Fields

| Field | Type | Notes |
|---|---|---|
| `evidence_id` | `str` | section 1; must equal the ID derived from the next three fields |
| `scenario_id` | `str` | explicit, from the manifest; never inferred from a path at query time |
| `channel` | `Literal["Security", "Microsoft-Windows-Sysmon/Operational"]` | the record's `System/Channel` |
| `source_type` | `Literal["windows_security", "sysmon"]` | derived from `channel`; the validator enforces the pairing |
| `record_id` | `int > 0` | original `EventRecordID` |
| `source_event_id` | `int > 0` | Windows Event ID (`4624`, `4688`, Sysmon `1`, `11`, …) |
| `timestamp_utc` | `str` | section 2 |
| `timestamp_ticks` | `int` | section 2 |
| `host` | `str \| None` | `System/Computer`. Absent → `None` **plus a warning**; present but empty → `""` and no warning |
| `user` | `str \| None` | mapping table in section 4; never case-folded, never domain-stripped |
| `event_data` | `dict[str, str]` | **every** `EventData/Data` name/value pair, values verbatim as strings |
| `raw_reference` | `str` | `evtx://datasets/<scenario>/raw/<file>#EventRecordID=<record_id>` |
| `source_sha256` | `str` | the digest the scenario manifest declares for that file, verbatim (the datasets store it in uppercase) |
| `raw_xml` | `str` | the original record XML, unmodified |
| `in_scenario_window` | `bool` | `window_start_ticks <= ticks <= window_end_ticks` — **inclusive at both ends** |
| `parse_warnings` | `tuple[str, ...]` | what was missing or odd; a record is **never dropped** for one |

Notes that matter to consumers:

* **Nothing keys on `record_id` alone.** `M6` re-derives a record from `raw_reference`, and the
  ID keeps the scenario explicit.
* **`""` and `None` are different facts.** An empty `TargetUserName` is an empty string, an
  absent field is `None` plus a warning. The query API keeps the distinction: `user=""` matches
  the empty value and only that, while `user=None` means "do not filter".
* **`in_scenario_window` is inclusive at both ends**, because a scenario window is a declared
  capture interval. A *query* window is `[start, end)` — see `docs/M2_QUERY_API.md`.
* A `Data` element without a `Name` attribute cannot be keyed, so it is not in `event_data`; it
  is still visible verbatim in `raw_xml`, so nothing is lost.

## 4. Mapping table

| Input | Output |
|---|---|
| `scenario_id` | the scenario directory's manifest `scenario_id` |
| `channel` | `System/Channel` of the record, checked against the source file's manifest channel |
| `record_id`, `source_event_id` | `System/EventRecordID`, `System/EventID` |
| `timestamp_utc`, `timestamp_ticks` | raw `TimeCreated/@SystemTime` FILETIME, integer conversion |
| `host` | `System/Computer` verbatim (`None` when the element is absent) |
| `user` — Security 4624, 4625, 4634, 4647, 4648 | `EventData/TargetUserName` |
| `user` — any other Security event | `EventData/SubjectUserName` |
| `user` — Sysmon | `EventData/User` |
| `user` — field absent | `None` + `parse_warnings` entry |
| `event_data` | every `EventData/Data` pair, values verbatim |
| `raw_reference` | `evtx://datasets/<scenario>/raw/<file>#EventRecordID=<record_id>` |
| `source_sha256` | the manifest digest of the source file |
| `raw_xml` | the original record XML |
| `in_scenario_window` | scenario metadata window, inclusive |
| `parse_warnings` | one entry per missing or odd field |

A present-but-empty field stays `""`: "no value" and "absent" are different facts.

## 5. Source manifests (two shapes)

`datasets/<scenario>/metadata/manifest.json` and `scenario_metadata.json` come in two shapes and
both are parsed explicitly; a file matching neither, or mixing them, raises rather than being
half-read.

| | S01 | S02 / S03 |
|---|---|---|
| manifest markers | `schema_version`, `generated_at_utc` | `collection_time_utc`, `collection_host` |
| file path | `relative_path` (e.g. `raw/Security.evtx`) | `filename` (always under `raw/`) |
| channel field | `source_channel` | `channel` |
| window fields | `capture_start_utc` / `capture_end_utc` | `scenario_start_utc` / `scenario_end_utc` |

Every declared source file must exist, be real content and match its declared SHA-256 before M2
parses it, and a record whose `System/Channel` contradicts its file's manifest channel aborts
the whole run. An unfetched Git LFS pointer is reported as such rather than as a hash mismatch.

## 6. Examples

Both are real corpus events, copied from `out/corpus/S02.jsonl` with `raw_xml` elided (the field
is present in full — 2088 and 1193 characters for these two).

### Security: `S02-SEC-43584` (the colliding record number)

```json
{
  "channel": "Security",
  "event_data": {
    "AuthenticationPackageName": "Negotiate",
    "IpAddress": "127.0.0.1",
    "LogonProcessName": "User32 ",
    "LogonType": "2",
    "ProcessName": "C:\\Windows\\System32\\svchost.exe",
    "SubjectDomainName": "WORKGROUP",
    "SubjectUserName": "MAIR-WIN11-LAB$",
    "TargetDomainName": "MAIR-WIN11-LAB",
    "TargetUserName": "mair_user",
    "WorkstationName": "MAIR-WIN11-LAB"
  },
  "evidence_id": "S02-SEC-43584",
  "host": "MAIR-WIN11-LAB",
  "in_scenario_window": true,
  "parse_warnings": [],
  "raw_reference": "evtx://datasets/S02/raw/Security.evtx#EventRecordID=43584",
  "record_id": 43584,
  "scenario_id": "S02",
  "source_event_id": 4624,
  "source_sha256": "D396CE599723189331D440EDD55CC055C28EB4B6AD45A421D07A8E83A2F0EBA7",
  "source_type": "windows_security",
  "timestamp_ticks": 639256395300430374,
  "timestamp_utc": "2026-09-21T02:05:30.0430374Z",
  "user": "mair_user",
  "raw_xml": "<Event …>  <!-- elided here; 2088 characters in the corpus -->"
}
```

The same record number is `S03-SEC-43584`: Event ID `4688`, `dllhost.exe`, at
`2026-09-21T02:25:15.6704553Z`. Two different events, two different IDs.

### Sysmon: `S02-SYS-25891` (file create)

```json
{
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "event_data": {
    "CreationUtcTime": "2026-09-21 02:06:12.474",
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "ProcessGuid": "{6708084d-90fb-6ab0-1c01-000000000e00}",
    "ProcessId": "784",
    "RuleName": "-",
    "TargetFilename": "C:\\Users\\mair_user\\Documents\\s02_marker.txt",
    "User": "MAIR-WIN11-LAB\\mair_user",
    "UtcTime": "2026-09-21 02:06:12.474"
  },
  "evidence_id": "S02-SYS-25891",
  "host": "MAIR-WIN11-LAB",
  "in_scenario_window": true,
  "parse_warnings": [],
  "raw_reference": "evtx://datasets/S02/raw/Sysmon.evtx#EventRecordID=25891",
  "record_id": 25891,
  "scenario_id": "S02",
  "source_event_id": 11,
  "source_sha256": "9EFA2E10CDBBE44893804C7E7225DAC31A876FB188D1C52542F2F461FF4A70D1",
  "source_type": "sysmon",
  "timestamp_ticks": 639256395724766070,
  "timestamp_utc": "2026-09-21T02:06:12.4766070Z",
  "user": "MAIR-WIN11-LAB\\mair_user",
  "raw_xml": "<Event …>  <!-- elided here; 1193 characters in the corpus -->"
}
```

Note that Sysmon's own `UtcTime` field has millisecond precision; M2's `timestamp_ticks` keeps
the record's full 100 ns precision, which is why the two differ.

## 7. Change control

* `SCHEMA_VERSION = "m2-event-v1"` identifies this field set. The corpus manifest carries
  `schema_version = "m2-corpus-v1"` separately, so a change in *how* files are written is
  distinguishable from a change in *what* an event is.
* A field rename, a type change, a new required field, a change to the ID format or a change to
  the `""`/`None`, inclusivity or ordering rules **is a contract change**: it affects M3
  (`m3/queries/interface.py`, `m3/models.py`, `m3/queries/semantics.py`), M5 and M6. It needs a
  new `SCHEMA_VERSION`, an entry in M2's response to
  [`docs/M6_TO_M2_INTERFACE_NOTE.md`](M6_TO_M2_INTERFACE_NOTE.md) (items 1–4), and reviewer
  approval before it lands.
* Adding an optional field with a default, or adding a new scenario directory, is not a
  contract change.
* The pinning tests are `m2/tests/test_ids.py`, `m2/tests/test_timeutil.py`,
  `m2/tests/test_schema.py` and `m2/tests/test_normalise.py`; the real-evidence anchors are in
  `m2/tests/test_normalise.py` and `m2/tests/test_real_corpus.py`. If a change makes one of
  them fail, the change is wrong, not the test.
