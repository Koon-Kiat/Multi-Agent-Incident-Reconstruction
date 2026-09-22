# M2 → M6: Response to "Corpus Constraints and Query Requirements"

From: M2 — Data Processing & Detection
To: M6 — Evidence Verification & Evaluation
Date: 2026-09-22
Re: [`M6_TO_M2_INTERFACE_NOTE.md`](M6_TO_M2_INTERFACE_NOTE.md) (2026-09-21)

## Summary

Items 1–4 are **accepted and implemented**; each one below says what was built and which test
proves it. Item 5 is **pending the joint M2 + M1 + M6 call** — the code is written and tested, the
definitions are not agreed, and the real baseline is deliberately unscored
([`M2_DETECTION_METRICS_PROPOSAL.md`](M2_DETECTION_METRICS_PROPOSAL.md), DRAFT; task T4.3 is
BLOCKED in `task_plan.md`). Item 6 is handled by explicit dual-path manifest parsing, and the M1
alignment is still welcome.

| # | Item | Status | Where |
|---|---|---|---|
| 1 | Scope `evidence_id` by scenario + channel + record ID | **Done** | `m2/ids.py`, `m2/schema.py` |
| 2 | Preserve 100 ns timestamp precision end to end | **Done** | `m2/timeutil.py`, `m2/schema.py`, `m2/evtx_reader.py` |
| 3 | Not-found semantics, no fuzzy match, deterministic order, read-only, documented bounds | **Done** | `m2/query.py` |
| 4 | Preserve `scenario_id`, `channel`, `record_id`, `source_event_id`, raw reference | **Done** | `m2/schema.py`, `m2/normalise.py` |
| 5 | Agree detection metric definitions before the baseline runs | **Pending the call** | `m2/metrics.py` + the proposal |
| 6 | Align manifest schema across scenarios | **Handled either way** | `m2/manifest.py` |

None of this required the answer key, the runbook or the scenario labels. Everything quoted below
is reproducible from the public datasets with the commands in
[Verifying this yourself](#verifying-this-yourself).

---

## Item 1 — `evidence_id` scoped per scenario: accepted

The ID is exactly the tuple you asked for, plus a fixed channel code so the ID alone identifies one
record in one file:

```
evidence_id = f"{scenario_id}-{CHANNEL_CODE}-{record_id}"
CHANNEL_CODE: "Security" -> "SEC", "Microsoft-Windows-Sysmon/Operational" -> "SYS"
S02-SEC-43584   S02-SYS-25891   S01-SEC-31213331
regex: ^(?P<scenario>[A-Za-z0-9_-]{1,80})-(?P<code>SEC|SYS)-(?P<record>[1-9][0-9]*)$
```

* **Parsed from the right**, because a scenario ID may itself contain hyphens (M3's fixtures use
  `SYN-A`). `SYN-A-SEC-1` resolves to scenario `SYN-A`, and a scenario that itself contains `-SEC-`
  still parses, because the record and channel codes are taken from the end.
  Tests: `test_ids.py::test_scenario_with_hyphens_parses_from_the_right`,
  `::test_scenario_that_contains_sec_parses_from_the_right`.
* **Stable across re-runs**: the record part is the original `EventRecordID`, unmodified; nothing
  is renumbered, and the ID is recomputed and re-checked by a schema validator on every event.
  Tests: `test_ids.py::test_round_trip`, `test_schema.py::test_evidence_id_must_match_the_scope`.
* **Collisions cannot key anything.** Your three examples reproduce exactly, and the same record
  number in S02 and S03 resolves to two different events, never to one:
  `S02-SEC-43584` = 4624 `2026-09-21T02:05:30.0430374Z`, `S03-SEC-43584` = 4688 `dllhost.exe`
  `2026-09-21T02:25:15.6704553Z`. Tests:
  `test_query_real.py::test_the_colliding_record_id_resolves_to_two_different_events`,
  `test_normalise.py::test_record_ids_collide_but_evidence_ids_do_not`,
  `test_ids.py::test_record_ids_collide_across_scenarios_but_ids_do_not`.
* **It equals M3's `evidence_id_for(scenario, record)`** for Security events, which is what makes
  the ID usable on both sides of the M3 boundary. Test:
  `test_ids.py::test_matches_m3_evidence_id_for_security_events`.
* A malformed ID raises from the parser and is reported as `invalid_id` by the query API rather
  than being coerced. Tests: `test_ids.py::test_malformed_ids_are_rejected`,
  `test_query.py::test_lookup_distinguishes_not_found_from_invalid_id`.

The full format, and why the scenario prefix is mandatory, is in
[`M2_EVENT_SCHEMA.md`](M2_EVENT_SCHEMA.md).

## Item 2 — 100 ns precision: accepted, and your three measurements reproduce

`timestamp_ticks` is the raw 64-bit FILETIME-derived tick count (100 ns units) and is converted with
**integer arithmetic only**: no `datetime`, no `float`, no `time` anywhere on the tick path, and
`timestamp_utc` is always the canonical `YYYY-MM-DDTHH:MM:SS.fffffffZ` string (7 fractional digits,
`Z`, UTC). Both fields travel on every event and both are re-checked against each other by a schema
validator, so a truncated rendering cannot be stored. `python-evtx` renders `SystemTime` with only 6
fractional digits, so the reader takes the raw FILETIME from the record's binary XML substitution
values instead of the rendered string.

We re-ran your measurement over the normalised S01 corpus. All three of your numbers hold, at
`2022-08-31T17:47:04Z`:

| Your claim | Reproduced |
|---|---|
| closest pair 214 µs apart | `S01-SYS-35811744` (`17:47:04.8513339`) → `S01-SYS-35811745` (`17:47:04.8515477`) = **2138 ticks = 213.8 µs**, both Sysmon 11 for `ntdsutil.exe` |
| Security and Sysmon view of one launch 1.06 ms apart | `S01-SEC-31213331` (Security 4688) → `S01-SYS-35811738` (Sysmon 1) = **10567 ticks = 1.0567 ms**, both `C:\Windows\System32\ntdsutil.exe`, both PID `0x18bc` = 6332 |
| millisecond truncation would tie them | truncating to ms gives both Sysmon 11 records `.851` and both launch records `.789` / `.788` |

Tests that pin this permanently: `test_timeutil.py::test_214_microsecond_gap_stays_distinct_and_ordered`,
`::test_millisecond_truncation_would_tie_the_burst_pair`, `::test_one_tick_apart_stays_distinct`,
`::test_round_trip_through_iso`, `::test_renders_exactly_seven_fractional_digits`,
`test_schema.py::test_timestamp_must_be_canonical_seven_digit_utc`, and the real-anchor tests
`test_normalise.py::test_real_security_anchors_through_the_full_normaliser`,
`test_query_real.py::test_every_public_anchor_resolves_through_the_query_api`.

Two related facts you may want for M5/M6 ordering work:

* **Equal ticks are real.** The corpus contains records that share a tick exactly across channels —
  `S01-SEC-31213367` (Security 4799) and `S01-SYS-35811762` (Sysmon 10) are both
  `2022-08-31T17:47:04.9583823Z`. Ordering is therefore `(timestamp_ticks, evidence_id)` ascending,
  the same order on every run; equal ticks do **not** imply precedence. Test:
  `test_corpus.py::test_event_sort_key_is_ticks_then_evidence_id`,
  `test_query.py::test_equal_ticks_are_ordered_by_evidence_id_and_queries_repeat`.
* Your "five events spanning 108 ms" is the one figure we could not re-derive exactly: the second
  as a whole holds 152 records, and the five-event group your filter selected is not reconstructible
  from the note alone. The sub-millisecond pairs above — the part that matters for ordering — are
  reproduced, and the storage keeps every digit.

## Item 3 — query API semantics: accepted, each point explicitly

| Your requirement | Behaviour | Test |
|---|---|---|
| Unknown `evidence_id` returns a **defined not-found result**, distinguishable from a real event with empty fields | `lookup()` returns `status="found" \| "not_found" \| "invalid_id"`. `not_found` carries no event, so it cannot be confused with a found event whose `user`/`host` is `""` | `test_query.py::test_lookup_distinguishes_not_found_from_invalid_id`, `::test_a_found_event_with_empty_fields_is_not_a_not_found` |
| **Never** fuzzy-match or return a nearest neighbour | exact dict lookup only; no case folding, no prefixes, no "did you mean" | `test_query.py::test_lookup_never_returns_a_nearby_event` |
| **Deterministic ordering** | always `(timestamp_ticks, evidence_id)` ascending; repeated queries return identical lists | `test_query.py::test_equal_ticks_are_ordered_by_evidence_id_and_queries_repeat`, `test_query_real.py::test_a_real_query_is_ordered_repeatable_and_honest_about_truncation` |
| **Read-only** | frozen models; every returned event is a detached copy, so no call can mutate the store | `test_query.py::test_a_returned_event_cannot_be_mutated`, `::test_mutating_a_returned_event_data_does_not_reach_the_store` |
| **Bounded time-range filters document inclusive/exclusive boundaries** | UTC `[start, end)`: start inclusive, end exclusive — in the docstrings, `M2_QUERY_API.md` and the CLI help | `test_query.py::test_start_is_inclusive_and_end_is_exclusive` |

Two additions that matter for a verification path: an oversized window or limit is **rejected with
an error, never silently clamped**, and a result that stopped early reports `truncated=True` with the
true `total_matched` (`test_query.py::test_an_oversized_window_is_rejected_not_clamped`,
`::test_truncated_is_reported_with_the_true_total`). Filters are exact, case-sensitive equality;
`None` means "no filter" and `""` matches a real empty value only
(`test_query.py::test_filters_are_exact_and_case_sensitive`, `::test_none_means_no_filter_and_an_empty_collection_matches_nothing`).

## Item 4 — required fields: accepted

Every field you list is on the frozen `NormalisedEvent`, alongside the rest of the contract
(`m2-event-v1`; field-by-field detail in [`M2_EVENT_SCHEMA.md`](M2_EVENT_SCHEMA.md)):

| Your ask | Field | Notes |
|---|---|---|
| `scenario_id` explicit | `scenario_id` | carried on the event, never inferred from a path at query time; a corpus file holding an event of another scenario is rejected at load |
| `channel` | `channel` | closed two-value set (`Security`, `Microsoft-Windows-Sysmon/Operational`), cross-checked against `source_type` |
| `record_id` | `record_id` | original `EventRecordID`, unmodified, positive int |
| `source_event_id` | `source_event_id` | the Windows Event ID (4624, 4688, Sysmon 1, 11, …) |
| raw reference | `raw_reference`, `raw_xml`, `source_sha256` | `evtx://datasets/S02/raw/Security.evtx#EventRecordID=43584`, the original record XML, and the manifest SHA-256 of the source file — enough to re-derive the record and to prove you re-derived the same bytes |

Tests: `test_normalise.py::test_raw_reference_format`, `test_schema.py::test_valid_security_event`,
`::test_valid_sysmon_event`, `::test_raw_reference_and_raw_xml_cannot_be_empty`,
`::test_event_data_values_must_be_strings`, `test_corpus.py::test_manifest_records_the_schema_version_and_source_digests`.
`event_data` keeps **every** original `EventData` field with its value verbatim: no dropping, no
renaming, no case folding, no domain stripping. A field the source does not carry becomes `None`
(or stays `""` if the source carried it empty) plus a `parse_warnings` entry — a record is never
dropped for a missing optional field
(`test_normalise.py::test_missing_user_field_gives_none_and_a_warning`,
`::test_empty_user_field_is_kept_as_an_empty_string_without_a_warning`).

One property worth knowing on your side: Security and Sysmon spell the same account differently —
the S01 pair above is `administrator` (Security `TargetUserName`) and `ATTACKRANGE\Administrator`
(Sysmon `User`). M2 preserves both verbatim rather than normalising them, so a verification path
that compares accounts across channels should treat the domain prefix as a real difference, not an
M2 defect. This is also recorded as a known limitation in [`../m2/README.md`](../m2/README.md).

## Item 5 — detection metric definitions: pending the joint call

Accepted as a joint decision, not an M2 one. M2 never locates, requests or derives a label; the code
in `m2/metrics.py` is arithmetic over whatever labels M1/M6 produce and defines nothing itself.

* The proposal — the unit (one `evidence_id`), the positive ("an event cited by a malicious
  ground-truth stage"), TP/FP/FN as set operations, "a window detection counts only its trigger
  IDs", the excluded category, the label-file format and the open questions — is
  [`M2_DETECTION_METRICS_PROPOSAL.md`](M2_DETECTION_METRICS_PROPOSAL.md), **DRAFT — not agreed**.
* Both corpus properties in your note are reflected in it: the operator/scaffolding events outside
  the declared window (identifiable through `in_scenario_window`, itself derived from the neutral
  scenario metadata) and the one Security 1102 log clear per lab export, which `R-LOG-01` fires on
  in every scenario. M2 proposes labelling both `excluded` and **reporting them separately**
  (`flagged_excluded` / `unflagged_excluded`) rather than hiding them.
* `python -m m2 score` is implemented and tested against synthetic labels only. No metric computed
  over the MAIR scenarios exists anywhere in the repository, and task T4.3 stays BLOCKED until the
  definitions are agreed **and** a labels file path is provided.

Ready for the call: M2 brings the code, the label-file format it can read, and the questions.

## Item 6 — manifest schema: handled, no change needed on your side

Both shapes are supported explicitly rather than inferred, and the difference never reaches a
consumer: `load_scenario()` returns one `ScenarioInfo` model for either shape.

* **S01 shape**: `schema_version`, `generated_at_utc`, `file_count`, `relative_path`,
  `source_channel`, with `capture_start_utc`/`capture_end_utc` in the scenario metadata.
* **S02/S03 shape**: `collection_time_utc`, `collection_host`, `source`, `channel`, with
  `scenario_start_utc`/`scenario_end_utc`.
* Every source file's SHA-256 is verified against the manifest before parsing, and a Git-LFS pointer
  file is detected and reported as a missing dataset rather than parsed. An unrecognised or mixed
  shape raises a clear error instead of guessing.

Tests: `test_manifest.py::test_loads_the_s01_shape`, `::test_loads_the_lab_shape_and_resolves_raw_paths`,
`::test_unknown_manifest_shape_raises`, `::test_mixed_manifest_shape_raises`,
`::test_hash_mismatch_raises`, `::test_lfs_pointer_is_reported_as_such`, `::test_two_window_field_pairs_raise`,
`::test_real_scenarios_load_and_verify`.

The M1 alignment is still welcome — one shape would be simpler — but it is not blocking: M2 already
reads both, and the window fields feed `in_scenario_window` for the metrics question in item 5.

## Verifying this yourself

```powershell
.\.venv\Scripts\python.exe -m pytest -q m2/tests --basetemp .test-tmp
.\.venv\Scripts\python.exe -m m2 normalise --datasets datasets --out out/corpus
.\.venv\Scripts\python.exe -m m2 lookup S02-SEC-43584     # 4624 @ 02:05:30.0430374Z
.\.venv\Scripts\python.exe -m m2 lookup S03-SEC-43584     # 4688 @ 02:25:15.6704553Z
```

The EVTX exports must be present (not LFS pointers); where they are absent the real-data tests skip
with a reason instead of failing, so CI stays green without them.

## What M2 will not do

* Read the answer key, the runbook or the private labels. The baseline was designed blind and stays
  blind; the scoring code accepts labels, it never finds them.
* Adjust a threshold or a rule to move a metric. Thresholds are frozen constants; a change is a
  versioned rule change recorded in [`M2_DETECTION_RULES.md`](M2_DETECTION_RULES.md).
* Report any precision, recall or F1 for the real scenarios before item 5 is agreed.
