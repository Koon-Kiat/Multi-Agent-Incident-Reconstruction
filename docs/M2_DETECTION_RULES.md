# M2 Detection Rules and Baseline Run

Owner: M2 (Data Processing & Detection). Status: implemented (`m2/detection/schema.py`,
`m2/detection/rules.py`, `m2/detection/engine.py`, `m2/__main__.py`).
Companion documents: [`M2_EVENT_SCHEMA.md`](M2_EVENT_SCHEMA.md) for the events the rules read,
[`M2_QUERY_API.md`](M2_QUERY_API.md) for the query layer underneath them.

This is the **conventional (non-LLM) detection baseline**: fixed, readable rules over the
normalised corpus, plus the counts they produced on the MAIR exports. There is no machine
learning, no anomaly scoring, no LLM call and no automatic response here.

The baseline is **not scored** in this document. There are no labels, no precision, recall or
F1, and no statement about which detections are correct. Metric definitions are a joint
M2/M1/M6 decision; M2's proposal is `docs/M2_DETECTION_METRICS_PROPOSAL.md` (DRAFT — not agreed,
and the baseline must not be scored until it is). The scoring code and the label-file format are
implemented and tested (`m2/metrics.py`), but they are arithmetic over whatever labels are agreed,
not a definition of their own.

## Contents

* [Design rules that were fixed before the first run](#design-rules-that-were-fixed-before-the-first-run)
* [Detection artefacts](#detection-artefacts)
* [The rules](#the-rules)
* [Not covered](#not-covered)
* [Baseline run](#baseline-run)
* [Reproducing the baseline](#reproducing-the-baseline)
* [Change control](#change-control)

## Design rules that were fixed before the first run

The rules were designed **blind**: from generic Windows logging and MITRE ATT&CK knowledge, not
from the answer key, the runbook or the scenario labels. Every threshold and vocabulary is a
named constant in `m2/detection/rules.py`, declared and committed *before* the engine was ever
run over real data. They were not tuned after seeing the output below, and they are not to be
tuned now: if a value turns out to be wrong, that is a recorded decision (a STUCK entry to the
planner), not a quiet edit.

| Constant | Value | Used by | Why this value |
|---|---|---|---|
| `FAILED_LOGON_MIN_EVENTS` | 3 | R-AUTH-01, R-AUTH-02 | three failed logons for one account is a burst, not a typo |
| `FAILED_LOGON_WINDOW_SECONDS` | 300 | R-AUTH-01, R-AUTH-02 | five minutes covers an interactive retry run |
| `DISCOVERY_MIN_BINARIES` | 3 | R-EXEC-01 | three *distinct* discovery tools is enumeration rather than routine admin |
| `DISCOVERY_WINDOW_SECONDS` | 120 | R-EXEC-01 | two minutes for one enumeration burst |
| `DISCOVERY_BINARIES` | 12 names | R-EXEC-01 | built-in Windows discovery tools (T1033/T1082/T1016) |
| `DISCOVERY_TECHNIQUES` | 12 mappings | R-EXEC-01 | the ATT&CK technique each discovery binary is attributed to (see below) |
| `SUSPICIOUS_PARENT_IMAGES` | 9 names | R-EXEC-03 | document, browser and WMI hosts that should not spawn a shell |
| `SHELL_IMAGES` | 7 names | R-EXEC-03 | shells, script engines and proxy execution binaries |
| `SUSPICIOUS_PARENT_TECHNIQUE` | `T1204` | R-EXEC-03 | the artefact's technique field: user execution |
| `SUSPICIOUS_PARENT_SECONDARY_TECHNIQUE` | `T1059` | R-EXEC-03 | the spawned interpreter, named in the rationale |
| `ENCODED_COMMAND_PATTERNS` | 5 patterns | R-EXEC-02 | encoded, hidden-window and downloader PowerShell markers |
| `POWERSHELL_COMMAND_MARKERS` | `powershell`, `pwsh` | R-EXEC-02 | the shell names `POWERSHELL_EXECUTABLES` derives `powershell.exe`/`pwsh.exe` from |
| `POWERSHELL_EXECUTABLES` | `powershell.exe`, `pwsh.exe` | R-EXEC-02 | the process image basename or a whole command-line token must be one of these (B6: no substring match) |
| `LSASS_ACCESS_MASKS` | 7 masks | R-CRED-01 | documented `PROCESS_VM_READ` / `ALL_ACCESS` combinations |
| `FILE_DROP_EXTENSIONS` | 6 extensions | R-FILE-01 | executable and script payload types |
| `FILE_DROP_USER_APP_DATA_MARKERS` | 2 path segments | R-FILE-01 | `\users\` **and** `\appdata\` must both appear, i.e. `\Users\<x>\AppData\` |
| `FILE_DROP_LOCATION_MARKERS` | 3 locations | R-FILE-01 | `\Temp\`, `\Downloads\`, `\ProgramData\`; any one is enough |
| `RUN_KEY_MARKERS` | 2 key paths | R-PERSIST-03 | `Run` / `RunOnce` autostart keys |

`DISCOVERY_TECHNIQUES` in full — every detection R-EXEC-01 emits is tagged with the technique of
the binary it reports:

| Binary | ATT&CK | Binary | ATT&CK |
|---|---|---|---|
| `whoami`, `quser`, `qwinsta` | `T1033` System Owner/User Discovery | `ipconfig`, `arp`, `route` | `T1016` System Network Configuration Discovery |
| `systeminfo` | `T1082` System Information Discovery | `net`, `net1` | `T1135` Network Share Discovery |
| `tasklist` | `T1057` Process Discovery | `nltest` | `T1482` Domain Trust Discovery |
| `dsquery` | `T1087.002` Domain Account Discovery | | |

The plan named `T1033`/`T1082`/`T1016` for this rule; the other four are the standard ATT&CK
techniques for the remaining binaries, mapped rather than mislabelled. A burst covers several
binaries and therefore several techniques: its `attack_technique` field carries the technique of
its **first trigger**, and its `rationale` names every technique the burst covers. Single hits
carry their own binary's technique.

The exact values travel with every run: each `DetectionRun` records its rules as
`{rule_id, version, params}`, so a stored run states the thresholds it used even if the source
changes later.

## Detection artefacts

`python -m m2 detect` writes, under `--out`:

```
<out>/<scenario>.json   one DetectionRun per scenario, including zero-detection scenarios
<out>/summary.json      per-scenario, per-rule counts
```

`--out` is a directory `detect` owns, but only for the artefacts it writes itself: after writing
this run, it removes a direct child only when **both** hold — the name is `<scenario_id>.json` or
`summary.json`, and the contents carry the M2 schema marker (`schema_version` `m2-detect-v1`, with
a matching `scenario_id` in a scenario file, or the `detection-summary` marker in the summary). A
run left over from an earlier corpus revision is removed for that reason, because `m2 score` or
anything that globs the directory would otherwise read it as current. Everything else is left
untouched: a `manifest.json`, a `package.json`, a foreign `S02.json` that lacks the marker, or a
malformed file all survive. Nothing outside `--out`, and no subdirectory, is touched. `detect`
refuses an `--out` that resolves inside a `datasets/` or `ground_truth/` tree (any path component,
case-insensitive) or that is the corpus directory itself, and exits `2` without writing.

Before it writes, `detect` also checks every name it is about to use: if a file already exists
there and does **not** carry the M2 marker, it is a foreign file rather than a stale run of ours,
so the whole run exits `1` and writes nothing — not even `summary.json`. Reserving the scenario id
`summary` (case-insensitively, at corpus time and again at detect time) is the other half of the
same guarantee: a scenario can never claim the summary's name.

```python
from m2.detection.engine import DetectionEngine, write_detections

write_detections("out/corpus", "out/detections")   # writes the files, returns the summary
```

A `Detection` is a **finding, not a conclusion**:

| Field | Meaning |
|---|---|
| `detection_id` | `<scenario>-<rule_id>-<closing trigger evidence_id>` — deterministic; the **closing** trigger is the last of the detection's triggers in `(timestamp_ticks, evidence_id)` order |
| `rule_id`, `rule_version` | which rule fired and which revision of it |
| `scenario_id` | the scenario the triggers belong to |
| `trigger_evidence_ids` | every event that caused the detection, in `(timestamp_ticks, evidence_id)` order |
| `window_start_utc`, `window_end_utc` | the **closed** span `[start, end]` of the triggers, 7 fractional digits |
| `attack_technique` | the ATT&CK technique of the binary that ran (R-EXEC-01), the primary technique of a two-technique rule (R-EXEC-03), or the rule's primary, or `null` |
| `severity` | `low` / `medium` / `high`, fixed in the rule definition |
| `rationale` | one line saying what matched and with which thresholds |

`window_start_utc`/`window_end_utc` are inclusive at both ends — they describe the evidence, not
a query bound. Because the query API is `[start, end)` (see `M2_QUERY_API.md`), reading a
detection's own events back goes through
`store.query(scenario_id, window_start_utc, window_end_utc + 1 tick)`, or through the trigger
IDs, which are exact. A single-event detection has `window_start_utc == window_end_utc`.

Every rule **partitions** the events it fires on, except R-AUTH-01: it is anchored on each
successful logon (T3.2), so two successes inside one 300 s span confirm the *same* failures and
produce two detections that share them. That is why `detection_id` names the detection's
**closing** trigger rather than its first — a rule T3.2's amendment ratifies, keeping the
`schema_version` at `m2-detect-v1`. The closing trigger is the success for R-AUTH-01, the last
failure of a burst for R-AUTH-02 and the last binary of a burst for R-EXEC-01, and it identifies
the detection uniquely even when trigger sets overlap. Every `detection_id` in a run is unique —
the artefact and the engine both fail closed if one ever is not — and R-AUTH-01 and R-AUTH-02
never share a trigger. `severity` is the rule's coarse signal strength; it is not a verdict, a
probability or a priority.

`triggers_for(scenario_id)` returns a scenario's detections ordered by
`(window_start_utc, detection_id)`, for a consumer that wants to route windows to M3/M4 without
reading the files. `DetectionEngine.run(scenario_id)` returns the full `DetectionRun`.

**Determinism.** Two runs over the same corpus write byte-identical files: sorted keys, `\n`
line endings, no "now" timestamp anywhere in the artefacts. The corpus revision is recorded as
the SHA-256 of `corpus_manifest.json`.

## The rules

Twelve rules. `params` are the exact recorded values. Case is folded **inside the rules** — a
basename, a registry key or a command line is a heuristic, which is why the query API stays
exact and case-sensitive.

| ID | Ver. | Sev. | ATT&CK | Logic | Benign lookalikes / known false positives |
|---|---|---|---|---|---|
| R-AUTH-01 | 4 | high | T1110 | anchored on **each success**: for every 4624 `S` of a `(user, host)` group, the 4625s of that group in `[t(S) - 300 s, t(S))`; when there are ≥3, one detection with `F(S)` followed by `S` as triggers and `[min t(F(S)), t(S)]` as its window. Two close successes can confirm the same failures and produce two overlapping detections | a user mistyping a password three times and then succeeding; a stale-credential service account retrying before a good logon; the attempts a parallel brute-force tool logs *after* the one that succeeded, while the earlier ones still confirm it |
| R-AUTH-02 | 5 | medium | T1110 | anchored on the **uncovered failure burst**: the failures that are *not* a trigger of any R-AUTH-01 detection of the same `(user, host)`. A burst starts at each uncovered failure `t_i` and covers the uncovered failures in `[t_i, t_i + 300 s)`; ≥3 of them qualify, and overlapping qualifying bursts merge into one detection holding every uncovered failure of the merged segment. The rationale names the merged segment's own span as `window_span_seconds`, which can exceed 300 s when bursts chain | the same retry patterns with no success; password spraying aimed at one account; a burst whose only nearby success confirms fewer than three failures, so R-AUTH-01 cannot use it |
| R-AUTH-03 | 1 | low | T1078 | every Security 4648 (explicit-credential logon) | `runas`, admin tooling, backup and deployment software using alternate credentials — routine in admin workflows, hence low |
| R-CRED-01 | 1 | high | T1003.001 | Sysmon 10 where the target image stem is `lsass` and `GrantedAccess` is one of 7 masks (`0x1010`, `0x1410`, `0x1418`, `0x1438`, `0x143a`, `0x1f0fff`, `0x1fffff`) | monitoring/EDR/backup agents that legitimately read `lsass`; the mask is what was *requested*, not what was granted |
| R-EXEC-01 | 2 | medium (burst) / low (single) | the binary's own technique (see the map above) | ≥3 distinct discovery binaries by one account inside **any** 120 s window is one windowed detection; every matching event outside such a window is its own low detection | routine administration and troubleshooting running `whoami`/`net`/`ipconfig`; installers and scripts that call several discovery tools in a row |
| R-EXEC-02 | 2 | high | T1059.001 | Security 4688 or Sysmon 1 that is a PowerShell process — its own image basename is `powershell.exe`/`pwsh.exe`, or a whitespace/quote-delimited `CommandLine` token's basename is — **and** the command line matches ≥1 of: `-enc`/`-EncodedCommand` token, `FromBase64String`, `-w`/`-WindowStyle hidden`, `IEX`/`Invoke-Expression`, `DownloadString` | management scripts that `-enc` a legitimate payload; modules that use `IEX` internally; scheduled tasks that run a hidden window. `-Encoding` is deliberately not matched. A binary whose *name* merely contains `powershell`/`pwsh` (`notpowershell.exe`, `pwshish`) is not PowerShell and never matches (B6) |
| R-EXEC-03 | 2 | high | T1204 (field) / T1059 (rationale) | parent image stem in {winword, excel, powerpnt, outlook, msedge, chrome, firefox, wmiprvse, mshta} spawning a child stem in {cmd, powershell, pwsh, wscript, cscript, rundll32, regsvr32} | management agents that run scripts through `WmiPrvSE.exe` (SCCM/Intune-style); legacy Office add-ins that shell out |
| R-FILE-01 | 1 | medium | T1105 | Sysmon 11 creating a file whose name ends in `.exe|.dll|.ps1|.bat|.vbs|.js` under `\Users\*\AppData\`, `\Temp\`, `\Downloads\` or `\ProgramData\` | installers and updaters that stage binaries in `%TEMP%`/`%APPDATA%`; browser and print-driver updates — deliberately noisy, hence medium |
| R-LOG-01 | 1 | high | T1070.001 | every Security 1102 (audit log cleared) | an operator or log-rotation script legitimately clearing the log — see the baseline note below |
| R-PERSIST-01 | 1 | medium | T1543.003 | every Security 4697 (service installed) | software installers creating services |
| R-PERSIST-02 | 1 | medium | T1053.005 | every Security 4698 (scheduled task created) | provisioning scripts and updaters creating tasks |
| R-PERSIST-03 | 1 | medium | T1547.001 | every Sysmon 13 whose `TargetObject` names `\CurrentVersion\Run` or `\CurrentVersion\RunOnce` (the key or a value below it) | installers and users adding autostart entries |

### How the failed-logon rules decide (version 5)

The two rules are anchored, not scanned: neither decision depends on where a grouping window
happened to start. R-AUTH-01 is evaluated first and R-AUTH-02 is defined on the failures
R-AUTH-01 did **not** claim (task_plan.md T3.2, "planner amendment A1"), so the two rules are
disjoint: no failure is a trigger of both. Both evaluate one `(user, host)` group at a time, over
that group's events in `(timestamp_ticks, evidence_id)` order, with `W` = 300 s.

**R-AUTH-01 is anchored on each success.** For every 4624 `S` of the group, `F(S)` is the 4625s
of that group with `t(S) - W ≤ t(F) < t(S)`: the failures inside the W seconds that end at `S`.
The bound is half-open at both ends, so a failure at exactly `t(S) - W` counts and a failure
logged in the same 100 ns tick as `S` does not. When `|F(S)| ≥ 3`, `S` yields one detection whose
triggers are `F(S)` followed by `S` and whose window is `[min t(F(S)), t(S)]`. Failures after `S`
are not part of it. Two successes close together confirm the same failures and produce two
detections that overlap — T3.2 allows that, and each is named after its own success, so
`detection_id` stays unique.

**R-AUTH-02 is anchored on the uncovered failure burst.** The group's **uncovered** failures are
those that are not a trigger of any R-AUTH-01 detection in that group. A burst starts at each
uncovered failure `t_i` and covers the uncovered failures in `[t_i, t_i + W)` — the anchor is
included, a failure exactly W later is not. A burst with at least three of them qualifies, and
qualifying bursts that overlap merge into one detection holding every uncovered failure of the
merged segment, in `(timestamp_ticks, evidence_id)` order. The rationale therefore names the
property directly — *"N failed logons for … (window_span_seconds=S), not followed by a qualifying
successful logon (R-AUTH-01)"* — and the claim is true by construction: a failure a success could
confirm was already claimed by R-AUTH-01.

`window_span_seconds` is the merged segment's **own** span, `last trigger − first trigger`, exact
to the 100 ns tick and always rendered with 7 fractional digits. Chained bursts merge, so it can
exceed the 300 s window: six uncovered failures every 100 s from 0 s to 500 s are one detection
with `window_span_seconds=500.0000000`. Naming it keeps the merged span visible to a consumer that
would otherwise infer a single window from the rule's threshold.

The A1 definition replaced the version-4 rule, which reported a burst unless a 4624 of the group
lay in `(first failure, last failure + W]`. That suppression was too strong: a success could veto
a burst it was unable to confirm. Failures at 0, 100 and 200 s with a success at 310 s were
reported by **neither** rule under version 4 — `F(310 s)` holds only two failures, so no
R-AUTH-01, and the 4624 sat inside the burst's `(0 s, 500 s]` span, so no R-AUTH-02. Under version
5 the three failures are uncovered and R-AUTH-02 reports them. The rationale names exactly that
condition, and never claims that no successful logon happened.

A failure and a success logged in the same 100 ns tick are not an ordered pair: R-AUTH-01's
`F(S)` excludes the failure because it is not strictly before `S`, so that failure is uncovered
and R-AUTH-02 judges it on its own. Three such failures are a burst. This is T3.2's accepted
same-tick behaviour and it is pinned by a test rather than special-cased.

Worked examples, all pinned by tests in `m2/tests/test_detection_rules.py`:

| Timeline | R-AUTH-01 | R-AUTH-02 |
|---|---|---|
| failures 0, 10, 20 s; success 30 s | one detection on `{0, 10, 20, 30}` | none — every failure is claimed |
| failures 0, 10, 20 s; success 30 s; failures 40, 50 s (phase-3 F7) | one detection on `{0, 10, 20, 30}` | none — two late failures are not a burst |
| the same with a third late failure at 60 s | one detection on `{0, 10, 20, 30}` | one detection on `{40, 50, 60}` — the failures no success claimed |
| failures every second 0–19 s; success 10 s (parallel brute force) | one detection on `{0…9, 10}` | one detection on `{10…19}` — the in-flight failures, including the one logged in the success's own tick |
| failures 0, 250, 310, 320 s; success 330 s (phase-3 F1/F5) | one detection on `{250, 310, 320, 330}` | none — the stray failure at 0 s is uncovered but alone |
| failures 0, 100, 200, 350, 360 s; success 370 s (phase-3 F5) | one detection on `{100, 200, 350, 360, 370}` | none — the stray failure at 0 s is uncovered but alone |
| failures 0, 100, 200 s; success 310 s (A1) | none — `F(310 s)` holds only 100 and 200 | one detection on `{0, 100, 200}` |
| failures every 100 s, 0–500 s, no success (A2) | none | one detection on `{0, 100, 200, 300, 400, 500}` — overlapping candidates merge, so `window_span_seconds=500.0000000` exceeds W |
| failures 0, 10, 20 s; successes 30 s and 40 s | **two** detections, on `{0,10,20,30}` and `{0,10,20,40}` | none — every failure is claimed |
| failures 0, 10 s on LAB-A, 20 s on LAB-B, success on LAB-A at 30 s (phase-3 F8) | none — LAB-A confirms only two failures | none — LAB-B's lone failure is not a burst |

Two failures closer to the previous definition's boundary are worth stating: the uncovered burst
window is `[t_i, t_i + W)`, so failures at 0, 10 and 300 s form **no** burst (the first failure's
window stops just short of the third, and the middle failure's window holds only two); failures
at 0, 10 and 299 s do. Both are tested.

Version 4 replaced the greedy scan with T3.2's anchors (phase-3 F7); version 3 had confirmed a
burst against the first window a greedy scan accepted, which reported failures at 0, 100, 200,
350 and 360 s with a success at 370 s as R-AUTH-02 on `{0, 100, 200}` — a medium "no success"
finding for an attack that had just succeeded (phase-3 review finding F5).

### How the windowed rule slides (R-EXEC-01)

"What fires must not depend on an earlier event in the same account's history." R-EXEC-01 scans
greedily with a sliding window: a candidate window starts at the first event not yet consumed,
takes every following event within the window length of that anchor, and is kept only when it
meets the rule's condition — at least three *distinct* discovery binaries. A candidate that does
not meet it advances the scan by **one** event, and accepted windows consume their own events,
so windows never overlap.

An earlier, unrelated event can therefore no longer hide a later burst: `whoami` at 0 s and
`net`, `ipconfig`, `systeminfo` at 100, 130 and 140 s is one burst even though the first binary
is 100 s before it. The benign counterpart holds as well: binaries that never share a window are
single hits. Version 1 clustered from the first event of an account's history instead, which
silently suppressed such bursts (phase-3 review finding F1); the thresholds themselves are
unchanged.


User and host grouping uses the normalised `user` and `host` fields exactly as stored; they are
never case-folded or domain-stripped. `None` (a field the source did not carry) forms its own
group and is never merged with `""` or with a real name.

## Not covered

Stated so nobody reads absence of a detection as absence of activity.

* **Channels not in the corpus.** Only `Security` and `Microsoft-Windows-Sysmon/Operational` are
  normalised, and `NormalisedEvent.channel` is a two-value literal. System-channel service
  installs (7045), PowerShell script-block logging (4104), WMI-Activity, Task Scheduler
  operational and Defender/AV channels cannot be detected at all.
* **Security event IDs with no rule.** No rule uses 4672/4703 (privilege use), 4720/4726/4732
  (account manipulation), 4699/4700/4702 (task modification), 5140/5145 (share access),
  5152–5158 (filtering platform), 8222 (shadow copy), 4776 (NTLM validation), or 4634/4647
  (logoff).
* **Tactics with no rule.** No lateral movement, no Kerberos attacks, no DCSync, no C2/beaconing
  or exfiltration heuristics, no timestomping, no shadow-copy deletion, no ransom or
  data-destruction indicators, no persistence beyond Run keys / services / scheduled tasks
  (no Winlogon, IFEO, COM hijack, WMI subscription or startup-folder checks).
* **Sysmon event IDs with no rule.** No 3/22 (network/DNS), 6 (driver load), 7/8 (image load,
  CreateRemoteThread), 9 (raw access), 12 (registry key create), 17/18 (named pipes), 23/24
  (file delete, archive), 25 (process tampering).
* **A failure burst shorter than the threshold.** Two uncovered failures inside a window are
  reported by nothing. That is the threshold doing its job, not a gap: the plan fixes
  `FAILED_LOGON_MIN_EVENTS` at 3. The version-4 gap in which a three-failure burst was reported by
  *neither* failed-logon rule was closed by amendment A1 and is now R-AUTH-02.
* **No statistics, no ML, no LLM, no response.** The baseline is fixed rules only; it never
  scores, classifies or takes action.
* **No scoring.** Whether a detection is correct is a labelled-evaluation question and is not
  answered here (phase 4).

## Baseline run

Produced by:

```powershell
.\.venv\Scripts\python.exe -m m2 normalise --datasets datasets --out out/corpus
.\.venv\Scripts\python.exe -m m2 detect --corpus out/corpus --out out/detections
```

Corpus: 2 700 S01 + 1 930 S02 + 2 031 S03 events, corpus manifest SHA-256
`ebf5f9df82e51e20e737c418f2059a0c3a4abb59f00347f6f2960a6d4c13e968`.

Detections per rule per scenario, with the severity of every detection:

| Rule | Severity | S01 | S02 | S03 |
|---|---|---|---|---|
| R-AUTH-01 | high | 0 | 1 | 0 |
| R-AUTH-02 | medium | 0 | 0 | 0 |
| R-AUTH-03 | low | 0 | 6 | 6 |
| R-CRED-01 | high | 2 | 0 | 0 |
| R-EXEC-01 | low | 6 | 4 | 4 |
| R-EXEC-02 | high | 0 | 0 | 0 |
| R-EXEC-03 | high | 0 | 0 | 0 |
| R-FILE-01 | medium | 0 | 3 | 3 |
| R-LOG-01 | high | 1 | 1 | 1 |
| R-PERSIST-01 | medium | 0 | 0 | 0 |
| R-PERSIST-02 | medium | 0 | 0 | 0 |
| R-PERSIST-03 | medium | 0 | 0 | 0 |
| **total** | | **9** | **15** | **14** |

These counts are **unchanged by every rule change so far** — the version-2 windowing and ATT&CK
fixes, the version-3 failed-logon confirmation fix, the version-4 T3.2 anchors and the version-5
amendment A1 redefinition of R-AUTH-02. That is the point: each is a spec-conformance fix, not a
tuning change. A sliding window can only find *more* qualifying windows than the version-1
clustering did, and this corpus contains none: the largest number of failures for any one
account/host inside any 300 s window is 5 (S02, already detected) and 2 (S03), and the largest
number of *distinct* discovery binaries for one account inside any 120 s window is 1 (S01) and 2
(S02, S03). Version 4 changes nothing either: the only account/host pair that reaches three
failures at all is S02's `mair_user`, whose five 4625s all sit inside the 19 s that the 4624 at
`02:05:30` closes, so `F(4624)` is exactly those five — the same six triggers version 3 reported —
and no success in the corpus has failures after it. **Version 5 also leaves the counts at
9/15/14:** S01 holds no 4625 at all; S03's one account reaches at most two failures inside any
300 s window, below the threshold; and S02's `mair_user` has five, all inside the 19 s that the
4624 closes, so R-AUTH-01 claims every one of them and no uncovered burst exists anywhere in this
corpus. The scenario-file digests below changed because each one records the rules' versions and
`params` — and between versions 3 and 4 because S02's one R-AUTH-01 `detection_id` moved from the
first failure to the success. `summary.json` records only counts, so its digest moved once, in
phase 5, and only because the file gained the `detection-summary` marker described under
[Detection artefacts](#detection-artefacts).

**Phase 6 (B6) also leaves the counts at 9/15/14.** R-EXEC-02 produces no detection on this
corpus, so changing its PowerShell test from a substring to a whole-executable one changes no
detection; only the rule's version moved (`1` → `2`, because the matching logic changed), which
changed the `rules` array recorded in the three scenario files and therefore their digests.
`summary.json` stores only counts, so its digest is unchanged.

38 detections in total. What the run looked like, descriptively:

* **Every R-EXEC-01 detection is a single hit.** No account reached three *distinct* discovery
  binaries inside 120 s anywhere in the corpus, so the medium-severity burst variant never fired.
* **R-EXEC-01's real tags are not all one technique.** With per-binary attribution, the four
  S02 and four S03 single hits split into two `T1033` and two `T1016` detections each (S01 is
  six `T1033`); version 1 tagged all 14 `T1033`, which misdescribed the `ipconfig`-class hits.
* **R-AUTH-01 fired once**, in S02, on a six-trigger burst of five 4625s and one 4624 whose
  window ends at `2026-09-21T02:05:30.0430374Z` — the public `S02-SEC-43584` anchor. Its
  `detection_id` is `S02-R-AUTH-01-S02-SEC-43584`: R-AUTH-01 is anchored on the success, so that
  is the event it is named after. No other account/host pair reached three failures inside five
  minutes, so no failure in this corpus is left uncovered and R-AUTH-02 is **still empty** — not
  because a success suppressed a burst (version 5 never suppresses), but because the failures that
  are uncovered are too few to form one.
* **R-AUTH-03 fired six times in each lab scenario** and never in S01, always as a single low
  detection.
* **R-FILE-01 fired three times in each lab scenario** and never in S01, always medium.
* **R-CRED-01 fired only in S01** (two high detections).
* **R-LOG-01 fired exactly once in every scenario**, including the two lab scenarios. This is the
  runbook's log reset, the corpus property M6's interface note describes. Treating it as
  operator/scaffolding activity (tallied separately rather than counted as a detection) is a
  joint M2/M1/M6 decision, proposed in `docs/M2_DETECTION_METRICS_PROPOSAL.md`; it is
  **not** decided here.
* **Six rules produced no detection at all on this corpus:** R-AUTH-02, R-EXEC-02, R-EXEC-03 and
  the three persistence rules. The corpus holds no Security 4697 or 4698 record, no Sysmon 13
  event whose target object is a Run/RunOnce key, no command line matching the R-EXEC-02
  patterns, and no suspicious parent-to-shell pair. Their synthetic tests cover them.
* **Security and Sysmon views of one action appear as two detections.** For example S02's
  02:05:58 discovery activity yields `S02-SEC-43662` (Security 4688) and `S02-SYS-25814`
  (Sysmon 1) as separate low detections with different evidence IDs. Whether that counts once or
  twice is the first open question in the metrics proposal.

Output digests (SHA-256), for reproducing the run byte for byte:

| File | SHA-256 |
|---|---|
| `S01.json` | `30f11dfc273566b2b5b44960e13a511ac067a7a6ae5ec9c9029581d768c2c114` |
| `S02.json` | `c8a15743010ac43d21ce67142727a4262e80f5ce0b93a714dabb39fc1a01bb85` |
| `S03.json` | `289e4b1690dce2f494e6e94a356535b88f005d41206d954c42efe405b6879af4` |
| `summary.json` | `62c5ce9ebd8291b80efb990c8ec07cab88680340879518796347410e752974fa` |

These are byte-identical across repeated runs, which the real test
`m2/tests/test_detection_real.py::test_two_real_runs_are_byte_identical` checks; the four
SHA-256 values themselves are pinned by
`test_the_declared_output_digests_reproduce_on_the_real_corpus`, which also pins the corpus
manifest digest, and `test_the_declared_baseline_reproduces_on_the_real_corpus` pins the per-rule
counts above. A rule change that alters these files therefore fails a test rather than silently
leaving this document stale.

## Reproducing the baseline

```powershell
.\.venv\Scripts\python.exe -m pytest -q m2/tests --basetemp .test-tmp
.\.venv\Scripts\python.exe -m m2 detect --corpus out/corpus --out out/detections
```

The rule tests are synthetic and run in CI, where the EVTX exports are absent; the real tests
(`test_detection_real.py`) skip with a reason in that case. Nothing needs the answer key.

## Change control

Changing a rule's logic, a threshold constant or a recorded `params` value is a **rule change**:
bump `rule_version`, justify it in the `task_plan.md` progress log, and re-run the baseline. Do
not edit a constant to make a particular detection appear or disappear — that would break the
blind-design rule this baseline was built under. A changed rule changes `detection_id` values
and therefore every downstream artifact, so the metrics phase must be re-run too.

Recorded so far:

| Version | Rule(s) | Change | Reason |
|---|---|---|---|
| 2 | R-AUTH-01, R-AUTH-02, R-EXEC-01 | windowed matching moved from first-event clustering to a greedy sliding window | phase-3 review finding F1: a stray early event suppressed a later burst. Spec conformance, not tuning — no threshold changed and no real count moved |
| 2 | R-EXEC-01 | `attack_technique` is per binary (declared map) instead of the rule-wide `T1033` | phase-3 review finding F2: `systeminfo`/`ipconfig` hits were tagged with the wrong technique |
| 2 | R-EXEC-03 | `attack_technique` is `T1204` (primary), `T1059` named in the rationale and `params` | phase-3 review finding F2: the rule covers both techniques |
| 3 | R-AUTH-01, R-AUTH-02 | the confirmation is part of the sliding predicate: a 4624 must lie inside the burst's own 300 s span at or after its last failure; R-AUTH-02 scans only the failures no confirmed span claimed, and its rationale names the span instead of saying "afterwards" | phase-3 review finding F5: a burst that the same run later confirmed was reported as R-AUTH-02 on an earlier window, with a rationale that contradicted the evidence. Spec conformance, not tuning — no threshold changed and no real count moved |
| 4 | R-AUTH-01, R-AUTH-02 | the scan is replaced by T3.2's anchors: R-AUTH-01 is one detection per success over `F(S) = failures in [t(S) - W, t(S))` (overlapping detections allowed), R-AUTH-02 is one detection per merged segment of qualifying bursts, and a burst qualifies only when no 4624 of the group lies in `(first failure, last failure + W]`. `detection_id` now names the **closing** trigger (the success for R-AUTH-01) because the first trigger is no longer unique | phase-3 review finding F7: a burst followed by a success and then more failures inside the same window produced no R-AUTH-01, and the R-AUTH-02 it produced claimed a "no successful logon" span that contained the success. Spec conformance, not tuning — no threshold changed and no real count moved |
| 5 | R-AUTH-02 | R-AUTH-02 now reports only the **uncovered** failures — those that are not a trigger of any R-AUTH-01 detection of the same `(user, host)`. A burst starts at each uncovered failure `t_i` and covers the uncovered failures in `[t_i, t_i + W)`; ≥3 of them qualify, and overlapping qualifying bursts merge into one segment. The rationale becomes "not followed by a qualifying successful logon (R-AUTH-01)". The rule's description changed with it | task_plan.md T3.2 "Planner amendment A1" (after the phase-3 round-4 planner notes): version 4's suppression window let a success veto a burst it could not confirm, so failures at 0/100/200 s with a success at 310 s were reported by neither rule. Version 5 makes the two rules disjoint and exhaustive. Spec conformance, not tuning — no threshold changed and no real count moved (9/15/14 unchanged; only the version bytes in the scenario files moved) |
| 5 (rationale only, no bump) | R-AUTH-02 | the rationale gained `window_span_seconds=…` — the merged segment's own span, exact to the 100 ns — so a consumer can see that a chained segment may exceed 300 s | task_plan.md T5.0 "Planner amendment A2": additive to the rationale **text only**. No threshold, matching logic, `params`, severity, trigger set, window or `detection_id` changed, so the recorded `params`/version bytes are unchanged and no artefact digest moves. R-AUTH-02 emits no detection on this corpus, so no stored `Detection` differs at all; on another corpus two version-5 runs could differ only in this string, which is why it is recorded here |
| 2 **for R-EXEC-02** (phase 6; its version restarted from 1, every other rule keeps its own version) | R-EXEC-02 | the PowerShell test is now a whole-executable match — the process image basename, or a whitespace/quote-delimited command-line token, must be `powershell.exe`/`pwsh.exe` — instead of "the command line contains `powershell`/`pwsh` as a substring" | phase-6 review finding B6 (`PR #8`): the substring test fired on binaries merely named `notpowershell.exe`/`pwshish`, and the finding requires boundary matching. A matching-logic change, so the version moved per this section; no threshold, pattern, severity, `attack_technique`, `params` or count changed (9/15/14 unchanged). R-EXEC-02 emits nothing on this corpus, so only the recorded version bytes moved, which changed the three scenario digests (not `summary.json`, which stores counts only) |
