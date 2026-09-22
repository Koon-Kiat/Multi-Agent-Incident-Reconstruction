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
M2/M1/M6 decision; the proposal is phase 4's `docs/M2_DETECTION_METRICS_PROPOSAL.md` (not
written yet).

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
| `SUSPICIOUS_PARENT_IMAGES` | 9 names | R-EXEC-03 | document, browser and WMI hosts that should not spawn a shell |
| `SHELL_IMAGES` | 7 names | R-EXEC-03 | shells, script engines and proxy execution binaries |
| `ENCODED_COMMAND_PATTERNS` | 5 patterns | R-EXEC-02 | encoded, hidden-window and downloader PowerShell markers |
| `POWERSHELL_COMMAND_MARKERS` | `powershell`, `pwsh` | R-EXEC-02 | the command line must actually be a PowerShell one |
| `LSASS_ACCESS_MASKS` | 7 masks | R-CRED-01 | documented `PROCESS_VM_READ` / `ALL_ACCESS` combinations |
| `FILE_DROP_EXTENSIONS` | 6 extensions | R-FILE-01 | executable and script payload types |
| `FILE_DROP_LOCATION_MARKERS` | 4 locations | R-FILE-01 | user-writable drop locations |
| `RUN_KEY_MARKERS` | 2 key paths | R-PERSIST-03 | `Run` / `RunOnce` autostart keys |

The exact values travel with every run: each `DetectionRun` records its rules as
`{rule_id, version, params}`, so a stored run states the thresholds it used even if the source
changes later.

## Detection artefacts

`python -m m2 detect` writes, under `--out`:

```
<out>/<scenario>.json   one DetectionRun per scenario, including zero-detection scenarios
<out>/summary.json      per-scenario, per-rule counts
```

```python
from m2.detection.engine import DetectionEngine, write_detections

write_detections("out/corpus", "out/detections")   # writes the files, returns the summary
```

A `Detection` is a **finding, not a conclusion**:

| Field | Meaning |
|---|---|
| `detection_id` | `<scenario>-<rule_id>-<first trigger evidence_id>` — deterministic |
| `rule_id`, `rule_version` | which rule fired and which revision of it |
| `scenario_id` | the scenario the triggers belong to |
| `trigger_evidence_ids` | every event that caused the detection, in `(timestamp_ticks, evidence_id)` order |
| `window_start_utc`, `window_end_utc` | the **closed** span `[start, end]` of the triggers, 7 fractional digits |
| `attack_technique` | the rule's primary ATT&CK technique, or `null` |
| `severity` | `low` / `medium` / `high`, fixed in the rule definition |
| `rationale` | one line saying what matched and with which thresholds |

`window_start_utc`/`window_end_utc` are inclusive at both ends — they describe the evidence, not
a query bound. Because the query API is `[start, end)` (see `M2_QUERY_API.md`), reading a
detection's own events back goes through
`store.query(scenario_id, window_start_utc, window_end_utc + 1 tick)`, or through the trigger
IDs, which are exact. A single-event detection has `window_start_utc == window_end_utc`.

Every rule **partitions** the events it fires on, so two detections of one rule in one scenario
never share a trigger; `detection_id` is therefore unique within a run (the engine fails closed
if it ever is not). `severity` is the rule's coarse signal strength; it is not a verdict, a
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
| R-AUTH-01 | 1 | high | T1110 | ≥3 Security 4625 for one `(user, host)` inside 300 s, then a 4624 for the same `(user, host)` after the last failure and inside the same window | a user mistyping a password three times and then succeeding; a stale-credential service account retrying before a good logon |
| R-AUTH-02 | 1 | medium | T1110 | the same burst with **no** 4624 for that `(user, host)` after the last failure inside the window | the same retry patterns with no success; password spraying aimed at one account |
| R-AUTH-03 | 1 | low | T1078 | every Security 4648 (explicit-credential logon) | `runas`, admin tooling, backup and deployment software using alternate credentials — routine in admin workflows, hence low |
| R-CRED-01 | 1 | high | T1003.001 | Sysmon 10 where the target image stem is `lsass` and `GrantedAccess` is one of 7 masks (`0x1010`, `0x1410`, `0x1418`, `0x1438`, `0x143a`, `0x1f0fff`, `0x1fffff`) | monitoring/EDR/backup agents that legitimately read `lsass`; the mask is what was *requested*, not what was granted |
| R-EXEC-01 | 1 | medium (burst) / low (single) | T1033 | ≥3 distinct discovery binaries by one account inside 120 s is one windowed detection; every other single hit is its own low detection | routine administration and troubleshooting running `whoami`/`net`/`ipconfig`; installers and scripts that call several discovery tools in a row |
| R-EXEC-02 | 1 | high | T1059.001 | Security 4688 or Sysmon 1 whose `CommandLine` mentions `powershell`/`pwsh` **and** matches ≥1 of: `-enc`/`-EncodedCommand` token, `FromBase64String`, `-w`/`-WindowStyle hidden`, `IEX`/`Invoke-Expression`, `DownloadString` | management scripts that `-enc` a legitimate payload; modules that use `IEX` internally; scheduled tasks that run a hidden window. `-Encoding` is deliberately not matched |
| R-EXEC-03 | 1 | high | T1059 | parent image stem in {winword, excel, powerpnt, outlook, msedge, chrome, firefox, wmiprvse, mshta} spawning a child stem in {cmd, powershell, pwsh, wscript, cscript, rundll32, regsvr32} | management agents that run scripts through `WmiPrvSE.exe` (SCCM/Intune-style); legacy Office add-ins that shell out |
| R-FILE-01 | 1 | medium | T1105 | Sysmon 11 creating a file whose name ends in `.exe|.dll|.ps1|.bat|.vbs|.js` under `\Users\*\AppData\`, `\Temp\`, `\Downloads\` or `\ProgramData\` | installers and updaters that stage binaries in `%TEMP%`/`%APPDATA%`; browser and print-driver updates — deliberately noisy, hence medium |
| R-LOG-01 | 1 | high | T1070.001 | every Security 1102 (audit log cleared) | an operator or log-rotation script legitimately clearing the log — see the baseline note below |
| R-PERSIST-01 | 1 | medium | T1543.003 | every Security 4697 (service installed) | software installers creating services |
| R-PERSIST-02 | 1 | medium | T1053.005 | every Security 4698 (scheduled task created) | provisioning scripts and updaters creating tasks |
| R-PERSIST-03 | 1 | medium | T1547.001 | every Sysmon 13 whose `TargetObject` names `\CurrentVersion\Run` or `\CurrentVersion\RunOnce` (the key or a value below it) | installers and users adding autostart entries |

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

38 detections in total. What the run looked like, descriptively:

* **Every R-EXEC-01 detection is a single hit.** No account reached three *distinct* discovery
  binaries inside 120 s anywhere in the corpus, so the medium-severity burst variant never fired.
* **R-AUTH-01 fired once**, in S02, on a six-trigger burst of five 4625s and one 4624 whose
  window ends at `2026-09-21T02:05:30.0430374Z` — the public `S02-SEC-43584` anchor. No other
  account/host pair reached three failures inside five minutes.
* **R-AUTH-03 fired six times in each lab scenario** and never in S01, always as a single low
  detection.
* **R-FILE-01 fired three times in each lab scenario** and never in S01, always medium.
* **R-CRED-01 fired only in S01** (two high detections).
* **R-LOG-01 fired exactly once in every scenario**, including the two lab scenarios. This is the
  runbook's log reset, the corpus property M6's interface note describes. Treating it as
  operator/scaffolding activity (tallied separately rather than counted as a detection) is a
  joint M2/M1/M6 decision, proposed in phase 4's `docs/M2_DETECTION_METRICS_PROPOSAL.md`; it is
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
| `S01.json` | `08381b4bb32a6773d5c6a9fd828510864df439f2676dd388179e201fbd5d381c` |
| `S02.json` | `57402c0901ea97beef05537d6149a41485d2e09e6f3d9df3d1d2db0e20e0b54f` |
| `S03.json` | `b91eeb840375a26855361cc0ffe8e7881cbcea1f55ab30d2276d44d942c6b4e9` |
| `summary.json` | `b5942b87d30123390193257a319838f0482f3d45dde18ed3084c129853bea184` |

These are byte-identical across repeated runs, which the real test
`m2/tests/test_detection_real.py::test_two_real_runs_are_byte_identical` checks, and
`test_the_declared_baseline_reproduces_on_the_real_corpus` pins the per-rule counts above.

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
