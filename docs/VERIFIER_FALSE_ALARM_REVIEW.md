# Verifier false-alarm review

Owner: Evidence Verification & Evaluation. Reviewed 2026-10-18, after the first scored run.

The scored run's full-MAIR configuration passed 17 claims to the verifier. The deterministic checks confirmed all
17. The model layer then lowered **5** of them to `partially_supported`. This review checks each of the 5 against
the cited records themselves, without reference to the answer key, and records what went wrong.

**Result: all 5 downgrades were false alarms.** In every case the lowered assertion is stated by, or follows
directly from, the records the model was shown. The model layer caught no unsupported claim in this run.

## The five claims

| # | Claim type | Assertion the model called "not stated" | What the cited records show |
|---|---|---|---|
| 1 | discovery commands | the process ran "multiple times, each time with PowerShell as the parent" | three executions of the same binary, each record naming PowerShell as the parent, under both the domain-qualified and the plain account form |
| 2 | failed logons then success | five failures "within 30 seconds" | the failures span 14.6 s and the success follows at 19.0 s from the first record; the duration is arithmetic on the records' timestamps |
| 3 | script written to a temp folder | the whole compound sentence (account, folder, host, PowerShell script) | two file-creation records, each naming the account, the PowerShell image and a path under that account's Temp folder |
| 4 | explicit-credential logons | "using accounts A, B and C between 02:24:57 and 02:25:13" | three records, one target account each, with exactly those accounts and a time span of 15.6 s |
| 5 | script files written | "two script files in a user-writable directory" | two file-creation records under the account's profile Temp folder; "two" is a count of records, "user-writable" is read from the path |

## Causes

1. **Derived facts.** Counts ("multiple", "two"), durations ("within 30 seconds"), and characterisations of a path
   ("user-writable") follow from the records by arithmetic or reading, but no record *states* them. The v2
   grounding rule asked for a quotable statement, so it penalised assertions that are true only by inference
   (cases 1, 2 and 5).
2. **Compound sentences and lists judged as one lump.** In cases 3 and 4 the model marked a whole multi-part
   assertion "not stated" even though each part is stated. The prompt asked for atomic assertions but did not forbid
   marking a compound one whole.

Neither is a defect in the deterministic checks, in the grounding rule's code, or in what the model was shown: for
case 3 the supporting records were present in the prompt, and the model still marked the sentence not stated.

## Why the benchmark did not catch it

The synthetic benchmark used to choose prompt v2 had 6 faithful claims, none resting on a derived fact, and 8
embellished ones. A held-out set written afterwards with six derived-fact faithful claims produced no false alarm
under v2 either (0 of 6). The synthetic claims are short and their records are clean, whereas the real claims
carry more records and longer values, and that is where the model failed. **Synthetic cases cannot validate a
fix for this failure; only real claims can.** That limits what any revision can claim.

## What this does and does not change

* The scored results are unchanged and remain the primary result. A lowered verdict in them is an audit signal, not
  a detected error (protocol section 11).
* A revised prompt (v3) was written to address both causes. Its measured effect is reported in protocol
  Amendment 3 as a labelled post-hoc re-run beside the scored one, never in its place, and it is opt-in so the
  scored configuration stays reproducible byte for byte.
* The deterministic verdicts are unaffected: all 17 claims were confirmed by code and none was rejected.

## Addendum: the post-hoc revision and a third cause

Prompt v3 was written for causes 1 and 2 and applied to the saved claims as a labelled post-hoc re-run (protocol
Amendment 3). It cleared four of the five false alarms. It lowered three claims, and **all three were again supported
by the records**:

* One was the same compound sentence from case 4, marked not stated as a whole again.
* One was an assertion the model invented itself, that a plain account name "is the same as" its domain-qualified
  form. The claim never made it.
* One, "using local credentials", is stated by the records (`TargetServerName` and `TargetInfo` are `localhost`), but
  the model **was never shown those two fields**.

**Cause 3: a field list that omits fields claims rest on.** The verifier shows the model a fixed list of record
fields. It omits, for example, the target server and target info of a logon. A claim can state
something only those fields establish, and the model then cannot find it. This is a defect in the verifier, not in
the model, and it affects v2 and v3 alike. It is not fixed here: correcting it would be a second revision evaluated on
the same 17 claims.

Net: no revision has yet been shown to catch a real unsupported claim on real data. The model layer's downgrades
remain audit signals only.

