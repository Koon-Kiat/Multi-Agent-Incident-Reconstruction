# Semantic review of the real-corpus component claims

Owner: Evidence Verification & Evaluation follow-up. Reviewed 2026-10-20 on `fix/evidence-evaluation-correctness`.

The corrected-code validation (`CORRECTNESS_REMEDIATION.md`, "Remaining items") ran the verifier once on 17
deterministic template claims from the real corpus: 13 confirmed, and four lowered (S01-CLM-02, S02-CLM-03,
S02-CLM-06, S03-CLM-06). This review checks every one of the 17 against its cited records, to establish
whether the four downgrades are justified or false alarms and whether the 13 confirmations hold up.

**Who reviewed.** A **model review**, not a human one: Claude (Anthropic model `claude-opus-5-5`), a different
model from the verifier's `qwen3:8b`. It was **not blind**: the request named the four lowered claims. Each label
and its reasoning are recorded with the cited evidence IDs so any reader can check them against the records. The
four-configuration scorer requires `independent_human_review` and does not accept this review in its place.

## Result

**Of the four downgrades, two are justified and two are false alarms.** Of the 13 confirmations, 12 hold up
and one confirmed a claim that is not fully supported.

| Claim | Verifier | Review | Outcome |
|---|---|---|---|
| S01-CLM-02 discovery commands | partially supported | partially supported | **justified** |
| S02-CLM-03 failed logons then success | unverified | supported | **false alarm** |
| S02-CLM-06 discovery commands | partially supported | partially supported | **justified** |
| S03-CLM-06 payload written | unverified | supported | **false alarm** |
| S03-CLM-04 discovery commands | confirmed | partially supported | **missed** |
| 12 other claims (3 audit log cleared, 5 explicit-credential logon, 1 LSASS access, 3 payload written) | confirmed | supported | correct |

Treating "not fully supported" as the condition to catch, the verifier caught 2 of 3 such claims and 2 of its
4 downgrades were correct. On these 17 claims its lowered/confirmed decision agrees with the review for 14.
**These counts are not an accuracy estimate** (see below). The per-claim labels and notes are in
[`validation/semantic-review-2026-10-20.json`](validation/semantic-review-2026-10-20.json).

## The three "enumeration burst" claims

S01-CLM-02, S02-CLM-06 and S03-CLM-04 share one sentence: "Discovery tooling: an enumeration burst, plus single
hits observed from *start* to *end*." The discovery activity and the time span are supported. The enumeration
burst is not:

* R-EXEC-01 defines an enumeration burst as at least three **distinct** discovery binaries run by one account
  within 120 s (`DETECTION_RULES.md`).
* S01-CLM-02's records show one binary, `whoami.exe`, run three times. S02-CLM-06 and S03-CLM-04 each show two,
  `whoami.exe` and `ipconfig.exe`. Every run is logged once in Security 4688 and once in Sysmon 1.
* The detection engine labelled every one of these detections a single hit "outside any enumeration burst".

So the claims are partially supported. The verifier lowered two of them and confirmed the third, although the
three are the same sentence over the same kind of records.

The sentence comes from the deterministic test narrator (`FakeReconstructionLLM`). It copies the rule's full
description into every claim, even when only single hits occurred. Runs with a real model write their own
claim text. The overstatement is therefore an artefact of these template claims, but it is what the verifier
was asked to judge.

## The two false alarms

* **S02-CLM-03.** Five Security 4625 failures for `MAIR-WIN11-LAB\mair_user` on `MAIR-WIN11-LAB`, from
  02:05:11.010 to 02:05:25.623, are followed by a 4624 success for the same account and host at 02:05:30.043.
  The failures are S02-SEC-43571, -43573, -43575, -43578 and -43580; the success is S02-SEC-43584. Every
  assertion is stated by the records: the burst, the order, the shared account and host, and the span.
* **S03-CLM-06.** Sysmon 11 records S03-SYS-26062 and S03-SYS-26356 show `powershell.exe` writing two `.ps1`
  files under `C:\Users\mair_admin\AppData\Local\Temp`, at exactly the stated start and end. The claim also
  cites records outside that span: the PowerShell start, `.temp`/`.TMP` files under `Recent` and the module
  analysis cache. These are context, not part of what it asserts.

The verifier's per-clause reasons for these two verdicts are in the validation run's local traces, which are
not in the repository. This review therefore does not attribute a cause.

## Judgement calls

* **"Payload"** is read as R-FILE-01's own category: an executable or script file. The files are PowerShell's
  `__PSScriptPolicyTest_*` execution-policy test scripts. The records do not show malicious content, and the
  claim does not assert any. A reviewer who read "payload" as attacker-delivered content would label all four
  payload claims partially supported. S03-CLM-06 would then become a justified downgrade, and S02-CLM-05,
  S02-CLM-08 and S03-CLM-03 would become misses.
* **"Documented suspicious access mask"** (S01-CLM-03) is supported because `0x00001410` is one of the seven
  masks R-CRED-01 documents.
* **Explicit-credential logons** to winlogon's UMFD/DWM virtual accounts are supported as stated. The claims
  assert nothing about the account or intent.

## What this does and does not establish

* It settles the specific question about the four downgrades on these claims: two were right, two were false
  alarms. It also shows that one confirmation was wrong, so "13/17 confirmed" was not 13 correct claims.
* It is one verifier run on 17 template claims from three lab scenarios, with one reviewer. Repeated development
  runs of the verifier varied. **It is not an estimate of the verifier's real-world accuracy.**
* The claims were regenerated from the same corpus and implementation. Generation is deterministic: two
  separate generations gave identical claim hashes. The claim IDs and types match the validation audit. The
  audit records no claim hashes, though, so this does not prove the claims are byte-identical to those the
  verifier saw.
* It is a disclosed model review. The final four-configuration comparison still needs independent human claim reviews
  (`FINAL_EVALUATION_HANDOFF.md`).

## Reproduce

```bash
python -m event_processing normalise --datasets datasets --out out/sr/corpus
python -m incident_reconstruction --corpus out/sr/corpus --llm fake --mode multi-agent --out out/sr/runs
python -m evidence_verification.evaluation.component_review prepare --corpus out/sr/corpus --runs out/sr/runs --out out/sr/packet
```

`prepare` writes the reading packet and the unanswered form. The completed labels are recorded in the
validation JSON above. `component_review score` checks them against the claims, corpus and packet, then
unblinds them against `validation/correctness-2026-10-20.json`.
