"""Synthetic benchmark for the verifier's model layer. Every case PASSES the deterministic checks; the model
layer exists to catch what they cannot read. Faithful claims state only what their records state; embellished
claims add an intent, cause, consequence, wrong account, wrong order or vague count the records do not state.
No real evidence and no answer key is involved."""
from __future__ import annotations

from evidence_verification.tests.conftest import (ClaimEntities, iso, make_claim, sec_id, sys_id)


def _typed(claim_type, ids, second, text, **kw):
    ids = tuple(ids)
    return make_claim(claim_type=claim_type, claim_text=text, evidence_ids=ids, context_evidence_ids=ids,
                      first_utc=iso(second[0]), last_utc=iso(second[1]), entities=ClaimEntities(), **kw)


FAITHFUL = {
    "F1 failed-then-success": make_claim(),
    "F2 explicit credentials": _typed("explicit_credential_logon", [sec_id(13)], (3, 3),
                                      "An explicit-credential logon (Security 4648) was recorded for the analyst account."),
    "F3 whoami": _typed("discovery_commands", [sys_id(20)], (5, 5),
                        "whoami.exe was executed by LAB-A\\analyst on LAB-A."),
    "F4 script written": _typed("payload_written", [sys_id(21)], (6, 6),
                                "cmd.exe created the script payload.ps1 under the analyst user's Temp folder."),
    "F5 log cleared": _typed("audit_log_cleared", [sec_id(14)], (4, 4),
                             "The Security audit log was cleared (Security 1102) on LAB-A."),
    "F6 lsass access": _typed("lsass_access", [sys_id(22)], (7, 7),
                              "A process opened lsass.exe with access mask 0x1410."),
}
EMBELLISHED = {
    "E1 compromise asserted": make_claim(claim_text="The analyst account was compromised by an external attacker after "
                                                   "two failed logons, then logged in successfully."),
    "E2 invented rdp": make_claim(claim_text="Two failed logons were followed by a successful logon, and the user then "
                                            "opened a remote desktop session."),
    "E3 invented intent": _typed("discovery_commands", [sys_id(20)], (5, 5),
                                 "whoami.exe was executed by LAB-A\\analyst to prepare lateral movement to other hosts."),
    "E4 wrong account": _typed("discovery_commands", [sys_id(20)], (5, 5),
                               "whoami.exe was executed by the domain administrator account on LAB-A."),
    "E5 invented exfil": _typed("payload_written", [sys_id(21)], (6, 6),
                                "cmd.exe created the script payload.ps1, which was then uploaded to an external server."),
    "E6 wrong order": make_claim(claim_text="A successful logon for the analyst preceded two failed logons for the same "
                                           "account."),
    "E7 vague count": make_claim(claim_text="Dozens of failed logons were followed by a successful logon."),
    "E8 invented meaning": _typed("explicit_credential_logon", [sec_id(13)], (3, 3),
                                  "A Security 4648 explicit-credential logon shows the analyst's password was changed."),
}
