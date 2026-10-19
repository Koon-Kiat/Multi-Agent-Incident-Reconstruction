"""Synthetic verifier development benchmark. Historically every case passed deterministic checks;
corrected count/order/duration checks now catch some cases before model consultation. Faithful claims state only what their records state; embellished
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


# ---------------------------------------------------------------------------------------------
# Held-out set, written BEFORE the post-hoc prompt revision (prompt v3) so the revision is measured on cases it
# was not tuned against. DERIVED_FAITHFUL claims are true but rest on facts that follow from the records (a
# duration, an order, a parent process, a characterisation of a path, a compound sentence) rather than on one
# quotable statement. HELD_OUT_EMBELLISHED claims add content the records do not state, including one whose
# derived fact is wrong.
# ---------------------------------------------------------------------------------------------

DERIVED_FAITHFUL = {
    "D1 duration derived": make_claim(
        claim_text="Two failed logons for the analyst account occurred within 2 seconds, followed by a successful logon."),
    "D2 compound sentence": make_claim(
        claim_text="The analyst account failed to log on twice and then logged on successfully, all on host LAB-A."),
    "D3 parent process": _typed("discovery_commands", [sys_id(20)], (5, 5),
                                "whoami.exe was started by explorer.exe under the analyst account."),
    "D4 office parent": _typed("unusual_parent_shell", [sys_id(23)], (8, 8),
                               "cmd.exe was started by winword.exe under the account LAB-A\\other."),
    "D5 order derived": make_claim(
        claim_text="Events 4625, 4625 and 4624 were recorded for the analyst account, in that order."),
    "D6 path characterised": _typed("payload_written", [sys_id(21)], (6, 6),
                                    "The script payload.ps1 was written to a folder under the analyst user's profile."),
}
HELD_OUT_EMBELLISHED = {
    "H1 invented escalation": make_claim(
        claim_text="Two failed logons for the analyst account occurred within 2 seconds, and the attacker then "
                   "escalated privileges."),
    "H2 invented cause": _typed("discovery_commands", [sys_id(20)], (5, 5),
                                "whoami.exe was started by explorer.exe under the analyst account, after the user "
                                "opened a phishing email."),
    "H3 derived fact wrong": make_claim(
        claim_text="The two failed logons for the analyst account were ten seconds apart, followed by a successful logon."),
    "H4 wrong actor": _typed("audit_log_cleared", [sec_id(14)], (4, 4),
                             "The Security audit log was cleared (Security 1102) by the SYSTEM account."),
}
