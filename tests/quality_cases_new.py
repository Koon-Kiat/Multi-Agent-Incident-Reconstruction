"""Predeclared synthetic generalization cases, 2026-10-19.

Labels and desired outcomes belong to the evaluation harness only. Production
agents receive just ordinary scoped requests and source records. These cases
must not be used to choose or tune the implementation before its first run.
"""
from event_processing.tests.synthetic import make_event, SECURITY, SYSMON
from event_processing.timeutil import iso_to_ticks, ticks_to_iso, TICKS_PER_SECOND
from evidence_verification.tests.conftest import make_claim, ClaimEntities
from authentication_agent.models import AuthenticationEvent, InvestigationRequest
from authentication_agent.queries.in_memory import InMemoryAuthenticationEventProvider

SCENARIO="SYN-QV"
BASE=iso_to_ticks("2026-10-19T06:00:00Z")


def record(n,second,event_id,*,channel=SECURITY,user="LAB\\ivy",**data):
    return make_event(scenario_id=SCENARIO,channel=channel,record_id=n,event_id=event_id,
        timestamp_ticks=BASE+int(second*TICKS_PER_SECOND),host="NODE-B",user=user,event_data=data)


def verifier_cases():
    auth=[record(n,t,4625,TargetUserName="ivy",TargetDomainName="LAB") for n,t in [(31,0),(38,3),(49,9)]]
    auth.append(record(71,13,4624,TargetUserName="ivy",TargetDomainName="LAB"))
    file=[record(92,20,11,channel=SYSMON,Image=r"C:\Windows\System32\cmd.exe",
        TargetFilename=r"C:\Users\ivy\AppData\Local\Temp\helper.ps1",User=r"LAB\ivy")]
    process=[record(108,25,1,channel=SYSMON,Image=r"C:\Windows\System32\notepad.exe",
        ParentImage=r"C:\Windows\explorer.exe",User=r"LAB\ivy")]
    clear=[record(119,30,1102,SubjectUserName="ivy",SubjectDomainName="LAB")]
    access=[record(133,35,10,channel=SYSMON,SourceImage=r"C:\Tools\monitor.exe",
        TargetImage=r"C:\Windows\System32\lsass.exe",GrantedAccess="0x1010",SourceUser=r"LAB\ivy")]
    explicit=[record(147,40,4648,TargetUserName="ivy",TargetDomainName="LAB",TargetServerName="FILE-SRV")]
    rows=[
        ("N01","supported",auth,"failed_logons_then_success","Three failed logons for ivy on NODE-B were followed by a successful logon."),
        ("N02","supported",auth,"failed_logons_then_success","ivy had three failed logons and then signed in successfully on NODE-B."),
        ("N03","supported",auth,"failed_logons_then_success","The three failures spanned nine seconds before the successful logon."),
        ("N04","supported",file,"payload_written",r"cmd.exe wrote helper.ps1 in C:\Users\ivy\AppData\Local\Temp."),
        ("N05","supported",process,"process_activity",r"notepad.exe was started by explorer.exe for LAB\ivy."),
        ("N06","supported",clear,"audit_log_cleared","The Security audit log was cleared on NODE-B."),
        ("N07","supported",access,"lsass_access","A process accessed lsass.exe; the recorded access mask was 0x1010."),
        ("N08","supported",explicit,"explicit_credential_logon","An explicit-credential logon targeted FILE-SRV."),
        ("N09","unsupported",auth,"failed_logons_then_success","Three failed logons were followed by a successful logon after ivy's password was stolen."),
        ("N10","unsupported",auth,"failed_logons_then_success","The failed logons prove that ivy was a malicious insider."),
        ("N11","unsupported",file,"payload_written","cmd.exe wrote helper.ps1, and the script executed successfully."),
        ("N12","unsupported",process,"process_activity","notepad.exe was started by explorer.exe after a phishing attachment was opened."),
        ("N13","unsupported",clear,"audit_log_cleared","The Security audit log was cleared to hide an attack."),
        ("N14","unsupported",access,"lsass_access","A process accessed lsass.exe and extracted a usable password."),
        ("N15","unsupported",explicit,"explicit_credential_logon","The explicit-credential logon shows the password was changed on FILE-SRV."),
        ("N16","unsupported",auth,"failed_logons_then_success","The failures spanned thirty seconds before the successful sign-in."),
    ]
    for name,label,events,kind,text in rows:
        ids=tuple(e.evidence_id for e in events)
        claim=make_claim(claim_id=f"{SCENARIO}-CLM-{name}",claim_type=kind,claim_text=text,
            first_utc=events[0].timestamp_utc,last_utc=events[-1].timestamp_utc,
            evidence_ids=ids,context_evidence_ids=ids,entities=ClaimEntities())
        yield name,label,claim,events


def authentication_cases():
    def auth(n,t,outcome,user="ivy",domain="LAB",sid="S-1-5-21-918-1001"):
        return record(n,t,outcome,user=user,TargetUserName=user,TargetDomainName=domain,
            TargetUserSid=sid,IpAddress="192.0.2.42",WorkstationName="NODE-B",LogonType="3")
    rows=[
        ("A01",[auth(12,0,4625),auth(29,1,4625),auth(80,7,4624)],2,4624),
        ("A02",[auth(11,0,4624,"svc"),auth(27,1,4624,"svc"),auth(75,7,4625)],2,4625),
        ("A03",[auth(10,0,4625),auth(24,1,4625),auth(78,7,4624,domain="OTHER",sid="S-1-5-21-321-1001")],2,4624),
        ("A04",[auth(9,0,4625),auth(21,0,4625),auth(77,0,4624)],2,4624),
        ("A05",[auth(8,0,4625),auth(22,1,4625),auth(73,6,4625,"marco"),auth(93,7,4624,"marco")],2,4624),
        ("A06",[auth(6,0,4625),auth(19,1,4625),auth(69,7,4624)],100,None),
        ("A07",[],100,None),
        ("A08",[record(5,0,4625,user=None),record(17,1,4624,user=None)],100,None),
    ]
    for name,events,cap,outcome in rows:
        adapted=[AuthenticationEvent.model_validate({k:v for k,v in e.model_dump(mode="json").items()
            if k in AuthenticationEvent.model_fields}) for e in events]
        request=InvestigationRequest(scenario_id=SCENARIO,start_utc=ticks_to_iso(BASE),end_utc=ticks_to_iso(BASE+60*TICKS_PER_SECOND))
        yield name,request,InMemoryAuthenticationEventProvider(adapted),cap,outcome
