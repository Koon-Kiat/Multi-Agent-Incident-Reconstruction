"""Negative examples for principal correlation across detection and verification."""

import pytest

from event_processing.identity import authentication_principals
from event_processing.detection.rules import detect_failed_logon_then_success
from event_processing.query import EventStore
from evidence_verification.tests.conftest import security,make_claim,assess_one,iso
from evidence_verification.facts import event_accounts,grounded,folded,value_pool


def sequence(domains=("A","A"),sids=("S-1-0-0","S-1-5-21-111-1001")):
    events=[security(100+i,i,4625,TargetDomainName=domains[0],TargetUserSid=sids[0]) for i in range(5)]
    events.append(security(105,5,4624,TargetDomainName=domains[1],TargetUserSid=sids[1]))
    return events


def claim_for(events):
    return make_claim(claim_text="Five failed logons were followed by a successful logon for the same account.",
        first_utc=events[0].timestamp_utc,last_utc=events[-1].timestamp_utc,
        evidence_ids=tuple(e.evidence_id for e in events),context_evidence_ids=tuple(e.evidence_id for e in events))


@pytest.mark.parametrize("domains,sids",[
    (("A","B"),("S-1-5-21-111-1001","S-1-5-21-222-1001")),
    (("A","A"),("S-1-5-21-111-1001","S-1-5-21-222-1001")),
    (("A","B"),("S-1-0-0","S-1-0-0")),
])
def test_distinct_principals_never_become_a_same_account_sequence(domains,sids):
    events=sequence(domains,sids)
    assert not detect_failed_logon_then_success(events)
    assert assess_one(claim_for(events),EventStore(events)).verdict != "confirmed"


def test_null_failure_sid_can_resolve_through_one_unambiguous_domain_alias():
    events=sequence()
    assert len(set(authentication_principals(events).values()))==1
    assert len(detect_failed_logon_then_success(events))==1
    assert assess_one(claim_for(events),EventStore(events)).verdict=="confirmed"


def test_missing_sid_does_not_bridge_two_conflicting_sids():
    events=sequence(sids=("S-1-0-0","S-1-5-21-111-1001"))
    events.append(security(106,6,4624,TargetDomainName="A",TargetUserSid="S-1-5-21-222-1001"))
    keys=authentication_principals(events)
    assert keys[events[0].evidence_id] != keys[events[-1].evidence_id]
    assert not detect_failed_logon_then_success(events)


@pytest.mark.parametrize("times",[(0,2,1),(0,1,1)])
def test_failures_after_or_tied_with_success_do_not_support_then_success(times):
    events=[security(10,times[0],4625),security(11,times[1],4625),security(12,times[2],4624)]
    claim=make_claim(last_utc=iso(max(times)))
    assert assess_one(claim,EventStore(events)).verdict != "confirmed"


def test_account_links_and_entity_grounding_retain_the_recorded_domain():
    a=security(1,0,4624,user="A\\analyst",TargetDomainName="A")
    b=security(2,1,4624,user="B\\analyst",TargetDomainName="B")
    assert not event_accounts(a)&event_accounts(b)
    pool=value_pool([a])
    assert grounded("A\\analyst",pool,folded(pool))
    assert not grounded("B\\analyst",pool,folded(pool))


def test_reconstruction_stage_links_keep_qualified_accounts_and_do_not_bridge_domains():
    from incident_reconstruction.stages import Stage
    a=Stage(1,"R-AUTH-03",[],0,0,trigger_events=[security(1,0,4648,user="A\\analyst",TargetDomainName="A")])
    b=Stage(2,"R-AUTH-03",[],0,0,trigger_events=[security(2,1,4648,user="B\\analyst",TargetDomainName="B")])
    c=Stage(3,"R-AUTH-03",[],0,0,trigger_events=[security(3,2,4648,user="A\\analyst",TargetDomainName="A")])
    assert a.accounts()=={"a\\analyst"}
    assert not a.accounts()&b.accounts()
    assert a.accounts()&c.accounts()=={"a\\analyst"}


def test_authentication_observations_do_not_merge_complete_entities_with_conflicting_sids():
    from authentication_agent.models import AuthenticationEvent
    from authentication_agent.observations import build_observations
    events=sequence(sids=("S-1-5-21-111-1001","S-1-5-21-222-1001"))
    converted=[]
    for event in events:
        data=event.model_dump(mode="json")
        data["user"]="analyst"
        data["event_data"].update(IpAddress="192.0.2.1",WorkstationName="LAB-A",LogonType="2")
        converted.append(AuthenticationEvent.model_validate({k:v for k,v in data.items() if k in AuthenticationEvent.model_fields}))
    observations=build_observations(converted,False)
    assert len(observations)==2
    assert not any(o.observed_events.repeated_failures_followed_by_success for o in observations)
    assert sorted(o.observed_events.failed_logons for o in observations)==[0,5]
