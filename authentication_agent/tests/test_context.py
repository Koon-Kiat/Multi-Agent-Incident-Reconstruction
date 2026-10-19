"""Model contexts fit the declared profile; no event is silently clipped."""

import json
import hashlib

from authentication_agent.agent import investigate
from authentication_agent.models import AuthenticationEvent,InvestigationRequest
from authentication_agent.queries.in_memory import InMemoryAuthenticationEventProvider
from authentication_agent.context import context_measure
from authentication_agent.config import Limits


class Capture:
    def __init__(self): self.messages=[]
    def metadata(self): return {"runtime":"test","num_ctx":8192}
    def complete(self,messages,schema,limits):
        assert context_measure(messages,schema,self.metadata(),limits)[0]
        self.messages.append(messages)
        return json.dumps({"action":"finish","tool":None,"annotations":[]})


def events(*,same_principal=False):
    result=[]
    for i in range(20):
        account="same" if same_principal else f"user{i}"
        # Long opaque package names expose byte/token mismatches, while remaining
        # legitimate bounded source strings for the contract boundary.
        opaque="".join(hashlib.sha256(f"{i}-{j}".encode()).hexdigest() for j in range(24))
        result.append(AuthenticationEvent(evidence_id=f"SYN-CTX-SEC-{i+1}",scenario_id="SYN-CTX",
            source_type="windows_security",channel="Security",source_event_id=4624,record_id=i+1,
            timestamp_utc=f"2026-01-01T00:00:{i:02d}Z",host="LAB",user=account,
            event_data={"TargetUserName":account,"TargetDomainName":"LAB","IpAddress":"127.0.0.1",
                "WorkstationName":"LAB","LogonType":"2","AuthenticationPackageName":opaque},
            raw_reference=f"evtx://synthetic#{i+1}"))
    return result


def test_large_snapshot_uses_fitting_batches_and_retains_every_observation():
    source=events(); llm=Capture()
    result=investigate(InvestigationRequest(scenario_id="SYN-CTX",start_utc="2026-01-01T00:00:00Z",
        end_utc="2026-01-01T00:01:00Z"),InMemoryAuthenticationEventProvider(source),llm)
    assert result.status=="completed",result.error_code
    assert len(llm.messages)>1
    assert {eid for finding in result.findings for eid in finding.evidence_ids}=={e.evidence_id for e in source}
    presented={event["evidence_id"] for msg in llm.messages for obs in json.loads(msg[1]["content"])["observations"] for event in obs["events"]}
    assert presented=={e.evidence_id for e in source}
    assert all(b.input_token_upper_bound+2048<=8192 for b in result.metadata.context_batches)
    assert result.metadata.evidence_readbacks==len(source)


def test_an_indivisible_finding_over_context_fails_without_partial_findings():
    source=events(same_principal=True); llm=Capture()
    result=investigate(InvestigationRequest(scenario_id="SYN-CTX",start_utc="2026-01-01T00:00:00Z",
        end_utc="2026-01-01T00:01:00Z"),InMemoryAuthenticationEventProvider(source),llm)
    assert result.status=="failed" and result.error_code=="context_size_limit"
    assert result.findings==() and llm.messages==[]


def test_nested_runtime_profile_and_output_reserve_are_enforced():
    messages=[{"role":"user","content":"x"*4000}]
    assert not context_measure(messages,{}, {"configuration":{"num_ctx":4096}},Limits())[0]
