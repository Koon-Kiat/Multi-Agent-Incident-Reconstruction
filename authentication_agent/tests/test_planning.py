import json
import pytest
from authentication_agent import investigate,ToolCall
from authentication_agent.config import Limits
from authentication_agent.queries.tools import AuthenticationTools
from authentication_agent.planning import query_menu,canonical,parse_reply
from authentication_agent.validate_investigations import run_case
from authentication_agent.validate_autonomy import assess


def test_menu_uses_only_public_audit_and_never_probes_provider(provider,request_a):
    limits=Limits(max_events_per_query=2);tools=AuthenticationTools(request_a,provider,limits)
    tools.execute(ToolCall(name="query_authentication_events",arguments={**request_a.model_dump(),"limit":2}),origin="initial")
    before=(tools.calls,len(tools.operations),set(tools.retrieved))
    menu,coverage=query_menu(request_a,tools,limits)
    assert before==(tools.calls,len(tools.operations),set(tools.retrieved))
    assert not coverage["initial_inventory_complete"] and menu
    assert all(canonical(ToolCall(**q["call"]))!=canonical(tools.operations[0].call) for q in menu.values())
    assert any(q["call"]["arguments"].get("event_ids")==[4624] for q in menu.values())
    assert all(q["call"]["arguments"]["limit"]==2 for q in menu.values())
    assert "availability_witness" not in json.dumps(menu)


def test_complete_inventory_has_no_redundant_queries(provider,request_a):
    limits=Limits();tools=AuthenticationTools(request_a,provider,limits)
    tools.execute(ToolCall(name="query_authentication_events",arguments={**request_a.model_dump(),"limit":100}),origin="initial")
    menu,coverage=query_menu(request_a,tools,limits)
    assert coverage["initial_inventory_complete"] and menu=={}


class SelectAndReview:
    def metadata(self): return {"runtime":"controlled-mechanism-test"}
    def complete(self,messages,schema,limits):
        context=json.loads(messages[-1]["content"])
        if not any(o["observed_events"]["successful_logons"] for o in context["observations"]):
            qid=next(k for k,v in context["available_queries"].items() if v["call"]["arguments"].get("event_ids")==[4624])
            return json.dumps({"assessment":"A controlled tool-boundary test, not model autonomy.","action":"tool","query_id":qid,"annotations":[]})
        return json.dumps({"assessment":"Reviewed the returned records.","action":"finish","tool":None,
            "annotations":[{"index":o["index"],"interpretation":"context_required"} for o in context["observations"]]})


def test_selected_query_and_reviews_expand_to_exact_records(provider,request_a):
    case=run_case("controlled-menu","autonomy",request_a,provider,SelectAndReview(),Limits(max_events_per_query=2))
    result=assess(case,4624)
    assert not case["check_errors"] and not result["behavior_errors"]
    assert result["relevant_new_evidence_ids"]==["SYN-A-SEC-4"]
    assert case["result"]["metadata"]["planning_policy"]=="public-query-menu-v1"


def test_unknown_query_alias_is_not_authority(provider,request_a):
    class Invalid:
        def metadata(self): return {"runtime":"controlled-mechanism-test"}
        def complete(self,*args): return '{"action":"tool","query_id":"Q99999","annotations":[]}'
    result=investigate(request_a,provider,Invalid(),Limits(max_events_per_query=2))
    assert result.status=="failed" and not result.findings
    assert result.metadata.tool_calls==1


def test_indexed_review_cannot_omit_or_duplicate_an_observation():
    observations=[{"finding_id":"A","evidence_ids":["SYN-A-SEC-1"]},{"finding_id":"B","evidence_ids":["SYN-A-SEC-2"]}]
    for indices in ([0],[0,0],[0,99]):
        text=json.dumps({"action":"finish","tool":None,"annotations":[{"index":i,"interpretation":None} for i in indices]})
        with pytest.raises(ValueError): parse_reply(text,observations,{})
