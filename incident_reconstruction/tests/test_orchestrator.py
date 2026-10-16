import threading

import pytest

from authentication_agent.config import Limits
from authentication_agent.llm.fake import FakeLLM as AuthenticationFake
from endpoint_agent.llm.fake import FakeLLM as EndpointFake
from event_processing.timeutil import iso_to_ticks, ticks_to_iso
from incident_reconstruction import IncidentOrchestrator, OrchestrationError, OrchestrationRun
from incident_reconstruction.orchestrator import corpus_investigators, task_limits

from .conftest import SCENARIO


def run(store, engine, investigators, **options):
    return IncidentOrchestrator(store, engine, investigators, **options).run(SCENARIO)


def test_every_window_is_investigated_through_the_real_agents(store, engine, investigators, detections):
    result = run(store, engine, investigators)
    assert [task.status for task in result.tasks] == ["completed"] * 3
    assert result.uninvestigated_detection_ids() == ()
    assert result.unresolved_task_ids() == ()
    assert {f.agent_type for f in result.findings()} == {"authentication", "endpoint"}
    # Every finding cites only evidence that exists in the corpus it came from.
    for finding in result.findings():
        assert all(store.lookup(eid).event is not None for eid in finding.evidence_ids)
    assert [c.detection_id for c in result.coverage] == [d.detection_id for d in engine.triggers_for(SCENARIO)]


def test_seeds_are_retrieved_as_trusted_operations(store, engine, investigators):
    result = run(store, engine, investigators)
    authentication = result.tasks[0].authentication_result
    required = [op for op in authentication.metadata.operations if op.origin == "required"]
    assert [op.call.arguments["evidence_id"] for op in required] == list(result.tasks[0].plan.seed_evidence_ids)
    endpoint = result.tasks[1].endpoint_result
    assert endpoint.request.seed_evidence_ids == result.tasks[1].plan.seed_evidence_ids
    assert any(op.origin == "seed" for op in endpoint.metadata.operations)


def test_the_run_record_round_trips(store, engine, investigators):
    result = run(store, engine, investigators, llm_metadata={"runtime": "fake"})
    assert OrchestrationRun.model_validate_json(result.model_dump_json()) == result


def test_an_agent_exception_is_recorded_and_the_run_continues(store, engine, investigators):
    def broken(plan):
        raise RuntimeError("secret provider text")

    result = run(store, engine, {**investigators, "authentication": broken})
    first = result.tasks[0]
    assert (first.status, first.error_code) == ("error", "agent_exception:RuntimeError")
    assert "secret" not in result.model_dump_json()
    assert [task.status for task in result.tasks[1:]] == ["completed", "completed"]
    # R-AUTH-01 went only to the failed agent, so it is reported, not presumed clean.
    assert any("R-AUTH-01" in d for d in result.uninvestigated_detection_ids())
    assert not any("R-AUTH-03" in d for d in result.uninvestigated_detection_ids())


def test_an_overrunning_agent_times_out_without_blocking_the_run(store, engine, investigators):
    release = threading.Event()

    def stuck(plan):
        release.wait(5)
        return investigators["endpoint"](plan)

    try:
        result = run(store, engine, {**investigators, "endpoint": stuck}, task_timeout_seconds=0.2)
    finally:
        release.set()
    assert [task.status for task in result.tasks] == ["completed", "timeout", "timeout"]
    assert result.tasks[1].error_code == "task_timeout"
    assert result.tasks[1].endpoint_result is None


def test_a_result_for_the_wrong_window_is_a_contract_violation(store, engine, investigators):
    def swapped(plan):
        other = plan.model_copy(update={"end_utc": ticks_to_iso(iso_to_ticks(plan.end_utc) - 1)})
        return investigators["authentication"](other)

    result = run(store, engine, {**investigators, "authentication": swapped})
    assert (result.tasks[0].status, result.tasks[0].error_code) == ("error", "agent_contract_violation")


def test_a_wrong_result_type_is_a_contract_violation(store, engine, investigators):
    def authentication_instead(plan):
        # A well-formed authentication result for the same window, returned for an endpoint task.
        return investigators["authentication"](plan.model_copy(update={"agent_type": "authentication",
                                                                       "seed_evidence_ids": ()}))

    result = run(store, engine, {**investigators, "endpoint": authentication_instead})
    assert (result.tasks[1].status, result.tasks[1].error_code) == ("error", "agent_contract_violation")
    assert result.tasks[1].authentication_result is None


def test_context_overflow_is_retried_on_smaller_windows(store, engine, investigators):
    tiny = corpus_investigators(store, authentication_llm=AuthenticationFake(), endpoint_llm=EndpointFake(),
                                limits=Limits(max_context_bytes=4096))
    first = run(store, engine, investigators).tasks[1]

    def overflow_once(plan):
        # The full near-window overflows; any half of it fits.
        chosen = tiny if plan.task_id == first.plan.task_id else investigators
        return chosen["endpoint"](plan)

    result = run(store, engine, {**investigators, "endpoint": overflow_once})
    parent = next(task for task in result.tasks if task.plan.task_id == first.plan.task_id)
    assert (parent.status, parent.error_code) == ("failed", "context_size_limit")
    assert parent.split_into == (f"{parent.plan.task_id}.1", f"{parent.plan.task_id}.2")
    children = [task for task in result.tasks if task.plan.parent_task_id == parent.plan.task_id]
    assert [task.status for task in children] == ["completed", "completed"]
    assert parent.resolved and result.unresolved_task_ids() == ()
    assert result.uninvestigated_detection_ids() == ()
    # Children run immediately after their parent, keeping each agent's tasks in time order.
    order = [task.plan.task_id for task in result.tasks]
    assert order.index(children[0].plan.task_id) == order.index(parent.plan.task_id) + 1


def test_splitting_stops_at_the_configured_depth(store, engine, investigators):
    tiny = corpus_investigators(store, authentication_llm=AuthenticationFake(), endpoint_llm=EndpointFake(),
                                limits=Limits(max_context_bytes=4096))
    result = run(store, engine, {**investigators, "endpoint": tiny["endpoint"]}, max_split_depth=0)
    endpoint = [task for task in result.tasks if task.plan.agent_type == "endpoint"]
    assert all(task.split_into == () for task in endpoint)
    assert {task.error_code for task in endpoint} == {"context_size_limit"}
    assert len(result.unresolved_task_ids()) == len(endpoint)


def test_an_exhausted_run_deadline_leaves_later_tasks_not_run(store, engine, investigators):
    release = threading.Event()

    def slow(plan):
        release.wait(0.3)
        return investigators["authentication"](plan)

    try:
        result = run(store, engine, {**investigators, "authentication": slow}, run_timeout_seconds=0.1)
    finally:
        release.set()
    assert result.tasks[0].status == "timeout"
    assert {task.status for task in result.tasks[1:]} == {"not_run"}
    assert {task.error_code for task in result.tasks[1:]} == {"run_deadline_exceeded"}


def test_tool_budget_reserves_room_for_the_model_after_seeds(store, engine):
    plan = IncidentOrchestrator(store, engine, {}).plan(SCENARIO)[0]
    assert len(plan.seed_evidence_ids) == 3
    assert task_limits(Limits(), plan, model_tool_calls=7).max_tool_calls == 11
    assert task_limits(Limits(max_tool_calls=20), plan).max_tool_calls == 20


def test_invalid_setup_is_refused_before_any_dispatch(store, engine, investigators):
    with pytest.raises(OrchestrationError, match="not in the corpus"):
        IncidentOrchestrator(store, engine, investigators).run("S99")
    with pytest.raises(OrchestrationError, match="no investigator"):
        IncidentOrchestrator(store, engine, {"endpoint": investigators["endpoint"]}).run(SCENARIO)
    with pytest.raises(OrchestrationError, match="positive"):
        IncidentOrchestrator(store, engine, investigators, task_timeout_seconds=0)


class LoopingLLM:
    """Repeats one identical query forever unless the decoder only offers finish (seen with qwen3:8b)."""

    def __init__(self, agent):
        self.agent = agent

    def metadata(self):
        return {"runtime": "looping"}

    def complete(self, messages, schema, limits):
        import json
        if schema.get("$ref") == "#/$defs/_FinishReply":
            reply = {"action": "finish", "tool": None, "annotations": []}
            return json.dumps({"assessment": "", **reply} if self.agent == "authentication" else reply)
        window = json.loads(messages[-1]["content"])["request"]
        window = {k: window[k] for k in ("scenario_id", "start_utc", "end_utc")}
        if self.agent == "authentication":
            return json.dumps({"assessment": "", "action": "tool", "annotations": [],
                               "tool": {"name": "query_authentication_events", "arguments": window}})
        return json.dumps({"action": "tool", "annotations": [],
                           "tool": {"name": "query_endpoint_events", "arguments": window}})


@pytest.mark.parametrize("guard, statuses", [(True, {"completed"}), (False, {"failed"})])
def test_finish_guard_stops_a_looping_model_from_discarding_evidence(store, engine, guard, statuses):
    agents = corpus_investigators(store, authentication_llm=LoopingLLM("authentication"),
                                  endpoint_llm=LoopingLLM("endpoint"), limits=Limits(), finish_guard=guard)
    result = run(store, engine, agents)
    assert {task.status for task in result.tasks} == statuses
    if guard:
        assert result.findings() and result.uninvestigated_detection_ids() == ()
        # The first model query already repeats the initial one; the next decision may only finish.
        for task in result.tasks:
            model_ops = [op for op in task.result.metadata.operations if op.origin == "model"]
            assert len(model_ops) == 1 and model_ops[0].reused_from is not None
            assert task.result.metadata.llm["finish_guard"] == "budget_or_repeat"
    else:
        assert {task.error_code for task in result.tasks} == {"tool_budget_exhausted"}


def test_finish_guard_leaves_other_turns_untouched():
    from incident_reconstruction.orchestrator import FinishGuard
    import json
    seen = []

    class Recorder:
        def metadata(self):
            return {}

        def complete(self, messages, schema, limits):
            seen.append(schema)
            return "{}"

    guard = FinishGuard(Recorder())
    schema = {"$defs": {"_FinishReply": {}, "_ToolReply": {}}, "anyOf": [{"$ref": "#/$defs/_ToolReply"}]}
    turn = lambda **context: [{"role": "user", "content": json.dumps(context)}]
    guard.complete(turn(tool_calls_remaining=3, operation_history=[{"origin": "initial", "reused_from": None}]), schema, None)
    guard.complete(turn(tool_calls_remaining=0, operation_history=[]), schema, None)
    guard.complete([{"role": "user", "content": "not json"}], schema, None)
    assert seen[0] is schema and seen[2] is schema
    assert seen[1] == {"$defs": schema["$defs"], "$ref": "#/$defs/_FinishReply"}
    assert guard.forced_finishes == 1
