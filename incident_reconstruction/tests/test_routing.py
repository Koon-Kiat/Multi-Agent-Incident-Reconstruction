from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks
from incident_reconstruction.models import WindowPolicy, default_policies
from incident_reconstruction.routing import agents_for, plan_investigations, split_plan

from .conftest import SCENARIO, at, detection, sysmon


def test_rules_route_to_the_agents_that_can_investigate_them(events, detections):
    by_rule = {d.rule_id: agents_for(d) for d in detections}
    assert by_rule["R-AUTH-01"] == ("authentication",)
    assert by_rule["R-AUTH-03"] == ("authentication", "endpoint")
    assert by_rule["R-EXEC-01"] == ("endpoint",)
    assert by_rule["R-FILE-01"] == ("endpoint",)
    assert agents_for(detection("R-LOG-01", events["explicit"])) == ("authentication", "endpoint")
    # A rule this table has never seen is investigated by every agent rather than dropped.
    assert agents_for(detection("R-NEW-01", events["explicit"])) == ("authentication", "endpoint")


def test_nearby_triggers_merge_and_distant_ones_do_not(store, detections):
    plans = plan_investigations(SCENARIO, detections, store)
    assert [plan.task_id for plan in plans] == [
        f"{SCENARIO}-authentication-01", f"{SCENARIO}-endpoint-01", f"{SCENARIO}-endpoint-02"]
    authentication, endpoint_near, endpoint_late = plans
    assert len(authentication.detection_ids) == 2
    assert len(endpoint_near.detection_ids) == 3
    assert endpoint_late.detection_ids == (detections[-1].detection_id,)


def test_windows_pad_closed_spans_into_half_open_bounds(store, detections):
    authentication = plan_investigations(SCENARIO, detections, store)[0]
    # R-AUTH-01 spans seconds 0..2 and R-AUTH-03 is at 3; 60 s context each side, end gains one tick.
    assert iso_to_ticks(authentication.start_utc) == at(0) - 60 * TICKS_PER_SECOND
    assert iso_to_ticks(authentication.end_utc) == at(3) + 60 * TICKS_PER_SECOND + 1


def test_only_retrievable_triggers_become_seeds(store, events, detections):
    authentication, endpoint_near, endpoint_late = plan_investigations(SCENARIO, detections, store)
    # 4648 is not one of the authentication tools' event types, so it defines the window only.
    assert authentication.seed_evidence_ids == tuple(events[k].evidence_id for k in ("fail1", "fail2", "success"))
    assert endpoint_near.seed_evidence_ids == (events["process_child"].evidence_id, events["file"].evidence_id)
    assert endpoint_late.seed_evidence_ids == (events["late_process"].evidence_id,)


def test_a_detection_longer_than_the_bound_is_trimmed_and_noted(store, events):
    long = detection("R-EXEC-01", events["process_child"], events["late_process"])
    policies = {"endpoint": WindowPolicy(context_before_seconds=15, context_after_seconds=15, max_window_seconds=600)}
    (plan,) = plan_investigations(SCENARIO, (long,), store, policies)
    assert iso_to_ticks(plan.end_utc) - iso_to_ticks(plan.start_utc) == 600 * TICKS_PER_SECOND
    assert iso_to_ticks(plan.start_utc) == events["process_child"].timestamp_ticks
    assert any("exceeds the window bound" in note for note in plan.notes)
    # The trigger that fell outside the window is not offered as a seed.
    assert plan.seed_evidence_ids == (events["process_child"].evidence_id,)


def test_merging_never_exceeds_the_window_bound(store, events):
    detections = tuple(detection("R-EXEC-01", sysmon(100 + i, i * 20)) for i in range(10))
    store = type(store)([*store.scenario_events(SCENARIO), *(sysmon(100 + i, i * 20) for i in range(10))])
    policies = {"endpoint": WindowPolicy(context_before_seconds=15, context_after_seconds=15, max_window_seconds=60)}
    plans = plan_investigations(SCENARIO, detections, store, policies)
    assert len(plans) > 1
    assert all(iso_to_ticks(p.end_utc) - iso_to_ticks(p.start_utc) <= 60 * TICKS_PER_SECOND for p in plans)
    assert sorted(d for p in plans for d in p.detection_ids) == sorted(d.detection_id for d in detections)


def test_split_keeps_triggers_and_seeds_with_their_half(store, events, detections):
    _, endpoint_near, _ = plan_investigations(SCENARIO, detections, store)
    by_id = {d.detection_id: d for d in detections}
    # The window is [-12 s, 21 s + 1 tick); the midpoint falls between the 4648 at 3 s and the process at 5 s.
    first, second = split_plan(endpoint_near, by_id, store)
    assert (first.task_id, second.task_id) == (f"{endpoint_near.task_id}.1", f"{endpoint_near.task_id}.2")
    assert first.start_utc == endpoint_near.start_utc and second.end_utc == endpoint_near.end_utc
    assert first.end_utc == second.start_utc
    assert [by_id[d].rule_id for d in first.detection_ids] == ["R-AUTH-03"]
    assert first.seed_evidence_ids == ()
    assert second.seed_evidence_ids == endpoint_near.seed_evidence_ids
    assert {first.parent_task_id, second.parent_task_id} == {endpoint_near.task_id}
    assert second.split_depth == 1


def test_split_drops_halves_without_a_trigger(store, events):
    single = detection("R-EXEC-01", events["late_process"])
    (plan,) = plan_investigations(SCENARIO, (single,), store)
    # The trigger sits exactly at the padded window's centre; context-only halves are not worth a call.
    halves = split_plan(plan, {single.detection_id: single}, store)
    assert len(halves) == 1
    assert halves[0].detection_ids == (single.detection_id,)


def test_split_stops_at_the_minimum_span(store, events):
    tight = {"endpoint": WindowPolicy(context_before_seconds=0, context_after_seconds=0, max_window_seconds=600)}
    single = detection("R-EXEC-01", events["process_child"])
    (plan,) = plan_investigations(SCENARIO, (single,), store, tight)
    assert split_plan(plan, {single.detection_id: single}, store) == ()


def test_default_endpoint_context_is_narrower_than_authentication():
    policies = default_policies()
    assert policies["endpoint"].context_before_seconds < policies["authentication"].context_before_seconds
