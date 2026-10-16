"""Route conventional detections to investigation agents as bounded, merged windows.

Routing is a fixed table keyed by detection rule, so the same detection run always yields the
same plan. Trigger evidence IDs become trusted seeds only where the receiving agent's tools can
retrieve that event type: Sysmon triggers for the Endpoint Investigation Agent, Security
4624/4625 triggers for the Authentication Investigation Agent. Other triggers (4648, 4688, 1102)
still define the window and stay referenced through ``detection_ids``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from endpoint_agent.models import ENDPOINT_EVENT_IDS
from event_processing.detection.schema import Detection
from event_processing.ids import parse_evidence_id
from event_processing.query import SECURITY_CHANNEL, SYSMON_CHANNEL, EventStore
from event_processing.timeutil import TICKS_PER_SECOND, iso_to_ticks, ticks_to_iso

from .models import AgentType, PlannedInvestigation, WindowPolicy, default_policies

AGENT_TYPES: tuple[AgentType, ...] = ("authentication", "endpoint")
AUTHENTICATION_SEED_EVENT_IDS = frozenset({4624, 4625})
MAX_SEEDS = 99
MIN_SPLIT_SECONDS = 2

# Exact rules first, then the rule family. An unknown rule goes to every agent: a new detection
# must not silently go uninvestigated because this table was not updated.
RULE_ROUTES: dict[str, tuple[AgentType, ...]] = {
    # Explicit-credential logons are usually caused by a process (runas, scheduled work), so the
    # endpoint view is needed as well as the surrounding logons.
    "R-AUTH-03": ("authentication", "endpoint"),
}
FAMILY_ROUTES: dict[str, tuple[AgentType, ...]] = {
    "R-AUTH": ("authentication",),
    "R-CRED": ("endpoint",),
    "R-EXEC": ("endpoint",),
    "R-FILE": ("endpoint",),
    "R-PERSIST": ("endpoint",),
    # Clearing the audit log removes context for both sources; both agents examine its window.
    "R-LOG": ("authentication", "endpoint"),
}


def agents_for(detection: Detection) -> tuple[AgentType, ...]:
    if detection.rule_id in RULE_ROUTES:
        return RULE_ROUTES[detection.rule_id]
    return FAMILY_ROUTES.get(detection.rule_id.rsplit("-", 1)[0], AGENT_TYPES)


@dataclass
class _Window:
    start: int
    end: int
    detections: list[Detection] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def plan_investigations(scenario_id: str, detections: Sequence[Detection], store: EventStore,
                        policies: Mapping[AgentType, WindowPolicy] | None = None) -> tuple[PlannedInvestigation, ...]:
    """Every agent window for one scenario, authentication first, each agent's in time order."""
    policies = {**default_policies(), **(policies or {})}
    plans: list[PlannedInvestigation] = []
    for agent_type in AGENT_TYPES:
        routed = [detection for detection in detections
                  if detection.scenario_id == scenario_id and agent_type in agents_for(detection)]
        for index, window in enumerate(_merge(routed, policies[agent_type]), start=1):
            seeds = [evidence_id for evidence_id in _seeds(agent_type, window.detections, store)
                     if window.start <= store.lookup(evidence_id).event.timestamp_ticks < window.end]
            notes = list(window.notes)
            if len(seeds) > MAX_SEEDS:
                notes.append(f"{len(seeds) - MAX_SEEDS} trigger seeds beyond the {MAX_SEEDS}-seed bound were not supplied")
                seeds = seeds[:MAX_SEEDS]
            plans.append(PlannedInvestigation(
                task_id=f"{scenario_id}-{agent_type}-{index:02d}",
                agent_type=agent_type,
                scenario_id=scenario_id,
                start_utc=ticks_to_iso(window.start),
                end_utc=ticks_to_iso(window.end),
                detection_ids=tuple(detection.detection_id for detection in window.detections),
                seed_evidence_ids=tuple(seeds),
                notes=tuple(notes),
            ))
    return tuple(plans)


def split_plan(plan: PlannedInvestigation, detections: Mapping[str, Detection],
               store: EventStore) -> tuple[PlannedInvestigation, ...]:
    """Halve a window at its midpoint, keeping only halves that still hold a trigger.

    A detection whose closed span touches a half stays with it, so a detection straddling the
    midpoint is investigated in both. Seeds follow their event's timestamp. Returns ``()`` when the
    window is already at the minimum span: there is nothing smaller worth asking the agent about.
    """
    start, end = iso_to_ticks(plan.start_utc), iso_to_ticks(plan.end_utc)
    if end - start < 2 * MIN_SPLIT_SECONDS * TICKS_PER_SECOND:
        return ()
    middle = start + (end - start) // 2
    halves = []
    for suffix, (low, high) in enumerate(((start, middle), (middle, end)), start=1):
        detection_ids = tuple(
            detection_id for detection_id in plan.detection_ids
            if iso_to_ticks(detections[detection_id].window_start_utc) < high
            and iso_to_ticks(detections[detection_id].window_end_utc) >= low
        )
        if not detection_ids:
            continue
        seeds = tuple(
            evidence_id for evidence_id in plan.seed_evidence_ids
            if low <= store.lookup(evidence_id).event.timestamp_ticks < high
        )
        halves.append(plan.model_copy(update={
            "task_id": f"{plan.task_id}.{suffix}",
            "start_utc": ticks_to_iso(low),
            "end_utc": ticks_to_iso(high),
            "detection_ids": detection_ids,
            "seed_evidence_ids": seeds,
            "notes": (),
            "parent_task_id": plan.task_id,
        }))
    return tuple(halves)


def _merge(detections: Iterable[Detection], policy: WindowPolicy) -> list[_Window]:
    before = policy.context_before_seconds * TICKS_PER_SECOND
    # Detection spans are closed; query windows are half-open, so the end gains one tick.
    after = policy.context_after_seconds * TICKS_PER_SECOND + 1
    limit = policy.max_window_seconds * TICKS_PER_SECOND
    spans = sorted(
        ((iso_to_ticks(d.window_start_utc), iso_to_ticks(d.window_end_utc), d) for d in detections),
        key=lambda item: (item[0], item[2].detection_id),
    )
    windows: list[_Window] = []
    for start, end, detection in spans:
        padded_start, padded_end = start - before, end + after
        current = windows[-1] if windows else None
        if current and padded_start <= current.end and max(current.end, padded_end) - current.start <= limit:
            current.end = max(current.end, padded_end)
            current.detections.append(detection)
            continue
        window = _Window(padded_start, padded_end, [detection])
        if padded_end - padded_start > limit:
            # Keep the trigger span itself in preference to context; never exceed the agent bound.
            window.start = min(start, padded_end - limit)
            window.end = window.start + limit
            window.notes.append(f"detection {detection.detection_id} context was trimmed to the "
                                f"{policy.max_window_seconds}s window bound")
            if end + 1 > window.end:
                window.notes.append(f"detection {detection.detection_id} span exceeds the window bound; "
                                    "later triggers fall outside this investigation")
        windows.append(window)
    return windows


def _seeds(agent_type: AgentType, detections: Iterable[Detection], store: EventStore) -> list[str]:
    seeds: list[str] = []
    for detection in detections:
        for evidence_id in detection.trigger_evidence_ids:
            if evidence_id in seeds or not _retrievable_by(agent_type, evidence_id, store):
                continue
            seeds.append(evidence_id)
    return seeds


def _retrievable_by(agent_type: AgentType, evidence_id: str, store: EventStore) -> bool:
    channel = parse_evidence_id(evidence_id).channel
    expected_channel, event_ids = (
        (SYSMON_CHANNEL, ENDPOINT_EVENT_IDS) if agent_type == "endpoint"
        else (SECURITY_CHANNEL, AUTHENTICATION_SEED_EVENT_IDS)
    )
    if channel != expected_channel:
        return False
    lookup = store.lookup(evidence_id)
    return lookup.event is not None and lookup.event.source_event_id in event_ids
