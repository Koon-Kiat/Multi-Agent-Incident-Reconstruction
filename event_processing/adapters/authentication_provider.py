"""Event Processing & Detection Engine's corpus offered to Authentication Investigation Agent as an ``AuthenticationEventProvider``.

``authentication_agent.queries.interface.AuthenticationEventProvider`` is the integration target Authentication Investigation Agent documents for
Event Processing & Detection Engine: :meth:`CorpusAuthenticationProvider.get_event` answers exact-ID lookups with
``authentication_agent.models.AuthenticationEvent | None``, and :meth:`CorpusAuthenticationProvider.query` answers a
bounded authentication window with ``authentication_agent.models.QueryResult``. Authentication Investigation Agent owns the meaning of both, so
this adapter calls ``authentication_agent.queries.semantics.check_bounds``, ``matches`` and ``event_order``
instead of restating them: any difference between the two would be an adapter bug, not a
second definition of the contract.

Mapping rules
-------------

* Only ``Security`` events 4624 and 4625 become an ``AuthenticationEvent``. Every other event
  — Sysmon, or another Security event ID — is outside Authentication Investigation Agent's authentication provider contract,
  so ``get_event`` returns ``None`` and ``query`` never offers it. ``None`` also covers a
  malformed ID and a well-formed ID the corpus does not hold: Authentication Investigation Agent's contract has one
  representation for "there is no such authentication event", and Event Processing & Detection Engine's own
  :class:`~event_processing.query.LookupResult` keeps the three cases apart for callers that need them.
* ``event_data`` is copied verbatim, values unchanged, so Authentication Investigation Agent's ``account_of`` fallback to
  ``TargetUserName`` keeps working. ``user`` and ``host`` are passed through untouched: Event Processing & Detection Engine
  never case-folds or strips a domain.
* ``evidence_id``, ``record_id``, ``raw_reference`` and the timestamp are preserved so Evidence Verification & Evaluation can
  re-derive the record independently. ``evidence_id`` already equals
  ``authentication_agent.models.evidence_id_for``, which ``AuthenticationEvent`` re-checks.
* A value Authentication Investigation Agent's model rejects — a host longer than its ``ShortText`` bound, for example —
  raises instead of being trimmed: a truncated identifier is a fabricated one, and silently
  losing it would corrupt Authentication Investigation Agent's entities.
* Read-only: the adapter never mutates the store, and every returned model is built fresh, so
  Authentication Investigation Agent cannot reach Event Processing & Detection Engine's corpus through a returned event.
"""

from __future__ import annotations

from authentication_agent.config import Limits
from authentication_agent.models import AUTH_EVENT_IDS, AuthenticationEvent, QueryRequest, QueryResult
from authentication_agent.queries.semantics import check_bounds, event_order, matches

from event_processing.query import SECURITY_CHANNEL, EventStore
from event_processing.schema import NormalisedEvent


class CorpusAuthenticationProvider:
    """An Authentication Investigation Agent ``AuthenticationEventProvider`` backed by one Event Processing & Detection Engine :class:`EventStore`.

    Pass the same ``Limits`` the investigation runs with: Authentication Investigation Agent builds every request with the
    investigation's own ``max_events_per_query``, and this provider refuses a request that
    exceeds its own bound instead of clamping it.
    """

    def __init__(self, store: EventStore, limits: Limits | None = None) -> None:
        self._store = store
        self._limits = limits or Limits()

    def get_event(self, evidence_id: str) -> AuthenticationEvent | None:
        """Return the authentication view of an exact event, or ``None`` when there is none."""
        found = self._store.lookup(evidence_id)
        if found.status != "found" or found.event is None:
            return None
        return _authentication_event(found.event)

    def query(self, request: QueryRequest) -> QueryResult:
        """Return the authentication events ``request`` selects, in Authentication Investigation Agent's order.

        The scenario's Security 4624/4625 events are pre-selected only to avoid building a
        model for every Sysmon record; ``matches`` remains the sole decision on what the
        request admits, and ``check_bounds`` is Authentication Investigation Agent's own bound check.
        """
        check_bounds(request, self._limits)
        selected = [
            event
            for event in (
                _authentication_event(candidate)
                for candidate in self._store.scenario_events(request.scenario_id)
                if candidate.channel == SECURITY_CHANNEL and candidate.source_event_id in AUTH_EVENT_IDS
            )
            if event is not None and matches(event, request)
        ]
        ordered = sorted(selected, key=event_order)
        return QueryResult(
            events=tuple(ordered[: request.limit]),
            truncated=len(ordered) > request.limit,
        )


def _authentication_event(event: NormalisedEvent) -> AuthenticationEvent | None:
    """Authentication Investigation Agent's authentication view of one normalised event, or ``None`` when it is out of contract."""
    if event.channel != SECURITY_CHANNEL or event.source_event_id not in AUTH_EVENT_IDS:
        return None
    return AuthenticationEvent(
        evidence_id=event.evidence_id,
        scenario_id=event.scenario_id,
        source_type="windows_security",
        channel="Security",
        source_event_id=event.source_event_id,
        record_id=event.record_id,
        timestamp_utc=event.timestamp_utc,
        host=event.host,
        user=event.user,
        event_data=dict(event.event_data),
        raw_reference=event.raw_reference,
    )
