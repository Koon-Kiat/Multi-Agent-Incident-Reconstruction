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

* Every ``Security`` event becomes an ``AuthenticationEvent`` under **exact lookup**, whatever
  its Event ID: Authentication Investigation Agent's own contract fixture requires ``get_event`` to return a Security 4634
  unchanged ("exact lookup retains that Security record"), and ``authentication_agent.models.AuthenticationEvent``
  places no Event-ID restriction on the model. A Sysmon event is outside Authentication Investigation Agent's contract and
  returns ``None``. ``None`` also covers a malformed ID and a well-formed ID the corpus does not
  hold: Authentication Investigation Agent's contract has one representation for "there is no such event", and Event Processing & Detection Engine's own
  :class:`~event_processing.query.LookupResult` keeps the three cases apart for callers that need them.
* ``query`` is narrower than ``get_event``: it offers only the ``Security`` events whose Event ID
  the request admits (4624/4625 by default, and ``QueryRequest`` permits no others), because the
  agent tools must see authentication evidence only. The pre-selection is an optimisation; Authentication Investigation Agent's
  ``matches`` remains the sole decision on what the request admits.
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
        """Return Authentication Investigation Agent's view of an exact event, or ``None`` when there is none.

        Any Security record is preserved, not only 4624/4625: Authentication Investigation Agent's contract fixture looks up a
        Security 4634 and requires it back unchanged. :meth:`query` is the narrower door.
        """
        found = self._store.lookup(evidence_id)
        if found.status != "found" or found.event is None:
            return None
        return _security_event(found.event)

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
                _security_event(candidate)
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


def _security_event(event: NormalisedEvent) -> AuthenticationEvent | None:
    """Authentication Investigation Agent's view of one normalised Security event, or ``None`` when it is out of contract.

    The only channel check is Authentication Investigation Agent's own model constraint (``channel == "Security"``); the Event ID
    is deliberately not filtered here, because Authentication Investigation Agent's model and contract accept any Security record
    under exact lookup. :meth:`CorpusAuthenticationProvider.query` applies the narrower Event-ID
    filter before it calls this.
    """
    if event.channel != SECURITY_CHANNEL:
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
