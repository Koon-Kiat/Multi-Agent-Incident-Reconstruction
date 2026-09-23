"""M2's corpus offered to M3 as an ``AuthenticationEventProvider``.

``m3.queries.interface.AuthenticationEventProvider`` is the integration target M3 documents for
M2: :meth:`M2AuthenticationProvider.get_event` answers exact-ID lookups with
``m3.models.AuthenticationEvent | None``, and :meth:`M2AuthenticationProvider.query` answers a
bounded authentication window with ``m3.models.QueryResult``. M3 owns the meaning of both, so
this adapter calls ``m3.queries.semantics.check_bounds``, ``matches`` and ``event_order``
instead of restating them: any difference between the two would be an adapter bug, not a
second definition of the contract.

Mapping rules
-------------

* Every ``Security`` event becomes an ``AuthenticationEvent`` under **exact lookup**, whatever
  its Event ID: M3's own contract fixture requires ``get_event`` to return a Security 4634
  unchanged ("exact lookup retains that Security record"), and ``m3.models.AuthenticationEvent``
  places no Event-ID restriction on the model. A Sysmon event is outside M3's contract and
  returns ``None``. ``None`` also covers a malformed ID and a well-formed ID the corpus does not
  hold: M3's contract has one representation for "there is no such event", and M2's own
  :class:`~m2.query.LookupResult` keeps the three cases apart for callers that need them.
* ``query`` is narrower than ``get_event``: it offers only the ``Security`` events whose Event ID
  the request admits (4624/4625 by default, and ``QueryRequest`` permits no others), because the
  agent tools must see authentication evidence only. The pre-selection is an optimisation; M3's
  ``matches`` remains the sole decision on what the request admits.
* ``event_data`` is copied verbatim, values unchanged, so M3's ``account_of`` fallback to
  ``TargetUserName`` keeps working. ``user`` and ``host`` are passed through untouched: M2
  never case-folds or strips a domain.
* ``evidence_id``, ``record_id``, ``raw_reference`` and the timestamp are preserved so M6 can
  re-derive the record independently. ``evidence_id`` already equals
  ``m3.models.evidence_id_for``, which ``AuthenticationEvent`` re-checks.
* A value M3's model rejects — a host longer than its ``ShortText`` bound, for example —
  raises instead of being trimmed: a truncated identifier is a fabricated one, and silently
  losing it would corrupt M3's entities.
* Read-only: the adapter never mutates the store, and every returned model is built fresh, so
  M3 cannot reach M2's corpus through a returned event.
"""

from __future__ import annotations

from m3.config import Limits
from m3.models import AUTH_EVENT_IDS, AuthenticationEvent, QueryRequest, QueryResult
from m3.queries.semantics import check_bounds, event_order, matches

from m2.query import SECURITY_CHANNEL, EventStore
from m2.schema import NormalisedEvent


class M2AuthenticationProvider:
    """An M3 ``AuthenticationEventProvider`` backed by one M2 :class:`EventStore`.

    Pass the same ``Limits`` the investigation runs with: M3 builds every request with the
    investigation's own ``max_events_per_query``, and this provider refuses a request that
    exceeds its own bound instead of clamping it.
    """

    def __init__(self, store: EventStore, limits: Limits | None = None) -> None:
        self._store = store
        self._limits = limits or Limits()

    def get_event(self, evidence_id: str) -> AuthenticationEvent | None:
        """Return M3's view of an exact event, or ``None`` when there is none.

        Any Security record is preserved, not only 4624/4625: M3's contract fixture looks up a
        Security 4634 and requires it back unchanged. :meth:`query` is the narrower door.
        """
        found = self._store.lookup(evidence_id)
        if found.status != "found" or found.event is None:
            return None
        return _security_event(found.event)

    def query(self, request: QueryRequest) -> QueryResult:
        """Return the authentication events ``request`` selects, in M3's order.

        The scenario's Security 4624/4625 events are pre-selected only to avoid building a
        model for every Sysmon record; ``matches`` remains the sole decision on what the
        request admits, and ``check_bounds`` is M3's own bound check.
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
    """M3's view of one normalised Security event, or ``None`` when it is out of contract.

    The only channel check is M3's own model constraint (``channel == "Security"``); the Event ID
    is deliberately not filtered here, because M3's model and contract accept any Security record
    under exact lookup. :meth:`M2AuthenticationProvider.query` applies the narrower Event-ID
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
