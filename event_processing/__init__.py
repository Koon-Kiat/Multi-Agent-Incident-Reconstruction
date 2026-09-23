"""Event Processing & Detection Engine data processing and detection.

Turns the original EVTX exports under ``datasets/S0*/raw/`` into a normalised, queryable
event corpus, exposes deterministic read-only lookup/query APIs, and provides the
conventional (non-LLM) rules/statistics detection baseline.

Contract summary (see ``docs/EVENT_*.md`` and AGENTS.md section 3):

* I1 - ``evidence_id`` is scoped by scenario + channel + record: ``S02-SEC-43584``.
* I2 - timestamps keep full 100 ns precision (``timestamp_utc`` string + ``timestamp_ticks``).
* I3 - lookup/query are exact, bounded, deterministic and read-only.
* I4 - every normalised event carries the required fields including a raw reference.
* I5 - both dataset manifest shapes are supported and source hashes are verified.
"""

__all__: list[str] = []
