"""The conventional (non-LLM) detection baseline: schema, rules and engine.

The package is deliberately independent of ``m2.query``: a rule is a pure function over an
already ordered tuple of normalised events, so a rule can be tested on hand-written events
without a corpus, and the engine is the only place that reads a corpus or writes files.
"""
