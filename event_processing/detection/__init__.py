"""The conventional (non-LLM) detection baseline: schema, rules and engine.

A rule is a pure function over an already ordered tuple of normalised events, so a rule can be
tested on hand-written events without a corpus, and the engine is the only part of the package
that reads a corpus or writes files.
"""
