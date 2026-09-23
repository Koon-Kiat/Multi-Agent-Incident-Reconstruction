"""Boundary between Event Processing & Detection Engine's corpus and the other MAIR members.

``event_processing.adapters`` holds the small, explicit translations Event Processing & Detection Engine offers to a consumer. Nothing in
this package implements another member's logic: each adapter calls that member's own contract
helpers so a divergence here is a bug in the translation, not a second definition.
"""
