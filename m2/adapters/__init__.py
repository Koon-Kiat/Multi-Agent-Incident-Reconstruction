"""Boundary between M2's corpus and the other MAIR members.

``m2.adapters`` holds the small, explicit translations M2 offers to a consumer. Nothing in
this package implements another member's logic: each adapter calls that member's own contract
helpers so a divergence here is a bug in the translation, not a second definition.
"""
