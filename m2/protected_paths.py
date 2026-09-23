"""Output trees M2 must never write into, shared by every writing command.

Contract
--------

``datasets/`` and ``ground_truth/`` are read-only for M2 (AGENTS.md 2.2): the original evidence
must never be rewritten, and the answer key must never be touched. Every command that writes an
output directory — ``normalise``, ``detect`` and ``score`` — checks its destination here, so the
rule is stated once instead of drifting between three commands.

The check is by **path component name**, not by comparing against this repository's own roots, so
it also refuses a directory named ``datasets`` next to a caller's own evidence. Over-refusal is
harmless; writing into an evidence or answer-key tree is not.
"""

from __future__ import annotations

from pathlib import Path

PROTECTED_OUTPUT_TREE_NAMES = ("datasets", "ground_truth")
_PROTECTED_OUTPUT_PARTS = frozenset(name.casefold() for name in PROTECTED_OUTPUT_TREE_NAMES)


class ProtectedOutputError(ValueError):
    """An output directory resolves into a tree M2 must never write to."""


def protected_output_component(path: Path | str) -> str | None:
    """The protected path component ``path`` resolves through, or ``None`` when it is safe.

    Resolving follows symlinks, so a link into a protected tree is refused as well.
    """
    for part in Path(path).resolve().parts:
        if part.casefold() in _PROTECTED_OUTPUT_PARTS:
            return part
    return None


def refuse_protected_output(path: Path | str) -> None:
    """Raise :class:`ProtectedOutputError` when ``path`` resolves inside a protected tree."""
    component = protected_output_component(path)
    if component is not None:
        readable = " and ".join(f"{name}/" for name in PROTECTED_OUTPUT_TREE_NAMES)
        raise ProtectedOutputError(f"output {path} is inside the {component}/ tree; {readable} are read-only for m2")
