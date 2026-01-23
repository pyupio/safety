from __future__ import annotations

from dataclasses import dataclass

from .enums import AssetKind


@dataclass
class Asset:
    """
    Represents a discovered asset in the UI.
    """

    kind: AssetKind
    subtype: str
    path: str
    linked_runtime: str | None = None
