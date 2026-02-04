from __future__ import annotations

from abc import ABC, abstractmethod

from rich.console import Console
from rich.text import Text

from ..state import ScanState


class BaseComponent(ABC):
    """
    Base class for TUI components.
    """

    def __init__(self, state: ScanState, console: Console | None = None):
        self.state = state
        self.console = console or Console()

    @property
    def width(self) -> int:
        return min(self.console.width - 4, 120)  # Cap at 120 for modern terminals

    @abstractmethod
    def render(self) -> Text:
        pass
