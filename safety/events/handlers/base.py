"""
Event handler definitions for the event bus system.
"""

from abc import ABC, abstractmethod
from typing import Any, TypeVar, Generic

from safety_schemas.models.events import Event

# Type variable for event types
EventType = TypeVar("EventType", bound=Event)


class EventHandler(Generic[EventType], ABC):
    """
    Abstract base class for event handlers.

    Concrete handlers should implement the handle method.
    """

    @abstractmethod
    async def handle(self, event: EventType) -> Any:
        """
        Handle an event asynchronously.

        Args:
            event: The event to handle

        Returns:
            Any result from handling the event
        """
        pass
