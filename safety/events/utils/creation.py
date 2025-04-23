import time
from typing import Optional, TypeVar

from safety_schemas.models.events import Event, EventTypeBase, PayloadBase, SourceType

from safety.meta import get_identifier

from ..types import InternalEventType, InternalPayload

PayloadBaseT = TypeVar("PayloadBaseT", bound=PayloadBase)
EventTypeBaseT = TypeVar("EventTypeBaseT", bound=EventTypeBase)


def create_event(
    payload: PayloadBaseT,
    event_type: EventTypeBaseT,
    source: SourceType = SourceType(get_identifier()),
    timestamp: int = int(time.time()),
    correlation_id: Optional[str] = None,
    **kwargs,
) -> Event[EventTypeBaseT, PayloadBaseT]:
    """
    Generic factory function for creating any type of event.
    """

    return Event(
        timestamp=timestamp,
        payload=payload,
        type=event_type,
        source=source,
        correlation_id=correlation_id,
        **kwargs,
    )


def create_internal_event(
    event_type: InternalEventType,
    payload: InternalPayload,
) -> Event[InternalEventType, InternalPayload]:
    """
    Create an internal event.
    """
    return Event(
        type=event_type,
        timestamp=int(time.time()),
        source=SourceType(get_identifier()),
        payload=payload,
    )
