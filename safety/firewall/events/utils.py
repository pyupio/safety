from typing import TYPE_CHECKING

from safety_schemas.models.events import EventType
from safety.events.event_bus import EventBus
from safety.events.types import InternalEventType

from .handlers import HeartbeatInspectionEventHandler

if TYPE_CHECKING:
    from safety.models import SafetyCLI


def register_event_handlers(event_bus: "EventBus", obj: "SafetyCLI") -> None:
    """
    Subscribes to the firewall events that are relevant to the current context.
    """
    handle_inspection = HeartbeatInspectionEventHandler(event_bus=event_bus)
    event_bus.subscribe([InternalEventType.EVENT_BUS_READY], handle_inspection)

    if sec_events_handler := obj.security_events_handler:
        event_bus.subscribe(
            [
                EventType.FIREWALL_CONFIGURED,
                EventType.FIREWALL_HEARTBEAT,
                EventType.FIREWALL_DISABLED,
            ],
            sec_events_handler,
        )
