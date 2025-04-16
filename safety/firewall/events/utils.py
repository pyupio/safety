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
                EventType.PACKAGE_INSTALLED,
                EventType.PACKAGE_UNINSTALLED,
                EventType.PACKAGE_UPDATED,
                EventType.TOOL_COMMAND_EXECUTED,
                EventType.INIT_STARTED,
                EventType.FIREWALL_SETUP_RESPONSE_CREATED,
                EventType.FIREWALL_SETUP_COMPLETED,
                EventType.CODEBASE_DETECTION_STATUS,
                EventType.CODEBASE_SETUP_RESPONSE_CREATED,
                EventType.CODEBASE_SETUP_COMPLETED,
                EventType.INIT_SCAN_COMPLETED,
                EventType.INIT_EXITED,
            ],
            sec_events_handler,
        )
