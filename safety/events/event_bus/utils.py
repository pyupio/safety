from typing import TYPE_CHECKING
from .bus import EventBus

from safety_schemas.models.events import EventType
from safety.events.types import InternalEventType
from safety.events.handlers import SecurityEventsHandler

from safety.constants import PLATFORM_API_EVENTS_ENDPOINT

if TYPE_CHECKING:
    from safety.models import SafetyCLI
    from safety.auth.utils import SafetyAuthSession


def start_event_bus(obj: "SafetyCLI", session: "SafetyAuthSession"):
    """
    Initializes the event bus with the default security events handler
    for authenticated users.
    This function creates an instance of the EventBus, starts it,
    and assigns it to the `event_bus` attribute of the provided `obj`.
    It also initializes the `security_events_handler` with the necessary
    parameters and subscribes it to a predefined list of events.

    Args:
        obj (SafetyCLI): The main application object.
        session (SafetyAuthSession): The authentication session containing
                                     the necessary credentials and proxies.

    """
    event_bus = EventBus()
    event_bus.start()
    obj.event_bus = event_bus

    token = session.token.get("access_token") if session.token else None

    obj.security_events_handler = SecurityEventsHandler(
        api_endpoint=PLATFORM_API_EVENTS_ENDPOINT,
        proxies=session.proxies,  # type: ignore
        auth_token=token,
        api_key=session.api_key,
    )

    events = [
        EventType.AUTH_STARTED,
        EventType.AUTH_COMPLETED,
        EventType.COMMAND_EXECUTED,
        EventType.COMMAND_ERROR,
        InternalEventType.CLOSE_RESOURCES,
        InternalEventType.FLUSH_SECURITY_TRACES,
    ]

    event_bus.subscribe(events, obj.security_events_handler)

    if obj.firewall_enabled:
        from safety.firewall.events.utils import register_event_handlers

        register_event_handlers(obj.event_bus, obj=obj)
