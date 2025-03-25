from typing import Literal

from safety_schemas.models.events import Event, EventType
from safety_schemas.models.events.payloads import (
    FirewallConfiguredPayload,
    FirewallDisabledPayload,
    PackageInstalledPayload,
    PackageUninstalledPayload,
    CommandExecutedPayload,
    CommandErrorPayload,
    FirewallHeartbeatPayload,
)

from .base import InternalEventType, InternalPayload

CommandExecutedEvent = Event[
    Literal[EventType.COMMAND_EXECUTED], CommandExecutedPayload
]
CommandErrorEvent = Event[Literal[EventType.COMMAND_ERROR], CommandErrorPayload]
PackageInstalledEvent = Event[
    Literal[EventType.PACKAGE_INSTALLED], PackageInstalledPayload
]
PackageUninstalledEvent = Event[
    Literal[EventType.PACKAGE_UNINSTALLED], PackageUninstalledPayload
]
FirewallHeartbeatEvent = Event[
    Literal[EventType.FIREWALL_HEARTBEAT], FirewallHeartbeatPayload
]
FirewallConfiguredEvent = Event[
    Literal[EventType.FIREWALL_CONFIGURED], FirewallConfiguredPayload
]
FirewallDisabledEvent = Event[
    Literal[EventType.FIREWALL_DISABLED], FirewallDisabledPayload
]

# Internal events
CloseResourcesEvent = Event[InternalEventType.CLOSE_RESOURCES, InternalPayload]
FlushSecurityTracesEvent = Event[
    InternalEventType.FLUSH_SECURITY_TRACES, InternalPayload
]
EventBusReadyEvent = Event[Literal[InternalEventType.EVENT_BUS_READY], InternalPayload]
