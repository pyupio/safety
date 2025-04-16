from typing import Literal

from safety_schemas.models.events import Event, EventType
from safety_schemas.models.events.payloads import (
    AuthCompletedPayload,
    AuthStartedPayload,
    CodebaseSetupCompletedPayload,
    CodebaseSetupResponseCreatedPayload,
    FirewallConfiguredPayload,
    FirewallDisabledPayload,
    FirewallSetupCompletedPayload,
    FirewallSetupResponseCreatedPayload,
    InitScanCompletedPayload,
    InitStartedPayload,
    PackageInstalledPayload,
    PackageUninstalledPayload,
    CommandExecutedPayload,
    CommandErrorPayload,
    FirewallHeartbeatPayload,
    CodebaseDetectionStatusPayload,
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


InitStartedEvent = Event[Literal[EventType.INIT_STARTED], InitStartedPayload]
AuthStartedEvent = Event[Literal[EventType.AUTH_STARTED], AuthStartedPayload]
AuthCompletedEvent = Event[Literal[EventType.AUTH_COMPLETED], AuthCompletedPayload]

# Firewall setup events
FirewallSetupResponseCreatedEvent = Event[
    Literal[EventType.FIREWALL_SETUP_RESPONSE_CREATED],
    FirewallSetupResponseCreatedPayload,
]
FirewallSetupCompletedEvent = Event[
    Literal[EventType.FIREWALL_SETUP_COMPLETED], FirewallSetupCompletedPayload
]

# Codebase setup events
CodebaseDetectionStatusEvent = Event[
    Literal[EventType.CODEBASE_DETECTION_STATUS], CodebaseDetectionStatusPayload
]
CodebaseSetupResponseCreatedEvent = Event[
    Literal[EventType.CODEBASE_SETUP_RESPONSE_CREATED],
    CodebaseSetupResponseCreatedPayload,
]
CodebaseSetupCompletedEvent = Event[
    Literal[EventType.CODEBASE_SETUP_COMPLETED], CodebaseSetupCompletedPayload
]

# Scan events
InitScanCompletedEvent = Event[
    Literal[EventType.INIT_SCAN_COMPLETED], InitScanCompletedPayload
]

# Internal events
CloseResourcesEvent = Event[InternalEventType.CLOSE_RESOURCES, InternalPayload]
FlushSecurityTracesEvent = Event[
    InternalEventType.FLUSH_SECURITY_TRACES, InternalPayload
]
EventBusReadyEvent = Event[Literal[InternalEventType.EVENT_BUS_READY], InternalPayload]
