"""
Event emission and handling subsystem.

This package is responsible for emitting, routing, and handling telemetry
and security events throughout the Safety CLI. It implements a lightweight
event-bus pattern:

  - ``event_bus/``       — The core event bus (pub/sub) and utilities
  - ``handlers/``        — Event handler implementations (sending to platform)
  - ``types/``           — Event type definitions (internal + external payloads)
  - ``utils/``           — Event creation, emission helpers, and conditions

Events are used for:
  - Telemetry (CLI usage metrics sent to Safety Platform)
  - Security traces (firewall blocks, package installs, diffs)
  - Internal lifecycle (flush, close resources)
"""

from .handlers import EventHandler
from .types import (
    CloseResourcesEvent,
    CommandErrorEvent,
    CommandExecutedEvent,
    FirewallConfiguredEvent,
    FirewallDisabledEvent,
    FirewallHeartbeatEvent,
    FlushSecurityTracesEvent,
    PackageInstalledEvent,
    PackageUninstalledEvent,
)

__all__ = [
    "EventHandler",
    "CloseResourcesEvent",
    "FlushSecurityTracesEvent",
    "CommandExecutedEvent",
    "CommandErrorEvent",
    "PackageInstalledEvent",
    "PackageUninstalledEvent",
    "FirewallHeartbeatEvent",
    "FirewallConfiguredEvent",
    "FirewallDisabledEvent",
]
