from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from rich.console import Console
    from safety_schemas.models import (
        ConfigModel,
        MetadataModel,
        PolicyFileModel,
        ReportSchemaVersion,
        TelemetryModel,
    )

    from safety.auth.models import Auth
    from safety.events.handlers import SecurityEventsHandler
    from safety.events.event_bus import EventBus
    from safety_schemas.models.events import Event


@dataclass
class SafetyCLI:
    """
    A class representing Safety CLI settings.
    """

    auth: Optional["Auth"] = None
    telemetry: Optional["TelemetryModel"] = None
    metadata: Optional["MetadataModel"] = None
    schema: Optional["ReportSchemaVersion"] = None
    project = None
    config: Optional["ConfigModel"] = None
    console: Optional["Console"] = None
    system_scan_policy: Optional["PolicyFileModel"] = None
    platform_enabled: bool = False
    firewall_enabled: bool = False
    events_enabled: bool = False
    event_bus: Optional["EventBus"] = None
    security_events_handler: Optional["SecurityEventsHandler"] = None
    correlation_id: Optional[str] = None
    pending_events: List["Event"] = field(default_factory=list)
