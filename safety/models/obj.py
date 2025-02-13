from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from safety.auth.models import Auth
    from rich.console import Console

    from safety_schemas.models import MetadataModel, ReportSchemaVersion, \
      TelemetryModel, PolicyFileModel, ConfigModel

@dataclass
class SafetyCLI:
    """
    A class representing Safety CLI settings.
    """
    auth: Optional['Auth'] = None
    telemetry: Optional['TelemetryModel'] = None
    metadata: Optional['MetadataModel'] = None
    schema: Optional['ReportSchemaVersion'] = None
    project = None
    config: Optional['ConfigModel'] = None
    console: Optional['Console'] = None
    system_scan_policy: Optional['PolicyFileModel'] = None
    platform_enabled: bool = False
    firewall_enabled: bool = False
