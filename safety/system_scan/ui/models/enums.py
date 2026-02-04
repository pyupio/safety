from enum import Enum


class ConnectionState(Enum):
    """
    Server connection states.
    """

    CONNECTING = "connecting"
    STREAMING = "streaming"
    PAUSED = "paused"
    RECONNECTING = "reconnecting"
    DISCONNECTED = "disconnected"
    COMPLETE = "complete"


class AssetKind(Enum):
    """
    Asset type categories.
    """

    CONTEXT = "context"
    RUNTIME = "runtime"
    ENVIRONMENT = "environment"
    DEPENDENCY = "dependency"
    TOOL = "tool"


class LogLevel(Enum):
    """
    Log entry severity levels.
    """

    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


# Symbol and color mappings
ASSET_STYLES: dict[AssetKind, tuple[str, str]] = {
    AssetKind.CONTEXT: ("◇", "dim"),
    AssetKind.RUNTIME: ("◆", "blue"),
    AssetKind.ENVIRONMENT: ("○", "yellow"),
    AssetKind.DEPENDENCY: ("■", "cyan"),
    AssetKind.TOOL: ("●", "cyan"),
}

LOG_STYLES: dict[LogLevel, tuple[str, str]] = {
    LogLevel.INFO: ("·", "dim"),
    LogLevel.SUCCESS: ("✓", "green"),
    LogLevel.WARNING: ("!", "yellow"),
    LogLevel.ERROR: ("✗", "red"),
}

CONNECTION_STYLES: dict[ConnectionState, tuple[str, str]] = {
    ConnectionState.CONNECTING: ("○ Connecting", "yellow"),
    ConnectionState.STREAMING: ("● Streaming", "green"),
    ConnectionState.PAUSED: ("● Paused", "yellow"),
    ConnectionState.RECONNECTING: ("○ Reconnecting", "yellow"),
    ConnectionState.DISCONNECTED: ("○ Disconnected", "red"),
    ConnectionState.COMPLETE: ("✓ Complete", "green"),
}
