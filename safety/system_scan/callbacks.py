from .scanner import NullCallbacks, Detection, ScanSummary
from .scanner.sinks.streaming.callbacks import (
    NullStreamingCallbacks,
    StreamingSummary,
    StreamingStatus,
    QueuePressure,
)
from .ui.state import ScanState

from .ui.adapters import convert_detection_to_asset
from .ui.models import LogLevel, ConnectionState


STATUS_MAP = {
    StreamingStatus.CONNECTING: ConnectionState.CONNECTING,
    StreamingStatus.STREAMING: ConnectionState.STREAMING,
    StreamingStatus.RECONNECTING: ConnectionState.RECONNECTING,
    StreamingStatus.DISCONNECTED: ConnectionState.DISCONNECTED,
    StreamingStatus.COMPLETE: ConnectionState.COMPLETE,
}


class CliCallbacks(NullCallbacks):
    def __init__(self, state: ScanState, verbose: bool = False):
        self.state = state
        self.verbose = verbose

    def phase(self, phase: str):
        self.state.set_phase(phase)

    def scan_id(self, scan_id: str):
        self.state.scan_id = scan_id

    def detection(self, detection: Detection):
        asset = convert_detection_to_asset(detection)
        self.state.add_asset(asset)

    def warning(self, message: str, path: str = "") -> None:
        self.state.log(LogLevel.WARNING, message)

    def error(self, message: str, exc: Exception) -> None:
        self.state.log(LogLevel.ERROR, message)

    def progress(self, current: int, total: int) -> None:
        self.state.set_progress(current, total)

    def complete(self, summary: ScanSummary) -> None:
        self.state.complete_scan()


class CliSafetyPlatformSinkCallbacks(NullStreamingCallbacks):
    def __init__(self, state: ScanState) -> None:
        super().__init__()
        self.state = state

    def batch_sent(self, count: int) -> None:
        self.state.batch_sent(count)

    def batch_queued(self, current_queue_size: int) -> None:
        self.state.batch_queued(current_queue_size)

    def connection_change(self, status: StreamingStatus) -> None:
        ui_status = STATUS_MAP.get(status, ConnectionState.CONNECTING)
        self.state.set_connection(ui_status)

    def error(self, message: str, exc: Exception) -> None:
        self.state.log(LogLevel.ERROR, f"{message}: {exc}")

    def queue_pressure(
        self, pressure: QueuePressure, current_size: int, max_size: int
    ) -> None:
        self.state.queue_pressure_changed(pressure.value, current_size, max_size)

    def complete(self, summary: StreamingSummary) -> None:
        pass
