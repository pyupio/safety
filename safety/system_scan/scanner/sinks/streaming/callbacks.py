"""Callback interface for streaming events."""

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class StreamingStatus(Enum):
    """Connection status for streaming operations."""

    CONNECTING = "connecting"
    STREAMING = "streaming"
    RECONNECTING = "reconnecting"
    DISCONNECTED = "disconnected"
    COMPLETE = "complete"


class QueuePressure(Enum):
    """Queue pressure levels for UI indication."""

    LOW = "low"  # 0-30% full
    MEDIUM = "medium"  # 30-70% full
    HIGH = "high"  # 70-90% full
    CRITICAL = "critical"  # 90%+ full


@dataclass
class StreamingSummary:
    total_batches_sent: int
    total_events_sent: int
    connection_duration_seconds: float
    reconnection_count: int = 0
    errors: int = 0
    queue_pressure_events: int = 0


class StreamingCallbacks(Protocol):
    def batch_sent(self, count: int) -> None: ...
    def batch_queued(self, current_queue_size: int) -> None: ...
    def connection_change(self, status: StreamingStatus) -> None: ...
    def error(self, message: str, exc: Exception) -> None: ...
    def queue_pressure(
        self, pressure: QueuePressure, current_size: int, max_size: int
    ) -> None: ...
    def complete(self, summary: StreamingSummary) -> None: ...


class NullStreamingCallbacks:
    def batch_sent(self, count: int) -> None:
        pass

    def batch_queued(self, current_queue_size: int) -> None:
        pass

    def connection_change(self, status: StreamingStatus) -> None:
        pass

    def error(self, message: str, exc: Exception) -> None:
        pass

    def queue_pressure(
        self, pressure: QueuePressure, current_size: int, max_size: int
    ) -> None:
        pass

    def complete(self, summary: StreamingSummary) -> None:
        pass


def calculate_queue_pressure(current_size: int, max_size: int) -> QueuePressure:
    """Calculate queue pressure level based on fill percentage."""
    if max_size == 0:
        return QueuePressure.LOW

    fill_percentage = (current_size / max_size) * 100

    if fill_percentage >= 90:
        return QueuePressure.CRITICAL
    elif fill_percentage >= 70:
        return QueuePressure.HIGH
    elif fill_percentage >= 30:
        return QueuePressure.MEDIUM
    else:
        return QueuePressure.LOW
