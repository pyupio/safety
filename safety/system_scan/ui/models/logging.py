from dataclasses import dataclass
from datetime import timedelta

from .enums import LogLevel


@dataclass
class LogEntry:
    """Represents a log message."""

    level: LogLevel
    message: str
    elapsed: timedelta
