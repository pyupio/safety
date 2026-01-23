from dataclasses import dataclass
from typing import Protocol

from .models import Detection


@dataclass
class ScanSummary:
    total_detections: int


class Callbacks(Protocol):
    def phase(self, phase: str) -> None: ...
    def scan_id(self, scan_id: str) -> None: ...
    def detection(self, detection: Detection) -> None: ...
    def warning(self, message: str, path: str = "") -> None: ...
    def error(self, message: str, exc: Exception) -> None: ...
    def progress(self, current: int, total: int) -> None: ...
    def complete(self, summary: ScanSummary) -> None: ...


class NullCallbacks:
    def phase(self, phase: str) -> None:
        pass

    def scan_id(self, scan_id: str) -> None:
        pass

    def detection(self, detection: Detection) -> None:
        pass

    def warning(self, message: str, path: str = "") -> None:
        pass

    def error(self, message: str, exc: Exception) -> None:
        pass

    def progress(self, current: int, total: int) -> None:
        pass

    def complete(self, summary: ScanSummary) -> None:
        pass
