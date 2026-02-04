from .base import Sink
from ..models import Detection


class NullSink(Sink[Detection]):
    name = "null"

    def open(self, machine_id: str, hostname: str) -> str:
        return "null-scan-id"

    def write(self, item: Detection) -> None: ...
    def close(self, ok: bool) -> None: ...
