from __future__ import annotations

from typing import Any

from .base import Sink


from .streaming import StreamingContext, SenderConfig, StreamingCallbacks
from ..events import build_discovered_event, build_system_scan_event, SystemScanAction


class SafetyPlatformSink(Sink):
    """
    Consumes single events (streaming).
    Internally batches + backpressures using your BatchedQueue + workers.
    """

    name = "safety_platform"

    def __init__(
        self,
        sender_config: SenderConfig,
        http_client: Any,
        callbacks: StreamingCallbacks,
    ):
        self.sender_config = sender_config
        self.http_client = http_client
        self.callbacks = callbacks

        self._ctx_mgr = None
        self._sender = None
        self.scan_id: str | None = None

    def open(self, machine_id: str, hostname: str) -> str:
        self._ctx_mgr = StreamingContext(
            self.sender_config, self.http_client, self.callbacks
        )
        self._sender = self._ctx_mgr.__enter__()

        self.scan_id = self._sender.create_scan(
            metadata={
                "subtype": "HOST",
                "machine_id": machine_id,
                "hostname": hostname,
            }
        )

        return self.scan_id

    def write(self, item) -> None:
        assert self._sender is not None
        assert self.scan_id is not None

        event = build_discovered_event(item, self.scan_id)
        self._sender.send(event)

    def close(self, ok: bool) -> None:
        if not self._sender or not self._ctx_mgr or not self.scan_id:
            return

        # send final scan event
        self._sender.send(
            build_system_scan_event(
                self.scan_id,
                SystemScanAction.SUCCEEDED if ok else SystemScanAction.FAILED,
            )
        )
        self._sender.finish()
        self._ctx_mgr.__exit__(None, None, None)
