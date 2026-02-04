from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from typing import TYPE_CHECKING

from .config import SenderConfig
from .http import EventSender
from .queue import BatchedQueue
from .callbacks import StreamingCallbacks, StreamingStatus

if TYPE_CHECKING:
    import httpx
    from authlib.integrations.httpx_client import OAuth2Client


class StreamingSender:
    """
    Handles streaming scan events without Optional types.
    Should be created via StreamingContext context manager.
    """

    def __init__(self, sender: EventSender, queue: BatchedQueue):
        self.sender = sender
        self.queue = queue
        self.scan_ref: str | None = None

    def create_scan(self, metadata: dict[str, Any] | None = None) -> str:
        self.scan_ref = self.sender.create_scan(metadata)
        return self.scan_ref

    def send(self, event: dict[str, Any]) -> None:
        """
        Called by detection code.

        Uses BatchedQueue.put() which:
        - Adds event to queue
        - Blocks if 500 events pending (backpressure)
        """
        self.queue.put(event)

    def finish(self, summary: dict[str, Any] | None = None) -> None:
        if not self.scan_ref:
            raise RuntimeError("No active scan to finish")

        # Signal no more events
        self.queue.close()

        # Wait for workers to drain queue
        while not self.queue.is_drained():
            time.sleep(0.1)


class StreamingContext:
    """
    Context manager that handles initialization and cleanup of streaming resources.
    Returns a StreamingSender for actual operations.
    """

    def __init__(
        self,
        config: SenderConfig,
        http_client: httpx.Client | OAuth2Client,
        callbacks: StreamingCallbacks,
    ):
        self.config = config
        self._http_client = http_client
        self.callbacks = callbacks
        self._sender: EventSender | None = None
        self._queue: BatchedQueue | None = None
        self._pool: ThreadPoolExecutor | None = None
        self._error: Exception | None = None
        self._streaming_sender: StreamingSender | None = None

    def __enter__(self) -> StreamingSender:
        # Notify connection starting
        self._notify_connection(StreamingStatus.CONNECTING)

        # HTTP client for sending batches
        self._sender = EventSender(
            self.config.base_url,
            http_client=self._http_client,
            timeout=self.config.timeout,
        )
        self._sender.__enter__()

        # Create BatchedQueue with config and callbacks
        self._queue = BatchedQueue(self.config.batch, self.callbacks)

        # Thread pool for workers
        self._pool = ThreadPoolExecutor(max_workers=self.config.workers)

        # Create StreamingSender with initialized resources
        self._streaming_sender = StreamingSender(self._sender, self._queue)

        # Start workers - they pull from BatchedQueue
        for _ in range(self.config.workers):
            self._pool.submit(self._worker)

        # Notify streaming started
        self._notify_connection(StreamingStatus.STREAMING)

        return self._streaming_sender

    def __exit__(self, *exc):
        # Signal queue closed - workers will drain and exit
        if self._queue:
            self._queue.close()

        # Wait for workers to finish
        if self._pool:
            self._pool.shutdown(wait=True)

        # Close HTTP client
        if self._sender:
            self._sender.__exit__(*exc)

        # Notify completion
        self._notify_connection(StreamingStatus.COMPLETE)

        # Propagate any worker error
        if self._error:
            raise self._error

    def _worker(self) -> None:
        """
        Runs in thread pool.

        Uses BatchedQueue.get() which:
        - Returns batch of up to 100 events
        - Or when 500KB reached
        - Or after 2s timeout
        """
        # These are guaranteed non-None after __enter__
        assert self._queue is not None
        assert self._sender is not None
        assert self._streaming_sender is not None

        while not self._queue.is_drained():
            batch = self._queue.get()

            if batch:
                if not self._streaming_sender.scan_ref:
                    self._error = RuntimeError("No scan created before sending events")
                    return
                try:
                    self._sender.send_batch(self._streaming_sender.scan_ref, batch)

                    # Notify successful batch send
                    self.callbacks.batch_sent(len(batch))

                except ConnectionError as e:
                    # Connection errors - notify and set error
                    self._notify_connection(StreamingStatus.RECONNECTING)
                    self.callbacks.error("Connection lost during batch send", e)
                    self._error = e
                    return
                except Exception as e:
                    # Other errors - notify and set error
                    self.callbacks.error(f"Batch send failed: {e}", e)
                    self._error = e
                    return

    def _notify_connection(self, status: StreamingStatus) -> None:
        """
        Notify connection status change.
        """
        self.callbacks.connection_change(status)
