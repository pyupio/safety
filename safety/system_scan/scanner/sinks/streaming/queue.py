from __future__ import annotations

import json
import time
import queue
from typing import Any

from .config import BatchConfig
from .callbacks import StreamingCallbacks, QueuePressure, calculate_queue_pressure


class BatchedQueue:
    """
    Single queue. Events in, batches out.

    Flush triggers: max_events, max_bytes, flush_interval
    Backpressure: blocks put() when max_pending_events reached
    """

    def __init__(self, config: BatchConfig, callbacks: StreamingCallbacks):
        self.config = config
        self.callbacks = callbacks

        self._queue: queue.Queue = queue.Queue(maxsize=self.config.max_pending_events)

        self._closed = False
        self._last_pressure = QueuePressure.LOW

    def put(self, event: dict[str, Any]) -> None:
        self._queue.put(event)

        # Notify callbacks about queue changes
        try:
            current_size = self._queue.qsize()
            max_size = self.config.max_pending_events

            # Standard queue size callback
            if self.callbacks.batch_queued:
                self.callbacks.batch_queued(current_size)

            # Pressure level callback
            if self.callbacks.queue_pressure:
                current_pressure = calculate_queue_pressure(current_size, max_size)

                # Only notify if pressure level changed
                if current_pressure != self._last_pressure:
                    self.callbacks.queue_pressure(
                        current_pressure, current_size, max_size
                    )
                    self._last_pressure = current_pressure

        except Exception:
            # Never let callback errors crash the queue
            pass

    def get(self, timeout: float | None = None) -> list[dict[str, Any]] | None:
        """
        Get next batch.

        Returns batch when any trigger fires:
        - max_events reached
        - max_bytes reached
        - flush_interval elapsed (timeout)
        """

        timeout = timeout if timeout is not None else self.config.flush_interval

        batch = []
        batch_bytes = 0

        deadline = time.monotonic()
        deadline += timeout

        while True:
            if len(batch) >= self.config.max_events:
                print("max_events reached")
                break

            if batch_bytes >= self.config.max_bytes:
                print("max_bytes reached")
                break

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print("timeout reached")
                break

            try:
                event = self._queue.get(timeout=remaining)

                batch.append(event)

                batch_bytes += len(json.dumps(event, separators=(",", ":")).encode())

            except queue.Empty:
                break

        # Update pressure after consuming events
        if batch:
            try:
                current_size = self._queue.qsize()
                max_size = self.config.max_pending_events
                current_pressure = calculate_queue_pressure(current_size, max_size)

                # Only notify if pressure level changed
                if current_pressure != self._last_pressure:
                    self.callbacks.queue_pressure(
                        current_pressure, current_size, max_size
                    )
                    self._last_pressure = current_pressure

            except Exception:
                # Never let callback errors crash the queue
                pass

        return batch if batch else None

    def close(self) -> None:
        self._closed = True

    def is_closed(self) -> bool:
        return self._closed

    def is_drained(self) -> bool:
        return self._closed and self._queue.empty()
