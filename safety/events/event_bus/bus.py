"""
Core EventBus implementation.
"""

import asyncio
import queue
import threading
import time
import logging
from concurrent.futures import Future
from typing import Dict, List, Any, Optional, Callable, TypeVar
from dataclasses import dataclass, field

from ..handlers import EventHandler

from safety_schemas.models.events import Event, EventTypeBase, PayloadBase


@dataclass
class EventBusMetrics:
    """
    Metrics for the event bus.
    """

    events_emitted: int = 0
    events_processed: int = 0
    events_failed: int = 0
    queue_high_water_mark: int = 0
    handler_durations: Dict[str, List[float]] = field(default_factory=dict)


E = TypeVar("E", bound=Event)

# Define bounded type variables
EventTypeT = TypeVar("EventTypeT", bound=EventTypeBase)
PayloadT = TypeVar("PayloadT", bound=PayloadBase)


class EventBus:
    """
    Event bus that runs in a separate thread with its own asyncio event loop.

    This class manages event subscription and dispatching across threads.

    This is an approach to leverage asyncio without migrating current codebase
    to async.
    """

    def __init__(self, max_queue_size: int = 1000):
        """
        Initialize the event bus.

        Args:
            max_queue_size: Maximum number of events that can be queued
        """
        self._handlers: Dict[EventTypeBase, List[EventHandler[Any]]] = {}

        # Queue for passing events from main thread to event bus thread
        self._event_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)

        # Thread management
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._shutdown_event = threading.Event()

        # Setup logging
        self.logger = logging.getLogger("event_bus")

        # Metrics
        self.metrics = EventBusMetrics()

    def subscribe(
        self, event_types: List[EventTypeBase], handler: EventHandler[E]
    ) -> None:
        """
        Subscribe a handler to one or more event types.

        Args:
            event_types: The list of event types to subscribe to
            handler: The handler to register
        """
        for event_type in event_types:
            if event_type not in self._handlers:
                self._handlers[event_type] = []

            self.logger.info(
                f"Registering handler {handler.__class__.__name__} "
                f"for event type {event_type}"
            )
            self._handlers[event_type].append(handler)

    def emit(
        self,
        event: Event[EventTypeT, PayloadT],
        block: bool = False,
        timeout: Optional[float] = None,
    ) -> Optional[Future]:
        """
        Emit an event to be processed by the event bus.

        Args:
            event: The event to emit
            block: Whether to block if the queue is full
            timeout: How long to wait if blocking

        Returns:
            Future that will contain the results, or None if the event couldn't be queued
        """
        if not self._running:
            self.logger.warning("Event bus is not running, but an event was emitted")

        self.metrics.events_emitted += 1

        # Create a future to track the results
        future = Future()

        try:
            # Track queue size for metrics
            current_size = self._event_queue.qsize()
            self.metrics.queue_high_water_mark = max(
                current_size, self.metrics.queue_high_water_mark
            )

            # Put the event in the queue
            self._event_queue.put((event, future), block=block, timeout=timeout)
            self.logger.debug("Emitted %s (%s)", event.type, event.id)
            return future

        except queue.Full:
            self.logger.error(f"Event queue is full, dropping event: {event}")
            future.set_exception(RuntimeError("Event queue is full"))
            return future

    def start(self):
        if self._running:
            return

        self._running = True
        self._shutdown_event.clear()
        self._thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        if not self._running:
            return True

        self._running = False
        self._event_queue.put((None, None), block=False)  # Send sentinel
        return self._shutdown_event.wait(timeout)

    def _run_event_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def main():
            pending_tasks = set()

            # Process the queue until shutdown
            while self._running or not self._event_queue.empty():
                try:
                    # Get the next event with a short timeout
                    try:
                        event, future = self._event_queue.get(timeout=0.1)
                    except queue.Empty:
                        await asyncio.sleep(0.01)
                        continue

                    # Check for shutdown sentinel
                    if event is None:
                        self.logger.info("Received shutdown sentinel")
                        break

                    # Process the event
                    task = asyncio.create_task(self._dispatch_event(event, future))
                    self.logger.debug(f"Dispatching {event.type} ({event.id})")
                    pending_tasks.add(task)
                    task.add_done_callback(lambda t: pending_tasks.discard(t))
                except Exception as e:
                    self.logger.exception(f"Error processing event: {e}")

            # Wait for any pending tasks before exiting
            if pending_tasks:
                self.logger.info(f"Waiting for {len(pending_tasks)} pending tasks")
                await asyncio.gather(*pending_tasks, return_exceptions=True)

        try:
            # Single run_until_complete call for the entire lifecycle
            self._loop.run_until_complete(main())
        finally:
            self._loop.close()
            self._shutdown_event.set()

    async def _dispatch_event(
        self, event: Event[EventTypeBase, PayloadBase], future: Future
    ) -> None:
        """
        Dispatch an event to all registered handlers.

        Args:
            event: The event to dispatch
            future: Future to set with the results
        """
        results = []

        handlers = self._handlers.get(event.type, [])

        if not handlers:
            self.logger.warning(f"No handlers registered for event type {event.type}")
            future.set_result([])
            return

        # Create tasks for all handlers and run them concurrently
        tasks = []
        for handler in handlers:
            task = asyncio.create_task(self._handle_event(handler, event))
            tasks.append(task)

        trace_id = event.correlation_id if event.correlation_id else "-"

        self.logger.debug(
            "Event %s | %s | %s Handler(s) Task(s)", trace_id, event.type, len(tasks)
        )

        # Wait for all handlers to complete
        handler_results = await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.info(
            "Event %s | %s | %s Handler(s) Completed",
            trace_id,
            event.type,
            len(handler_results),
        )

        # Process results
        for i, result in enumerate(handler_results):
            if isinstance(result, Exception):
                self.logger.error(
                    "Event %s | %s | Handler %d failed: %s",
                    trace_id,
                    event.type,
                    i,
                    str(result),
                    exc_info=result,
                )
            else:
                self.logger.debug(
                    "Event %s | %s | Handler %d succeeded: %s",
                    trace_id,
                    event.type,
                    i,
                    str(result),
                )
                results.append(result)

        # Set the result on the future
        if not future.done():
            future.set_result(results)

    async def _handle_event(self, handler: EventHandler[E], event: E) -> Any:
        """
        Handle a single event with error handling and metrics.

        Args:
            handler: The handler to use
            event: The event to handle

        Returns:
            The result from the handler
        """
        handler_name = handler.__class__.__name__
        start_time = time.time()

        try:
            # Call the handler
            result = await handler.handle(event)

            # Record successful processing
            self.metrics.events_processed += 1

            # Record timing
            duration = time.time() - start_time
            if handler_name not in self.metrics.handler_durations:
                self.metrics.handler_durations[handler_name] = []
            self.metrics.handler_durations[handler_name].append(duration)

            self.logger.debug(
                f"Handler {handler_name} processed {event.__class__.__name__} "
                f"in {duration:.3f}s"
            )

            return result

        except Exception as e:
            # Record failure
            self.metrics.events_failed += 1

            self.logger.exception(
                f"Handler {handler_name} failed to process {event.__class__.__name__}: {e}"
            )
            raise

    def get_metrics(self) -> dict:
        """
        Get the current metrics for the event bus.

        Returns:
            Dictionary of metrics
        """
        metrics: dict[str, Any] = {
            "events_emitted": self.metrics.events_emitted,
            "events_processed": self.metrics.events_processed,
            "events_failed": self.metrics.events_failed,
            "current_queue_size": self._event_queue.qsize(),
            "queue_high_water_mark": self.metrics.queue_high_water_mark,
        }

        # Add handler metrics
        handler_metrics = {}
        for handler_name, durations in self.metrics.handler_durations.items():
            if not durations:
                continue

            handler_metrics[handler_name] = {
                "count": len(durations),
                "avg_duration": sum(durations) / len(durations),
                "max_duration": max(durations),
                "min_duration": min(durations),
            }

        metrics["handlers"] = handler_metrics
        return metrics

    def emit_with_callback(
        self, event: Event, callback: Callable[[List[Any]], None]
    ) -> None:
        """
        Emit an event and register a callback for when it completes.

        Args:
            event: The event to emit
            callback: Function to call with the results when complete
        """
        future = self.emit(event)
        if future:
            future.add_done_callback(
                lambda f: callback(f.result()) if not f.exception() else None
            )
