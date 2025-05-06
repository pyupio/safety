import asyncio
import functools
import logging
import os
import sys
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union
import uuid

import httpx
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
import tenacity

from safety.meta import get_identifier, get_meta_http_headers, get_version

from ..types import (
    CommandErrorEvent,
    CommandExecutedEvent,
    CloseResourcesEvent,
    InternalEventType,
    FlushSecurityTracesEvent,
)
from ..handlers import EventHandler

if TYPE_CHECKING:
    from safety_schemas.models.events import EventContext
    from safety.events.utils import InternalPayload
    from safety.models import SafetyCLI

SecurityEventTypes = Union[
    CommandExecutedEvent,
    CommandErrorEvent,
    FlushSecurityTracesEvent,
    CloseResourcesEvent,
]


class SecurityEventsHandler(EventHandler[SecurityEventTypes]):
    """
    Handler that collects events in memory and flushes them when requested.
    """

    def __init__(
        self,
        api_endpoint: str,
        proxies: Optional[Dict[str, str]] = None,
        auth_token: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        """
        Initialize the telemetry handler.

        Args:
            api_endpoint: URL to send events to
            proxies: Optional dictionary of proxy settings
            auth_token: Optional authentication token for the API
            api_key: Optional API key for authentication
        """
        self.api_endpoint = api_endpoint
        self.proxies = proxies
        self.auth_token = auth_token
        self.api_key = api_key

        # Storage for collected events
        self.collected_events: List[Dict[str, Any]] = []

        # HTTP client (created when needed)
        self.http_client = None

        # Logging
        self.logger = logging.getLogger("security_events_handler")

        # Event types that should not be collected (to avoid recursion)
        self.excluded_event_types = [
            InternalEventType.FLUSH_SECURITY_TRACES,
        ]

    async def handle(self, event: SecurityEventTypes) -> Dict[str, Any]:
        """
        Handle an event - either collect it or process a flush request.

        Args:
            event: The event to handle

        Returns:
            Status dictionary
        """

        if event.type is InternalEventType.CLOSE_RESOURCES:
            self.logger.info("Received request to close resources")
            await self.close_async()
            return {"closed": True}

        if event.type is InternalEventType.FLUSH_SECURITY_TRACES:
            self.logger.info(f"Received flush request from {event.source}")
            return await self.flush(event_payload=event.payload)

        # Don't collect excluded event types
        if any(event == t for t in self.excluded_event_types):
            return {"skipped": True, "reason": "excluded_event_type"}

        try:
            event_data = event.model_dump(mode="json")
        except Exception:
            return {"collected": False, "event_count": len(self.collected_events)}

        # Add to in-memory collection
        self.collected_events.append(event_data)
        event_count = len(self.collected_events)

        self.logger.debug(
            f"Collected event: {event.type}, total event count: {event_count}"
        )

        return {"collected": True, "event_count": event_count}

    async def _build_context_data(self, obj: Optional["SafetyCLI"]) -> "EventContext":
        """
        Generate context data for telemetry events.

        Returns:
            Dict containing context information about client, runtime, etc.
        """
        from safety_schemas.models.events.types import SourceType
        from safety.events.utils.context import create_event_context

        project = getattr(obj, "project", None)
        tags = None
        try:
            if obj and obj.auth and obj.auth.stage:
                tags = [obj.auth.stage.value]
        except AttributeError:
            pass

        version = get_version() or "unknown"

        path = ""
        try:
            path = sys.argv[0]
        except (IndexError, TypeError):
            pass

        context = await asyncio.get_event_loop().run_in_executor(
            None,
            functools.partial(
                create_event_context,
                SourceType(get_identifier()),
                version,
                path,
                project,
                tags,
            ),
        )

        return context

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.1, min=0.2, max=1.0),
        retry=retry_if_exception_type(
            (httpx.NetworkError, httpx.TimeoutException, httpx.HTTPStatusError)
        ),
        before_sleep=before_sleep_log(logging.getLogger("api_client"), logging.WARNING),
    )
    async def _send_events(
        self, payload: dict, headers: dict
    ) -> Optional[httpx.Response]:
        """
        Send events to the API with retry logic.

        Args:
            payload: The data payload to send
            headers: The HTTP headers to include

        Returns:
            Response from the API or None if http_client is not initialized

        Raises:
            Exception if all retries fail
        """
        if self.http_client is None:
            self.logger.warning("Cannot send events: HTTP client not initialized")
            return None

        TIMEOUT = int(os.getenv("SAFETY_REQUEST_TIMEOUT_EVENTS", 10))

        response = await self.http_client.post(
            self.api_endpoint, json=payload, headers=headers, timeout=TIMEOUT
        )
        response.raise_for_status()
        return response

    async def flush(self, event_payload: "InternalPayload") -> Dict[str, Any]:
        """
        Send all collected events to the API endpoint.

        Returns:
            Status dictionary
        """
        # If no events, just return early
        if not self.collected_events:
            return {"status": "no_events", "count": 0}

        # Get a copy of events and clear the original list
        events_to_send = self.collected_events.copy()
        self.collected_events.clear()

        event_count = len(events_to_send)
        self.logger.info(
            "[Flush] -> Sending %s events to %s", event_count, self.api_endpoint
        )
        IDEMPOTENCY_KEY = str(uuid.uuid4())

        # Get context data that will be shared across all events
        obj = event_payload.ctx.obj if event_payload.ctx else None
        context = await self._build_context_data(obj=obj)
        self.logger.info("Context data built")

        for event_data in events_to_send:
            event_data["context"] = context.model_dump(mode="json")

        payload = {"events": events_to_send}

        # Create HTTP client if needed
        if self.http_client is None:
            # TODO: Add proxy support
            self.http_client = httpx.AsyncClient(proxy=None)

        headers = {
            "Content-Type": "application/json",
            "X-Idempotency-Key": IDEMPOTENCY_KEY,
        }
        headers.update(get_meta_http_headers())

        # Add authentication
        if self.api_key:
            headers["X-Api-Key"] = self.api_key
        elif self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        try:
            # Send the request with retries
            response = await self._send_events(payload, headers)

            # Handle case where http_client was None and _send_events returned None
            if response is None:
                self.logger.warning("Events not sent: HTTP client not initialized")
                # Put events back in collection
                self.collected_events = events_to_send + self.collected_events
                return {
                    "status": "error",
                    "count": event_count,
                    "error": "HTTP client not initialized",
                }

            self.logger.info(
                f"Successfully sent {event_count} events, status: {response.status_code}"
            )

            return {
                "status": "success",
                "count": event_count,
                "http_status": response.status_code,
            }
        except tenacity.RetryError as retry_exc:
            # Put events back in collection
            self.collected_events = events_to_send + self.collected_events
            exc = retry_exc.last_attempt.exception()

            status_code = None
            if hasattr(exc, "response"):
                status_code = exc.response  # type: ignore

            self.logger.error(f"Failed after retries: {exc}")

            result = {"status": "error", "count": event_count, "error": repr(exc)}
            if status_code:
                result["http_status"] = status_code

            return result
        except Exception as exc:
            # Handle any other unexpected exceptions
            self.collected_events = events_to_send + self.collected_events
            self.logger.exception(f"Unexpected error: {exc}")

            return {"status": "error", "count": event_count, "error": repr(exc)}

    async def close_async(self):
        """Close the HTTP client asynchronously."""
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None
            self.logger.debug("HTTP client closed")

    def close(self):
        """
        Synchronous method to close the handler.

        This is a non-blocking method that initiates closure but doesn't wait for it.
        The event bus will handle the actual closing asynchronously.
        """
        self.logger.info("Initiating telemetry handler shutdown")
        # The actual close will happen when the event loop processes events
        # Just log the intent and let the event loop handle it
        return {"status": "shutdown_initiated"}

    def get_stats(self) -> Dict[str, Any]:
        """
        Get current telemetry statistics.

        Returns:
            Dictionary of statistics
        """
        event_count = len(self.collected_events)

        # Group events by type
        event_types = {}
        for event in self.collected_events:
            event_type = event.get("event_type", "unknown")
            if event_type not in event_types:
                event_types[event_type] = 0
            event_types[event_type] += 1

        return {
            "events_in_memory": event_count,
            "event_types": event_types,
            "api_endpoint": self.api_endpoint,
        }
