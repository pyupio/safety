from __future__ import annotations

import time
import uuid
from typing import Any

import httpx
from authlib.integrations.httpx_client import OAuth2Client
from typing import cast
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential_jitter,
    retry_if_exception_type,
)

RETRYABLE_EXCEPTIONS = (
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.RemoteProtocolError,
)


class RetryableHTTPError(Exception):
    def __init__(self, status_code: int):
        self.status_code = status_code
        super().__init__(f"Retryable HTTP {status_code}")


class EventSender:
    """Low-level sync HTTP sender with retry logic."""

    def __init__(
        self,
        base_url: str,
        http_client: httpx.Client | OAuth2Client,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.client = http_client

    def __enter__(self):
        # Use injected client - already configured with auth, TLS, proxy, etc.
        return self

    def __exit__(self, *exc):
        # Don't close injected client - let caller manage lifecycle
        pass

    def create_scan(self, metadata: dict[str, Any] | None = None) -> str:
        resp = cast(httpx.Client, self.client).post(
            f"{self.base_url}/api/system-scans/", json=metadata or {}
        )
        resp.raise_for_status()
        return resp.json()["system_scan_id"]

    def send_batch(self, scan_ref: str, events: list[dict[str, Any]]) -> None:
        if not events:
            return
        self._send_with_split(scan_ref, events)

    def _send_with_split(self, scan_ref: str, events: list[dict[str, Any]]) -> None:
        try:
            self._send_once(scan_ref, events)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 413 and len(events) > 1:
                mid = len(events) // 2
                self._send_with_split(scan_ref, events[:mid])
                self._send_with_split(scan_ref, events[mid:])
            else:
                raise

    @retry(
        reraise=True,
        stop=stop_after_attempt(4),
        wait=wait_exponential_jitter(initial=1, max=30),
        retry=retry_if_exception_type((RetryableHTTPError, *RETRYABLE_EXCEPTIONS)),
    )
    def _send_once(self, scan_ref: str, events: list[dict[str, Any]]) -> None:
        resp = cast(httpx.Client, self.client).post(
            f"{self.base_url}/api/events/",
            headers={
                "Content-Type": "application/cloudevents-batch+json",
                "X-Scan-Ref": scan_ref,
                "X-Batch-Id": str(uuid.uuid4()),
            },
            json=events,
        )

        if resp.status_code == 201:
            return

        if resp.status_code in {408, 429} or 500 <= resp.status_code < 600:
            self._wait_retry_after(resp)
            raise RetryableHTTPError(resp.status_code)

        resp.raise_for_status()

    def _wait_retry_after(self, resp: httpx.Response) -> None:
        if retry_after := resp.headers.get("Retry-After"):
            try:
                time.sleep(min(int(retry_after), 60))
            except ValueError:
                pass
